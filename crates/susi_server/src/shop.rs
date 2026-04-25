//! Shop endpoints — Stripe-backed checkout for physical goods.
//!
//! - Public: list products, get product, create checkout session, webhook.
//! - Admin (JWT): CRUD for products + shipping rates.
//!
//! The cart lives entirely in the browser (localStorage). The checkout
//! endpoint accepts `[{sku, qty}]` + destination_country, looks up authoritative
//! prices from the DB, picks applicable shipping rates, and hands the cart to
//! Stripe Checkout with `automatic_tax: true`. Stripe collects address +
//! payment, computes tax, and redirects to success_url / cancel_url.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use susi_core::error::LicenseError;

use crate::{error_response, require_admin, require_password_changed, validate_principal, AppState, ErrorResponse};

type HmacSha256 = Hmac<Sha256>;

const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";
// Reject webhook events whose signed timestamp drifts more than this far from
// `now`. 5 minutes matches Stripe's own CLI default and covers NTP skew.
const WEBHOOK_TOLERANCE_SECS: i64 = 300;

fn db_err(e: LicenseError) -> (StatusCode, Json<ErrorResponse>) {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
}

fn shop_configured(state: &AppState) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if state.stripe_secret_key.is_empty() {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Shop checkout is not configured on this server",
        ));
    }
    Ok(())
}

fn product_to_json(
    row: (String, String, String, i64, String, Option<String>, String, bool, i64, String),
) -> Value {
    let (sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at) = row;
    json!({
        "sku": sku,
        "title": title,
        "description_md": description_md,
        "price_cents": price_cents,
        "currency": currency,
        "image_asset": image_asset,
        "image_url": image_asset.as_ref().map(|n| format!("/api/v1/website/assets/{}", n)),
        "tax_code": tax_code,
        "active": active,
        "ord": ord,
        "updated_at": updated_at,
    })
}

fn rate_to_json(
    row: (i64, String, i64, String, Option<i64>, Option<i64>, String, bool, i64),
) -> Value {
    let (id, label, amount_cents, currency, delivery_min_days, delivery_max_days, regions_json, active, ord) = row;
    let regions: Vec<String> = serde_json::from_str(&regions_json).unwrap_or_else(|_| vec!["*".into()]);
    json!({
        "id": id,
        "label": label,
        "amount_cents": amount_cents,
        "currency": currency,
        "delivery_min_days": delivery_min_days,
        "delivery_max_days": delivery_max_days,
        "regions": regions,
        "active": active,
        "ord": ord,
    })
}

// ---------------------------------------------------------------------------
// Public read endpoints
// ---------------------------------------------------------------------------

pub async fn handle_list_products(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let rows = {
        let db = state.db.lock().unwrap();
        db.list_products(true).map_err(db_err)?
    };
    let products: Vec<Value> = rows.into_iter().map(product_to_json).collect();
    Ok(Json(json!({ "products": products })))
}

pub async fn handle_get_product(
    State(state): State<Arc<AppState>>,
    Path(sku): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let row = {
        let db = state.db.lock().unwrap();
        db.get_product(&sku).map_err(db_err)?
    }
    .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Product not found"))?;
    if !row.7 {
        return Err(error_response(StatusCode::NOT_FOUND, "Product not found"));
    }
    Ok(Json(product_to_json(row)))
}

// ---------------------------------------------------------------------------
// Checkout
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CheckoutItem {
    pub sku: String,
    pub qty: i64,
}

#[derive(Deserialize)]
pub struct CheckoutRequest {
    pub items: Vec<CheckoutItem>,
    #[serde(default)]
    pub destination_country: String,
}

/// Region match — `*` is a wildcard for "any country".
fn rate_applies(regions: &[String], country: &str) -> bool {
    regions.iter().any(|r| r == "*" || r.eq_ignore_ascii_case(country))
}

/// Collect the union of allowed countries across all active rates. Stripe
/// requires 2-letter ISO codes; if a rate declares `*`, we expand it to the
/// supported country list (the Checkout "all" shortcut isn't an option —
/// Stripe requires an explicit list). We keep this small and pragmatic.
fn allowed_countries_for_checkout(rates: &[(i64, String, i64, String, Option<i64>, Option<i64>, String, bool, i64)]) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut wildcard = false;
    for r in rates {
        let regions: Vec<String> = serde_json::from_str(&r.6).unwrap_or_default();
        for reg in regions {
            if reg == "*" { wildcard = true; }
            else { set.insert(reg.to_uppercase()); }
        }
    }
    if wildcard {
        // Stripe accepts up to 250 ISO-3166-1 alpha-2 codes. The full list is
        // too large to hardcode here; seller should add specific regions in
        // the admin UI if they want to limit shipping. This fallback covers
        // the common commerce destinations — extend as needed.
        for c in COMMON_SHIPPING_COUNTRIES { set.insert((*c).into()); }
    }
    set.into_iter().collect()
}

const COMMON_SHIPPING_COUNTRIES: &[&str] = &[
    "US", "CA", "GB", "IE", "FR", "DE", "IT", "ES", "NL", "BE", "LU", "AT", "CH",
    "DK", "SE", "NO", "FI", "IS", "PT", "PL", "CZ", "HU", "GR", "JP", "KR", "CN",
    "TW", "HK", "SG", "MY", "TH", "VN", "ID", "PH", "AU", "NZ", "IN", "AE", "SA",
    "IL", "TR", "ZA", "BR", "MX", "AR", "CL", "CO",
];

/// Push a (key, value) pair onto a form builder using Stripe's bracket syntax.
/// e.g. `push(&mut form, &["line_items", "0", "price_data", "currency"], "usd")`
/// produces `line_items[0][price_data][currency]=usd`.
fn push_form(form: &mut Vec<(String, String)>, path: &[&str], value: impl Into<String>) {
    let mut key = String::new();
    for (i, p) in path.iter().enumerate() {
        if i == 0 {
            key.push_str(p);
        } else {
            key.push('[');
            key.push_str(p);
            key.push(']');
        }
    }
    form.push((key, value.into()));
}

pub async fn handle_create_checkout_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    shop_configured(&state)?;

    if req.items.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Cart is empty"));
    }
    if req.items.len() > 100 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Too many items"));
    }

    // Look up each SKU, never trust client-supplied price.
    let mut resolved: Vec<(String, String, i64, String, String, i64)> = Vec::with_capacity(req.items.len()); // sku, title, price_cents, currency, tax_code, qty
    let mut cart_currency: Option<String> = None;
    {
        let db = state.db.lock().unwrap();
        for item in &req.items {
            if item.qty <= 0 || item.qty > 1000 {
                return Err(error_response(StatusCode::BAD_REQUEST, "Invalid quantity"));
            }
            let row = db
                .get_product(&item.sku)
                .map_err(db_err)?
                .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, &format!("Unknown SKU: {}", item.sku)))?;
            let (sku, title, _desc, price_cents, currency, _img, tax_code, active, _ord, _upd) = row;
            if !active {
                return Err(error_response(StatusCode::BAD_REQUEST, &format!("Product is unavailable: {}", sku)));
            }
            match &cart_currency {
                None => cart_currency = Some(currency.clone()),
                Some(c) if c.eq_ignore_ascii_case(&currency) => {}
                Some(c) => return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("Mixed currencies in cart: {} vs {}", c, currency),
                )),
            }
            resolved.push((sku, title, price_cents, currency, tax_code, item.qty));
        }
    }
    let cart_currency = cart_currency.unwrap_or_else(|| "usd".to_string());

    // Pick applicable shipping rates. If destination_country is empty (first
    // load), pass all active rates and let Stripe's address step handle it;
    // the currency must still match.
    let active_rates = {
        let db = state.db.lock().unwrap();
        db.list_shipping_rates(true).map_err(db_err)?
    };
    let applicable: Vec<_> = active_rates
        .into_iter()
        .filter(|r| r.3.eq_ignore_ascii_case(&cart_currency))
        .filter(|r| {
            if req.destination_country.is_empty() { return true; }
            let regions: Vec<String> = serde_json::from_str(&r.6).unwrap_or_default();
            rate_applies(&regions, &req.destination_country)
        })
        .collect();

    // Build Stripe Checkout Session form body.
    let mut form: Vec<(String, String)> = Vec::with_capacity(64);
    form.push(("mode".into(), "payment".into()));

    let success = format!("{}/shop/success?session_id={{CHECKOUT_SESSION_ID}}", state.shop_base_url.trim_end_matches('/'));
    let cancel = format!("{}/shop/cancel", state.shop_base_url.trim_end_matches('/'));
    form.push(("success_url".into(), success));
    form.push(("cancel_url".into(), cancel));

    form.push(("automatic_tax[enabled]".into(), "true".into()));
    form.push(("billing_address_collection".into(), "auto".into()));

    for (i, (sku, title, price_cents, currency, tax_code, qty)) in resolved.iter().enumerate() {
        let idx = i.to_string();
        push_form(&mut form, &["line_items", &idx, "quantity"], qty.to_string());
        push_form(&mut form, &["line_items", &idx, "price_data", "currency"], currency.to_lowercase());
        push_form(&mut form, &["line_items", &idx, "price_data", "unit_amount"], price_cents.to_string());
        push_form(&mut form, &["line_items", &idx, "price_data", "tax_behavior"], "exclusive");
        push_form(&mut form, &["line_items", &idx, "price_data", "product_data", "name"], title.clone());
        push_form(&mut form, &["line_items", &idx, "price_data", "product_data", "tax_code"], tax_code.clone());
        push_form(&mut form, &["line_items", &idx, "price_data", "product_data", "metadata", "sku"], sku.clone());
    }

    // Shipping options.
    for (i, rate) in applicable.iter().enumerate() {
        let idx = i.to_string();
        push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "type"], "fixed_amount");
        push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "display_name"], rate.1.clone());
        push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "fixed_amount", "amount"], rate.2.to_string());
        push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "fixed_amount", "currency"], rate.3.to_lowercase());
        push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "tax_behavior"], "exclusive");
        if let Some(min) = rate.4 {
            push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "delivery_estimate", "minimum", "unit"], "business_day");
            push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "delivery_estimate", "minimum", "value"], min.to_string());
        }
        if let Some(max) = rate.5 {
            push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "delivery_estimate", "maximum", "unit"], "business_day");
            push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "delivery_estimate", "maximum", "value"], max.to_string());
        }
    }

    // Enable shipping address collection only if we have rates.
    if !applicable.is_empty() {
        let countries = allowed_countries_for_checkout(&applicable);
        for (i, c) in countries.iter().enumerate() {
            push_form(&mut form, &["shipping_address_collection", "allowed_countries", &i.to_string()], c.clone());
        }
    }

    // Call Stripe.
    let resp = state
        .http
        .post(format!("{}/checkout/sessions", STRIPE_API_BASE))
        .basic_auth(&state.stripe_secret_key, Some(""))
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            log::error!("Stripe request failed: {}", e);
            error_response(StatusCode::BAD_GATEWAY, "Unable to reach Stripe")
        })?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        log::error!("Stripe checkout.sessions create failed: {} — {}", status, body);
        let short = if body.len() > 400 { &body[..400] } else { &body };
        return Err(error_response(
            StatusCode::BAD_GATEWAY,
            &format!("Stripe error ({}): {}", status.as_u16(), short),
        ));
    }
    let session: Value = serde_json::from_str(&body)
        .map_err(|e| error_response(StatusCode::BAD_GATEWAY, &format!("Bad Stripe response: {}", e)))?;
    let url = session.get("url").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let id = session.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if url.is_empty() {
        return Err(error_response(StatusCode::BAD_GATEWAY, "Stripe returned no checkout URL"));
    }
    Ok(Json(json!({ "url": url, "session_id": id })))
}

// ---------------------------------------------------------------------------
// Webhook
//
// Stripe signs each webhook with an HMAC-SHA256 over `{timestamp}.{raw_body}`.
// We verify using the whsec_… secret + constant-time tag compare, then act on
// `checkout.session.completed` by emailing a short order summary to the shop
// owner. No DB writes — Stripe is the source of truth for orders.
// ---------------------------------------------------------------------------

fn parse_stripe_signature_header(h: &str) -> (Option<i64>, Vec<String>) {
    let mut t: Option<i64> = None;
    let mut v1s: Vec<String> = Vec::new();
    for part in h.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("t=") {
            t = rest.parse().ok();
        } else if let Some(rest) = part.strip_prefix("v1=") {
            v1s.push(rest.to_string());
        }
    }
    (t, v1s)
}

fn verify_stripe_signature(
    secret: &str,
    signature_header: &str,
    payload: &[u8],
    now: i64,
) -> Result<(), &'static str> {
    let (t, v1s) = parse_stripe_signature_header(signature_header);
    let ts = t.ok_or("missing timestamp")?;
    if (now - ts).abs() > WEBHOOK_TOLERANCE_SECS {
        return Err("timestamp outside tolerance");
    }
    if v1s.is_empty() { return Err("missing v1 signature"); }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| "invalid secret")?;
    mac.update(ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let expected_hex = hex::encode(mac.finalize().into_bytes());

    // Any of the v1 signatures can match (Stripe may rotate).
    for candidate in &v1s {
        // `Mac::verify_slice` would be constant-time but we've already
        // consumed the MAC. Do a manual constant-time compare via hex strings.
        if constant_time_eq(candidate.as_bytes(), expected_hex.as_bytes()) {
            return Ok(());
        }
    }
    Err("signature mismatch")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut r = 0u8;
    for i in 0..a.len() { r |= a[i] ^ b[i]; }
    r == 0
}

pub async fn handle_stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    if state.stripe_webhook_secret.is_empty() {
        return Err(error_response(StatusCode::SERVICE_UNAVAILABLE, "Webhook not configured"));
    }
    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "Missing Stripe-Signature"))?;

    let now = chrono::Utc::now().timestamp();
    verify_stripe_signature(&state.stripe_webhook_secret, sig, &body, now).map_err(|e| {
        log::warn!("Stripe webhook signature verify failed: {}", e);
        error_response(StatusCode::BAD_REQUEST, "Invalid signature")
    })?;

    let event: Value = serde_json::from_slice(&body)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Bad JSON: {}", e)))?;
    let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
    log::info!("Stripe webhook received: {}", event_type);

    if event_type == "checkout.session.completed" {
        if let Some(svc) = &state.email {
            if !state.shop_notify_addr.is_empty() {
                let summary = format_order_summary(&event);
                let subject = format!("[Susi shop] New order — {}", summary.0);
                let to = state.shop_notify_addr.clone();
                let svc = svc.clone();
                let body = summary.1;
                // Fire-and-log — don't fail the webhook on SMTP hiccup.
                tokio::spawn(async move {
                    if let Err(e) = svc.send_order_notification(&to, &subject, &body).await {
                        log::error!("Failed to send order-notification email: {}", e);
                    }
                });
            }
        }
    }

    Ok(Json(json!({ "received": true })))
}

/// Returns (short_summary, full_body). Pulls the useful bits out of the
/// Checkout Session payload without assuming every field is present.
fn format_order_summary(event: &Value) -> (String, String) {
    let obj = event.pointer("/data/object").cloned().unwrap_or(Value::Null);
    let session_id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
    let email = obj.get("customer_details").and_then(|d| d.get("email")).and_then(|v| v.as_str()).unwrap_or("");
    let name = obj.get("customer_details").and_then(|d| d.get("name")).and_then(|v| v.as_str()).unwrap_or("");
    let amount_total = obj.get("amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
    let currency = obj.get("currency").and_then(|v| v.as_str()).unwrap_or("");
    let short = format!("{} {}", fmt_money(amount_total, currency), if !name.is_empty() { name } else { email });

    let mut out = String::new();
    out.push_str(&format!("Session:   {}\n", session_id));
    out.push_str(&format!("Customer:  {} <{}>\n", name, email));
    out.push_str(&format!("Amount:    {}\n", fmt_money(amount_total, currency)));
    if let Some(ship) = obj.pointer("/shipping_details") {
        out.push_str(&format!("Ship to:   {}\n", ship));
    }
    if let Some(items) = obj.pointer("/display_items") {
        out.push_str(&format!("Items:     {}\n", items));
    }
    out.push_str("\nManage this order in the Stripe dashboard.\n");
    (short, out)
}

fn fmt_money(cents: i64, currency: &str) -> String {
    let whole = cents / 100;
    let frac = (cents.rem_euclid(100)).abs();
    format!("{}.{:02} {}", whole, frac, currency.to_uppercase())
}

// ---------------------------------------------------------------------------
// Admin endpoints (JWT)
// ---------------------------------------------------------------------------

pub async fn handle_admin_list_products(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let rows = {
        let db = state.db.lock().unwrap();
        db.list_products(false).map_err(db_err)?
    };
    let products: Vec<Value> = rows.into_iter().map(product_to_json).collect();
    Ok(Json(json!({ "products": products })))
}

#[derive(Deserialize)]
pub struct UpsertProductRequest {
    pub title: String,
    #[serde(default)]
    pub description_md: String,
    pub price_cents: i64,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default)]
    pub image_asset: Option<String>,
    #[serde(default = "default_tax_code")]
    pub tax_code: String,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(default)]
    pub ord: i64,
}

fn default_currency() -> String { "usd".into() }
fn default_tax_code() -> String { "txcd_99999999".into() }
fn default_active() -> bool { true }

fn validate_sku(sku: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if sku.is_empty()
        || sku.len() > 64
        || !sku.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid SKU (ascii alnum, - or _, <=64 chars)"));
    }
    Ok(())
}

pub async fn handle_upsert_product(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(sku): Path<String>,
    Json(req): Json<UpsertProductRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    validate_sku(&sku)?;
    if req.title.trim().is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Title is required"));
    }
    if req.price_cents < 0 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Price cannot be negative"));
    }
    {
        let db = state.db.lock().unwrap();
        db.upsert_product(
            &sku,
            &req.title,
            &req.description_md,
            req.price_cents,
            &req.currency.to_lowercase(),
            req.image_asset.as_deref(),
            &req.tax_code,
            req.active,
            req.ord,
        )
        .map_err(db_err)?;
    }
    Ok(Json(json!({ "sku": sku })))
}

pub async fn handle_delete_product(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(sku): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    validate_sku(&sku)?;
    let removed = {
        let db = state.db.lock().unwrap();
        db.delete_product(&sku).map_err(db_err)?
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Product not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_list_shipping_rates_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let rows = {
        let db = state.db.lock().unwrap();
        db.list_shipping_rates(false).map_err(db_err)?
    };
    let rates: Vec<Value> = rows.into_iter().map(rate_to_json).collect();
    Ok(Json(json!({ "rates": rates })))
}

#[derive(Deserialize)]
pub struct ShippingRateRequest {
    pub label: String,
    pub amount_cents: i64,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default)]
    pub delivery_min_days: Option<i64>,
    #[serde(default)]
    pub delivery_max_days: Option<i64>,
    #[serde(default = "default_regions")]
    pub regions: Vec<String>,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(default)]
    pub ord: i64,
}

fn default_regions() -> Vec<String> { vec!["*".into()] }

fn validate_rate_body(r: &ShippingRateRequest) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    if r.label.trim().is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Label is required"));
    }
    if r.amount_cents < 0 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Amount cannot be negative"));
    }
    for reg in &r.regions {
        if reg != "*" && !(reg.len() == 2 && reg.chars().all(|c| c.is_ascii_alphabetic())) {
            return Err(error_response(StatusCode::BAD_REQUEST, &format!("Invalid region code: {}", reg)));
        }
    }
    let normalized: Vec<String> = r.regions.iter()
        .map(|s| if s == "*" { s.clone() } else { s.to_uppercase() })
        .collect();
    serde_json::to_string(&normalized)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("JSON encode: {}", e)))
}

pub async fn handle_create_shipping_rate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ShippingRateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let regions_json = validate_rate_body(&req)?;
    let id = {
        let db = state.db.lock().unwrap();
        db.insert_shipping_rate(
            &req.label,
            req.amount_cents,
            &req.currency.to_lowercase(),
            req.delivery_min_days,
            req.delivery_max_days,
            &regions_json,
            req.active,
            req.ord,
        ).map_err(db_err)?
    };
    Ok(Json(json!({ "id": id })))
}

pub async fn handle_update_shipping_rate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<ShippingRateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let regions_json = validate_rate_body(&req)?;
    let ok = {
        let db = state.db.lock().unwrap();
        db.update_shipping_rate(
            id,
            &req.label,
            req.amount_cents,
            &req.currency.to_lowercase(),
            req.delivery_min_days,
            req.delivery_max_days,
            &regions_json,
            req.active,
            req.ord,
        ).map_err(db_err)?
    };
    if !ok {
        return Err(error_response(StatusCode::NOT_FOUND, "Shipping rate not found"));
    }
    Ok(Json(json!({ "id": id })))
}

pub async fn handle_delete_shipping_rate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let removed = {
        let db = state.db.lock().unwrap();
        db.delete_shipping_rate(id).map_err(db_err)?
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Shipping rate not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Public shop HTML shell
//
// /shop URLs reuse the same single-page-app shell as the public website so
// that header / sidebar / cart drawer stay consistent. The SPA's `route()`
// detects a `/shop` path and renders product views into the content area.
// ---------------------------------------------------------------------------

const WEBSITE_HTML: &str = include_str!("website.html");

pub async fn handle_shop_page() -> axum::response::Html<String> {
    let head = "<title>Shop — Xikaku</title>\n\
                <meta name=\"description\" content=\"Order Xikaku IMU and inertial sensors directly. Shipped from our Los Angeles office.\">\n\
                <meta property=\"og:title\" content=\"Shop — Xikaku\">\n\
                <meta property=\"og:type\" content=\"website\">\n";
    let html = WEBSITE_HTML.replacen("<!--SEO_HEAD-->", head, 1);
    axum::response::Html(html)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_form_flat() {
        let mut f = Vec::new();
        push_form(&mut f, &["mode"], "payment");
        assert_eq!(f, vec![("mode".into(), "payment".into())]);
    }

    #[test]
    fn push_form_nested() {
        let mut f = Vec::new();
        push_form(&mut f, &["line_items", "0", "price_data", "currency"], "usd");
        assert_eq!(f, vec![("line_items[0][price_data][currency]".into(), "usd".into())]);
    }

    #[test]
    fn signature_header_parse() {
        let (t, v) = parse_stripe_signature_header("t=1492774577,v1=abc123,v0=old");
        assert_eq!(t, Some(1492774577));
        assert_eq!(v, vec!["abc123".to_string()]);
    }

    #[test]
    fn signature_verify_roundtrip() {
        let secret = "whsec_test";
        let payload = br#"{"id":"evt_1","type":"checkout.session.completed"}"#;
        let ts = 1_700_000_000i64;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        let sig = hex::encode(mac.finalize().into_bytes());
        let header = format!("t={},v1={}", ts, sig);
        verify_stripe_signature(secret, &header, payload, ts).unwrap();
    }

    #[test]
    fn signature_verify_rejects_stale() {
        let secret = "whsec_test";
        let payload = b"{}";
        let ts = 1_700_000_000i64;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        let sig = hex::encode(mac.finalize().into_bytes());
        let header = format!("t={},v1={}", ts, sig);
        // 10 min later — outside 5 min tolerance.
        assert!(verify_stripe_signature(secret, &header, payload, ts + 600).is_err());
    }

    #[test]
    fn signature_verify_rejects_bad_sig() {
        let header = "t=1700000000,v1=deadbeef";
        assert!(verify_stripe_signature("whsec_test", header, b"{}", 1_700_000_000).is_err());
    }

    #[test]
    fn rate_applies_wildcard() {
        assert!(rate_applies(&["*".into()], "US"));
        assert!(rate_applies(&["US".into(), "CA".into()], "us"));
        assert!(!rate_applies(&["US".into()], "GB"));
    }
}
