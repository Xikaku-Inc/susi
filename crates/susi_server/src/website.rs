//! Public website endpoints.
//!
//! Simple single-site page store at `/api/v1/website/...`. Public reads for
//! viewing pages + assets; admin writes (JWT/API-token) for editing. Unlike
//! `docs`, there's no release concept and no pipeline/user origin split —
//! all content is hand-authored via the in-browser editor.

use std::sync::Arc;

use axum::{
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use susi_core::error::LicenseError;

use crate::docs::{safe_filename};
use crate::{error_response, require_admin, require_password_changed, validate_principal, AppState, ErrorResponse};

fn assets_dir(state: &AppState) -> std::path::PathBuf {
    std::path::Path::new(&state.data_dir).join("website").join("assets")
}

fn content_type_for(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".png") { "image/png" }
    else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") { "image/jpeg" }
    else if lower.ends_with(".gif") { "image/gif" }
    else if lower.ends_with(".svg") { "image/svg+xml" }
    else if lower.ends_with(".webp") { "image/webp" }
    else if lower.ends_with(".pdf") { "application/pdf" }
    else if lower.ends_with(".md") { "text/markdown; charset=utf-8" }
    else if lower.ends_with(".json") { "application/json" }
    else { "application/octet-stream" }
}

fn db_err(e: LicenseError) -> (StatusCode, Json<ErrorResponse>) {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
}

fn safe_slug(slug: &str) -> Result<&str, (StatusCode, Json<ErrorResponse>)> {
    if slug.is_empty()
        || slug.contains('/')
        || slug.contains('\\')
        || slug.contains('\0')
    {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid slug"));
    }
    Ok(slug)
}

// ---------------------------------------------------------------------------
// Public read endpoints
// ---------------------------------------------------------------------------

pub async fn handle_list_pages(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();
    let pages = db.list_website_pages().map_err(db_err)?;
    let assets = db.list_website_assets().map_err(db_err)?;
    let pages_json: Vec<_> = pages
        .into_iter()
        .map(|(slug, title, parent_slug, ord, updated_at)| {
            json!({
                "slug": slug,
                "title": title,
                "parent_slug": parent_slug,
                "ord": ord,
                "updated_at": updated_at,
            })
        })
        .collect();
    let assets_json: Vec<_> = assets
        .into_iter()
        .map(|(name, size)| json!({ "name": name, "size": size }))
        .collect();
    Ok(Json(json!({
        "pages": pages_json,
        "assets": assets_json,
    })))
}

pub async fn handle_get_page(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_slug(&slug)?;
    let db = state.db.lock().unwrap();
    let page = db
        .get_website_page(&slug)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Page not found"))?;
    let (title, body_md, parent_slug, ord, updated_at) = page;
    Ok(Json(json!({
        "slug": slug,
        "title": title,
        "body_md": body_md,
        "parent_slug": parent_slug,
        "ord": ord,
        "updated_at": updated_at,
    })))
}

pub async fn handle_get_asset(
    State(state): State<Arc<AppState>>,
    Path(file_name): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    safe_filename(&file_name)?;
    let path = assets_dir(&state).join(&file_name);
    if !path.exists() {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Read: {}", e)))?;

    let mut resp = HeaderMap::new();
    resp.insert(header::CONTENT_TYPE, content_type_for(&file_name).parse().unwrap());
    resp.insert(header::CONTENT_LENGTH, bytes.len().into());
    resp.insert(header::CACHE_CONTROL, "public, max-age=300".parse().unwrap());
    Ok((resp, bytes))
}

// ---------------------------------------------------------------------------
// Admin write endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpsertPageRequest {
    pub title: String,
    pub body_md: String,
    #[serde(default)]
    pub parent_slug: Option<String>,
    #[serde(default)]
    pub ord: i64,
}

pub async fn handle_upsert_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(req): Json<UpsertPageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    safe_slug(&slug)?;

    let id = {
        let mut db = state.db.lock().unwrap();
        db.upsert_website_page(
            &slug,
            &req.title,
            &req.body_md,
            req.parent_slug.as_deref(),
            req.ord,
            Some(&principal.username),
        )
        .map_err(db_err)?
    };
    Ok(Json(json!({ "id": id, "slug": slug })))
}

// ---------------------------------------------------------------------------
// Page revisions (history)
// ---------------------------------------------------------------------------

pub async fn handle_list_page_revisions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    safe_slug(&slug)?;
    let db = state.db.lock().unwrap();
    let rows = db.list_page_revisions(&slug).map_err(db_err)?;
    let revisions: Vec<_> = rows
        .into_iter()
        .map(|(id, captured_at, author, title, body_len)| json!({
            "id": id,
            "captured_at": captured_at,
            "author": author,
            "title": title,
            "body_length": body_len,
        }))
        .collect();
    Ok(Json(json!({ "slug": slug, "revisions": revisions })))
}

pub async fn handle_get_page_revision(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((slug, id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    safe_slug(&slug)?;
    let db = state.db.lock().unwrap();
    let row = db
        .get_page_revision(&slug, id)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Revision not found"))?;
    let (title, body_md, parent_slug, ord, captured_at, author) = row;
    Ok(Json(json!({
        "slug": slug, "id": id,
        "title": title, "body_md": body_md,
        "parent_slug": parent_slug, "ord": ord,
        "captured_at": captured_at, "author": author,
    })))
}

pub async fn handle_restore_page_revision(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((slug, id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    safe_slug(&slug)?;
    let mut db = state.db.lock().unwrap();
    let rev = db
        .get_page_revision(&slug, id)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Revision not found"))?;
    let (title, body_md, parent_slug, ord, _captured_at, _author) = rev;
    let new_id = db.upsert_website_page(
        &slug, &title, &body_md, parent_slug.as_deref(), ord,
        Some(&principal.username),
    ).map_err(db_err)?;
    Ok(Json(json!({ "id": new_id, "slug": slug, "restored_from": id })))
}

// ---------------------------------------------------------------------------
// Asset admin
// ---------------------------------------------------------------------------

pub async fn handle_list_assets_with_usage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    let db = state.db.lock().unwrap();
    let rows = db.list_website_assets_with_usage().map_err(db_err)?;
    let assets: Vec<_> = rows
        .into_iter()
        .map(|(name, size, usage_count, pages_csv)| {
            let pages: Vec<&str> = if pages_csv.is_empty() {
                Vec::new()
            } else {
                pages_csv.split(',').collect()
            };
            json!({
                "name": name, "size": size,
                "usage_count": usage_count,
                "pages": pages,
            })
        })
        .collect();
    Ok(Json(json!({ "assets": assets })))
}

#[derive(Deserialize)]
pub struct RenameAssetRequest {
    pub new_name: String,
}

pub async fn handle_rename_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(file_name): Path<String>,
    Json(req): Json<RenameAssetRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    safe_filename(&file_name)?;
    let new_name = req.new_name.trim();
    safe_filename(new_name)?;

    let (ok, n_pages) = {
        let mut db = state.db.lock().unwrap();
        db.rename_website_asset(&file_name, new_name).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("already exists") {
                error_response(StatusCode::CONFLICT, &msg)
            } else {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, &msg)
            }
        })?
    };
    if !ok {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    // Move file on disk.
    let dir = assets_dir(&state);
    let old_path = dir.join(&file_name);
    let new_path = dir.join(new_name);
    if old_path.exists() {
        if let Err(e) = std::fs::rename(&old_path, &new_path) {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("fs rename: {}", e),
            ));
        }
    }
    Ok(Json(json!({
        "name": new_name,
        "pages_updated": n_pages,
    })))
}

#[derive(Deserialize)]
pub struct RenamePageRequest {
    pub new_slug: String,
}

pub async fn handle_rename_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(req): Json<RenamePageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    let new_slug = req.new_slug.trim();
    if new_slug.is_empty() || new_slug.contains('/') || new_slug.contains('\\') || new_slug.contains('\0') {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid slug"));
    }

    let mut db = state.db.lock().unwrap();
    match db.rename_website_page(&slug, new_slug) {
        Ok(true) => Ok(Json(json!({ "slug": new_slug }))),
        Ok(false) => Err(error_response(StatusCode::NOT_FOUND, "Page not found")),
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("UNIQUE") {
                Err(error_response(StatusCode::CONFLICT, "Target slug already exists"))
            } else {
                Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, &msg))
            }
        }
    }
}

pub async fn handle_delete_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    safe_slug(&slug)?;

    let db = state.db.lock().unwrap();
    let removed = db.delete_website_page(&slug).map_err(db_err)?;
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Page not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_upload_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;

    let mut file_name = String::new();
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Multipart: {}", e)))?
    {
        if field.name() == Some("file") {
            file_name = field.file_name().unwrap_or("").to_string();
            let data = field
                .bytes()
                .await
                .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
            bytes = data.to_vec();
            break;
        }
    }
    if file_name.is_empty() || bytes.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Missing 'file' field"));
    }
    safe_filename(&file_name)?;

    let dir = assets_dir(&state);
    std::fs::create_dir_all(&dir).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("mkdir: {}", e))
    })?;
    let path = dir.join(&file_name);
    std::fs::write(&path, &bytes).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("write: {}", e))
    })?;

    {
        let db = state.db.lock().unwrap();
        db.upsert_website_asset(&file_name, bytes.len() as u64)
            .map_err(db_err)?;
    }

    let url = format!("/api/v1/website/assets/{}", file_name);
    log::info!("Website asset uploaded: {} ({} bytes)", file_name, bytes.len());
    Ok(Json(json!({ "name": file_name, "size": bytes.len(), "url": url })))
}

pub async fn handle_delete_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(file_name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    safe_filename(&file_name)?;

    let removed = {
        let db = state.db.lock().unwrap();
        db.delete_website_asset(&file_name).map_err(db_err)?
    };
    let _ = std::fs::remove_file(assets_dir(&state).join(&file_name));
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}
