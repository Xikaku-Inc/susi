use anyhow::{Context, Result};
use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

#[derive(Clone)]
pub struct EmailConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: Mailbox,
}

impl EmailConfig {
    pub fn from_parts(
        host: String,
        port: u16,
        username: String,
        password: String,
        from_name: &str,
        from_addr: &str,
    ) -> Result<Self> {
        let from: Mailbox = format!("{} <{}>", from_name, from_addr)
            .parse()
            .with_context(|| format!("Invalid SMTP From address: {} <{}>", from_name, from_addr))?;
        Ok(Self { host, port, username, password, from })
    }
}

#[derive(Clone)]
pub struct EmailService {
    cfg: EmailConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl EmailService {
    pub fn new(cfg: EmailConfig) -> Result<Self> {
        let creds = Credentials::new(cfg.username.clone(), cfg.password.clone());
        let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
            .with_context(|| format!("Failed to init SMTP relay for {}", cfg.host))?
            .port(cfg.port)
            .credentials(creds)
            .build();
        Ok(Self { cfg, transport })
    }

    pub async fn send_magic_link(
        &self,
        to_addr: &str,
        username: &str,
        link: &str,
        ttl_minutes: i64,
        device_label: &str,
        ip: &str,
    ) -> Result<()> {
        let to: Mailbox = to_addr
            .parse()
            .with_context(|| format!("Invalid recipient address: {}", to_addr))?;

        let subject = format!("Susi: sign in from a new device ({} min)", ttl_minutes);
        let text = format!(
            "Hi {user},\n\n\
             You (or someone) just tried to sign in to the Susi license server from a new device:\n\
             \n    Device: {dev}\n    IP:     {ip}\n\n\
             If this was you, click the link below within {ttl} minutes to authorize this device:\n\n\
             {link}\n\n\
             If this wasn't you, you can ignore this email — the link will expire and no sign-in will happen.\n\n\
             — Susi\n",
            user = username, dev = device_label, ip = ip, ttl = ttl_minutes, link = link
        );

        let html = format!(
            "<p>Hi {user},</p>\
             <p>You (or someone) just tried to sign in to the Susi license server from a new device:</p>\
             <ul>\
                <li><strong>Device:</strong> {dev}</li>\
                <li><strong>IP:</strong> {ip}</li>\
             </ul>\
             <p>If this was you, click the link below within <strong>{ttl} minutes</strong> to authorize this device:</p>\
             <p><a href=\"{link}\" style=\"display:inline-block;padding:10px 18px;background:#6c8cff;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;\">Sign in</a></p>\
             <p style=\"color:#888;font-size:12px;word-break:break-all;\">Or paste this into your browser: {link}</p>\
             <p style=\"color:#888;font-size:12px;\">If this wasn't you, you can ignore this email — the link will expire and no sign-in will happen.</p>\
             <p style=\"color:#888;font-size:12px;\">— Susi</p>",
            user = html_escape(username),
            dev = html_escape(device_label),
            ip = html_escape(ip),
            ttl = ttl_minutes,
            link = html_escape(link),
        );

        let email = Message::builder()
            .from(self.cfg.from.clone())
            .to(to)
            .subject(subject)
            .multipart(
                lettre::message::MultiPart::alternative()
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text),
                    )
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html),
                    ),
            )
            .context("Failed to build magic-link email")?;

        self.transport
            .send(email)
            .await
            .context("SMTP send failed")?;
        Ok(())
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
