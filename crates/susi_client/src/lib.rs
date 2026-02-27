use std::path::Path;

use chrono::{DateTime, Utc};
use susi_core::{
    crypto::{public_key_from_pem, verify_license},
    fingerprint, LicenseError, LicensePayload, SignedLicense,
};
use rsa::RsaPublicKey;

/// Result of a license verification.
#[derive(Debug)]
pub enum LicenseStatus {
    Valid {
        payload: LicensePayload,
    },
    Expired {
        expired_at: DateTime<Utc>,
    },
    InvalidMachine {
        expected: Vec<String>,
        actual: String,
    },
    InvalidSignature,
    FileNotFound(String),
    Error(String),
}

impl LicenseStatus {
    pub fn is_valid(&self) -> bool {
        matches!(self, LicenseStatus::Valid { .. })
    }

    /// Check if a specific feature is available in this license.
    pub fn has_feature(&self, feature: &str) -> bool {
        match self {
            LicenseStatus::Valid { payload } => payload.has_feature(feature),
            _ => false,
        }
    }

    /// Get the list of features if the license is valid.
    pub fn features(&self) -> Vec<String> {
        match self {
            LicenseStatus::Valid { payload } => payload.features.clone(),
            _ => vec![],
        }
    }

    /// Get the expiry date if the license is valid. `None` for perpetual.
    pub fn expires(&self) -> Option<DateTime<Utc>> {
        match self {
            LicenseStatus::Valid { payload } => payload.expires,
            _ => None,
        }
    }
}

/// Client for verifying licenses. Embedded in the FusionHub application.
pub struct LicenseClient {
    public_key: RsaPublicKey,
    server_url: Option<String>,
}

impl LicenseClient {
    /// Create a new client from a PEM-encoded public key string.
    pub fn new(public_key_pem: &str) -> Result<Self, LicenseError> {
        let public_key = public_key_from_pem(public_key_pem)?;
        Ok(Self {
            public_key,
            server_url: None,
        })
    }

    /// Create a new client with an optional server URL for online refresh.
    pub fn with_server(public_key_pem: &str, server_url: String) -> Result<Self, LicenseError> {
        let mut client = Self::new(public_key_pem)?;
        client.server_url = Some(server_url);
        Ok(client)
    }

    /// Verify a signed license file on disk.
    pub fn verify_file(&self, path: &Path) -> LicenseStatus {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => return LicenseStatus::FileNotFound(format!("{}: {}", path.display(), e)),
        };

        let signed: SignedLicense = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => return LicenseStatus::Error(format!("Invalid license file format: {}", e)),
        };

        self.verify_signed(&signed)
    }

    /// Verify a SignedLicense object (e.g. received from server or loaded from disk).
    pub fn verify_signed(&self, signed: &SignedLicense) -> LicenseStatus {
        let payload = match verify_license(&self.public_key, signed) {
            Ok(p) => p,
            Err(LicenseError::InvalidSignature) => return LicenseStatus::InvalidSignature,
            Err(e) => return LicenseStatus::Error(format!("Verification error: {}", e)),
        };

        if payload.is_expired() {
            return LicenseStatus::Expired {
                expired_at: payload.expires.unwrap(), // is_expired() only returns true for Some(dt)
            };
        }

        // Check machine code if the payload has machine restrictions
        if !payload.machine_codes.is_empty() {
            match fingerprint::get_machine_code() {
                Ok(local_code) => {
                    if !payload.is_machine_authorized(&local_code) {
                        return LicenseStatus::InvalidMachine {
                            expected: payload.machine_codes.clone(),
                            actual: local_code,
                        };
                    }
                }
                Err(e) => {
                    return LicenseStatus::Error(format!(
                        "Could not compute machine fingerprint: {}",
                        e
                    ));
                }
            }
        }

        LicenseStatus::Valid { payload }
    }

    /// Try to refresh the license from the server, falling back to the local file.
    pub fn verify_and_refresh(&self, path: &Path, license_key: &str) -> LicenseStatus {
        if let Some(ref server_url) = self.server_url {
            // Try online verification first
            match self.try_online_verify(server_url, license_key) {
                Ok(signed) => {
                    // Save refreshed license to disk
                    if let Ok(json) = serde_json::to_string_pretty(&signed) {
                        let _ = std::fs::write(path, json);
                    }
                    return self.verify_signed(&signed);
                }
                Err(e) => {
                    log::warn!("Online license refresh failed, using cached file: {}", e);
                }
            }
        }

        // Fall back to local file
        self.verify_file(path)
    }

    fn try_online_verify(
        &self,
        server_url: &str,
        license_key: &str,
    ) -> Result<SignedLicense, String> {
        let machine_code = fingerprint::get_machine_code()
            .map_err(|e| format!("Fingerprint error: {}", e))?;

        let url = format!("{}/verify", server_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "license_key": license_key,
            "machine_code": machine_code,
        });

        let response = reqwest::blocking::Client::new()
            .post(&url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_default();
            return Err(format!("Server returned {}: {}", status, text));
        }

        response
            .json::<SignedLicense>()
            .map_err(|e| format!("Invalid server response: {}", e))
    }

    /// Get the machine code for the current machine.
    pub fn get_machine_code() -> Result<String, LicenseError> {
        fingerprint::get_machine_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use susi_core::crypto::{generate_keypair, private_key_to_pem, public_key_to_pem, sign_license};

    fn make_keypair_pems() -> (String, String, rsa::RsaPrivateKey) {
        let (private, public) = generate_keypair(2048).unwrap();
        let priv_pem = private_key_to_pem(&private).unwrap();
        let pub_pem = public_key_to_pem(&public).unwrap();
        (priv_pem, pub_pem, private)
    }

    fn make_valid_payload(machine_code: Option<String>) -> LicensePayload {
        LicensePayload {
            id: "test-id".to_string(),
            product: "FusionHub".to_string(),
            customer: "Test Corp".to_string(),
            license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
            created: Utc::now(),
            expires: Some(Utc::now() + Duration::days(365)),
            features: vec!["full_fusion".to_string(), "recorder".to_string()],
            machine_codes: machine_code.into_iter().collect(),
        }
    }

    #[test]
    fn test_client_creation() {
        let (_, pub_pem, _) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem);
        assert!(client.is_ok());
    }

    #[test]
    fn test_verify_valid_license() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(status.is_valid());
        assert!(status.has_feature("full_fusion"));
        assert!(status.has_feature("recorder"));
        assert!(!status.has_feature("vehicular"));
    }

    #[test]
    fn test_verify_expired_license() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let payload = LicensePayload {
            id: "test".to_string(),
            product: "FusionHub".to_string(),
            customer: "Test".to_string(),
            license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
            created: Utc::now() - Duration::days(60),
            expires: Some(Utc::now() - Duration::days(1)),
            features: vec![],
            machine_codes: vec![],
        };
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(!status.is_valid());
        assert!(matches!(status, LicenseStatus::Expired { .. }));
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (_, _, private) = make_keypair_pems();
        let (_, wrong_pub_pem, _) = make_keypair_pems();
        let client = LicenseClient::new(&wrong_pub_pem).unwrap();
        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(matches!(status, LicenseStatus::InvalidSignature));
    }

    #[test]
    fn test_verify_machine_locked_license() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let local_code = LicenseClient::get_machine_code().unwrap();

        // License locked to this machine
        let payload = make_valid_payload(Some(local_code.clone()));
        let signed = sign_license(&private, &payload).unwrap();
        let status = client.verify_signed(&signed);
        assert!(status.is_valid());

        // License locked to a different machine
        let payload = make_valid_payload(Some("wrong_machine_code".to_string()));
        let signed = sign_license(&private, &payload).unwrap();
        let status = client.verify_signed(&signed);
        assert!(matches!(status, LicenseStatus::InvalidMachine { .. }));
    }

    #[test]
    fn test_verify_file_not_found() {
        let (_, pub_pem, _) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let status = client.verify_file(Path::new("/nonexistent/license.json"));
        assert!(matches!(status, LicenseStatus::FileNotFound(_)));
    }

    #[test]
    fn test_verify_file_roundtrip() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let payload = make_valid_payload(None);
        let signed = sign_license(&private, &payload).unwrap();

        let tmp = std::env::temp_dir().join("test_license_verify.json");
        let json = serde_json::to_string_pretty(&signed).unwrap();
        std::fs::write(&tmp, &json).unwrap();

        let status = client.verify_file(&tmp);
        assert!(status.is_valid());
        assert_eq!(status.features(), vec!["full_fusion", "recorder"]);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_verify_perpetual_license() {
        let (_, pub_pem, private) = make_keypair_pems();
        let client = LicenseClient::new(&pub_pem).unwrap();
        let payload = LicensePayload {
            id: "perpetual".to_string(),
            product: "FusionHub".to_string(),
            customer: "Perpetual Corp".to_string(),
            license_key: "PPPP-PPPP-PPPP-PPPP".to_string(),
            created: Utc::now(),
            expires: None,
            features: vec!["full_fusion".to_string()],
            machine_codes: vec![],
        };
        let signed = sign_license(&private, &payload).unwrap();

        let status = client.verify_signed(&signed);
        assert!(status.is_valid());
        assert!(status.expires().is_none());
        assert!(status.has_feature("full_fusion"));
    }

    #[test]
    fn test_status_features_on_invalid() {
        let status = LicenseStatus::InvalidSignature;
        assert!(!status.is_valid());
        assert!(!status.has_feature("anything"));
        assert!(status.features().is_empty());
        assert!(status.expires().is_none());
    }
}
