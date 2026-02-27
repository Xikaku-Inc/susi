use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Full license record stored on the server side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub id: String,
    pub product: String,
    pub customer: String,
    pub license_key: String,
    pub created: DateTime<Utc>,
    /// `None` means perpetual (never expires).
    pub expires: Option<DateTime<Utc>>,
    pub features: Vec<String>,
    pub max_machines: u32,
    pub machines: Vec<MachineActivation>,
    pub revoked: bool,
}

/// A machine activation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineActivation {
    pub machine_code: String,
    pub friendly_name: String,
    pub activated_at: DateTime<Utc>,
}

/// The payload that gets signed and shipped to the client.
/// This is a subset of License — no server-internal fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub id: String,
    pub product: String,
    pub customer: String,
    pub license_key: String,
    pub created: DateTime<Utc>,
    /// `None` means perpetual (never expires).
    pub expires: Option<DateTime<Utc>>,
    pub features: Vec<String>,
    pub machine_codes: Vec<String>,
}

/// A signed license file that can be written to disk and verified offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicense {
    /// JSON-serialized LicensePayload (canonical form).
    pub license_data: String,
    /// Base64-encoded RSA-SHA256 signature of `license_data`.
    pub signature: String,
}

impl License {
    pub fn new(
        product: String,
        customer: String,
        expires: Option<DateTime<Utc>>,
        features: Vec<String>,
        max_machines: u32,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            product,
            customer,
            license_key: generate_serial_key(),
            created: Utc::now(),
            expires,
            features,
            max_machines,
            machines: Vec::new(),
            revoked: false,
        }
    }

    pub fn to_payload(&self) -> LicensePayload {
        LicensePayload {
            id: self.id.clone(),
            product: self.product.clone(),
            customer: self.customer.clone(),
            license_key: self.license_key.clone(),
            created: self.created,
            expires: self.expires,
            features: self.features.clone(),
            machine_codes: self.machines.iter().map(|m| m.machine_code.clone()).collect(),
        }
    }

    pub fn is_expired(&self) -> bool {
        match self.expires {
            Some(dt) => Utc::now() > dt,
            None => false, // perpetual
        }
    }

    pub fn is_machine_activated(&self, machine_code: &str) -> bool {
        self.machines.iter().any(|m| m.machine_code == machine_code)
    }

    pub fn can_add_machine(&self) -> bool {
        self.max_machines == 0 || (self.machines.len() as u32) < self.max_machines
    }

    pub fn add_machine(&mut self, machine_code: String, friendly_name: String) {
        if !self.is_machine_activated(&machine_code) {
            self.machines.push(MachineActivation {
                machine_code,
                friendly_name,
                activated_at: Utc::now(),
            });
        }
    }

    pub fn remove_machine(&mut self, machine_code: &str) {
        self.machines.retain(|m| m.machine_code != machine_code);
    }
}

impl LicensePayload {
    pub fn is_expired(&self) -> bool {
        match self.expires {
            Some(dt) => Utc::now() > dt,
            None => false, // perpetual
        }
    }

    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    pub fn is_machine_authorized(&self, machine_code: &str) -> bool {
        self.machine_codes.is_empty() || self.machine_codes.iter().any(|m| m == machine_code)
    }
}

/// Generate a human-readable serial key in the format XXXXX-XXXXX-XXXXX-XXXXX.
fn generate_serial_key() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    let mut parts = Vec::with_capacity(4);
    for _ in 0..4 {
        let part: String = (0..5)
            .map(|_| {
                let idx = rng.gen_range(0..CHARS.len());
                CHARS[idx] as char
            })
            .collect();
        parts.push(part);
    }
    parts.join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_generate_serial_key_format() {
        let key = generate_serial_key();
        let parts: Vec<&str> = key.split('-').collect();
        assert_eq!(parts.len(), 4);
        for part in parts {
            assert_eq!(part.len(), 5);
            assert!(part.chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn test_license_creation() {
        let license = License::new(
            "FusionHub".to_string(),
            "Test Corp".to_string(),
            Some(Utc::now() + Duration::days(365)),
            vec!["full_fusion".to_string()],
            3,
        );
        assert_eq!(license.product, "FusionHub");
        assert_eq!(license.customer, "Test Corp");
        assert_eq!(license.max_machines, 3);
        assert!(!license.is_expired());
        assert!(license.can_add_machine());
        assert_eq!(license.machines.len(), 0);
    }

    #[test]
    fn test_machine_management() {
        let mut license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            2,
        );

        license.add_machine("abc123".to_string(), "Machine 1".to_string());
        assert!(license.is_machine_activated("abc123"));
        assert!(!license.is_machine_activated("xyz789"));
        assert!(license.can_add_machine());

        license.add_machine("xyz789".to_string(), "Machine 2".to_string());
        assert!(!license.can_add_machine());

        // Adding duplicate should not increase count
        license.add_machine("abc123".to_string(), "Machine 1 again".to_string());
        assert_eq!(license.machines.len(), 2);

        license.remove_machine("abc123");
        assert!(!license.is_machine_activated("abc123"));
        assert!(license.can_add_machine());
    }

    #[test]
    fn test_to_payload() {
        let mut license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec!["feature_a".to_string(), "feature_b".to_string()],
            0,
        );
        license.add_machine("machine1".to_string(), "M1".to_string());

        let payload = license.to_payload();
        assert_eq!(payload.id, license.id);
        assert_eq!(payload.features.len(), 2);
        assert_eq!(payload.machine_codes, vec!["machine1".to_string()]);
    }

    #[test]
    fn test_expired_license() {
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() - Duration::days(1)),
            vec![],
            0,
        );
        assert!(license.is_expired());
    }

    #[test]
    fn test_perpetual_license_never_expires() {
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            None,
            vec!["full_fusion".to_string()],
            0,
        );
        assert!(!license.is_expired());
        assert!(license.expires.is_none());

        let payload = license.to_payload();
        assert!(!payload.is_expired());
        assert!(payload.expires.is_none());
    }

    #[test]
    fn test_payload_feature_check() {
        let payload = LicensePayload {
            id: "test".to_string(),
            product: "FusionHub".to_string(),
            customer: "Test".to_string(),
            license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
            created: Utc::now(),
            expires: Some(Utc::now() + Duration::days(30)),
            features: vec!["full_fusion".to_string(), "recorder".to_string()],
            machine_codes: vec!["machine1".to_string()],
        };

        assert!(payload.has_feature("full_fusion"));
        assert!(payload.has_feature("recorder"));
        assert!(!payload.has_feature("vehicular"));
        assert!(payload.is_machine_authorized("machine1"));
        assert!(!payload.is_machine_authorized("other"));
    }

    #[test]
    fn test_payload_empty_machines_allows_all() {
        let payload = LicensePayload {
            id: "test".to_string(),
            product: "FusionHub".to_string(),
            customer: "Test".to_string(),
            license_key: "AAAA-BBBB-CCCC-DDDD".to_string(),
            created: Utc::now(),
            expires: Some(Utc::now() + Duration::days(30)),
            features: vec![],
            machine_codes: vec![],
        };

        assert!(payload.is_machine_authorized("any_machine"));
    }
}
