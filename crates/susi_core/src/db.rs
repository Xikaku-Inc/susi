use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

use crate::error::LicenseError;
use crate::license::{License, MachineActivation};

pub struct LicenseDb {
    conn: Connection,
}

impl LicenseDb {
    pub fn open(path: &str) -> Result<Self, LicenseError> {
        let conn =
            Connection::open(path).map_err(|e| LicenseError::Other(format!("DB open: {}", e)))?;
        let db = Self { conn };
        db.init_tables()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<(), LicenseError> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS licenses (
                id TEXT PRIMARY KEY,
                product TEXT NOT NULL,
                customer TEXT NOT NULL,
                license_key TEXT NOT NULL UNIQUE,
                created TEXT NOT NULL,
                expires TEXT NOT NULL,
                features TEXT NOT NULL,
                max_machines INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0,
                lease_duration_hours INTEGER NOT NULL DEFAULT 168,
                lease_grace_hours INTEGER NOT NULL DEFAULT 24
            );

            CREATE TABLE IF NOT EXISTS machine_activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id TEXT NOT NULL,
                machine_code TEXT NOT NULL,
                friendly_name TEXT NOT NULL DEFAULT '',
                activated_at TEXT NOT NULL,
                lease_expires_at TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (license_id) REFERENCES licenses(id),
                UNIQUE(license_id, machine_code)
            );

            CREATE INDEX IF NOT EXISTS idx_license_key ON licenses(license_key);
            CREATE INDEX IF NOT EXISTS idx_activations_license ON machine_activations(license_id);",
            )
            .map_err(|e| LicenseError::Other(format!("DB init: {}", e)))?;
        self.migrate()?;
        Ok(())
    }

    fn migrate(&self) -> Result<(), LicenseError> {
        // Add lease columns to existing databases
        let _ = self.conn.execute_batch(
            "ALTER TABLE licenses ADD COLUMN lease_duration_hours INTEGER NOT NULL DEFAULT 168;
             ALTER TABLE licenses ADD COLUMN lease_grace_hours INTEGER NOT NULL DEFAULT 24;
             ALTER TABLE machine_activations ADD COLUMN lease_expires_at TEXT NOT NULL DEFAULT '';"
        );
        Ok(())
    }

    /// Delete machine activations whose lease has expired (cleanup on access).
    pub fn cleanup_expired_leases(&self, license_id: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "DELETE FROM machine_activations
                 WHERE license_id = ?1 AND lease_expires_at != '' AND lease_expires_at < ?2",
                params![license_id, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB cleanup: {}", e)))?;
        Ok(())
    }

    pub fn insert_license(&self, license: &License) -> Result<(), LicenseError> {
        let features_json = serde_json::to_string(&license.features)?;
        let expires_str = license
            .expires
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        self.conn
            .execute(
                "INSERT INTO licenses (id, product, customer, license_key, created, expires, features, max_machines, revoked, lease_duration_hours, lease_grace_hours)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    license.id,
                    license.product,
                    license.customer,
                    license.license_key,
                    license.created.to_rfc3339(),
                    expires_str,
                    features_json,
                    license.max_machines,
                    license.revoked as i32,
                    license.lease_duration_hours,
                    license.lease_grace_hours,
                ],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(())
    }

    pub fn get_license_by_key(&self, license_key: &str) -> Result<Option<License>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, product, customer, license_key, created, expires, features, max_machines, revoked, lease_duration_hours, lease_grace_hours
             FROM licenses WHERE license_key = ?1",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;

        let mut rows = stmt
            .query(params![license_key])
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;

        let row = match rows
            .next()
            .map_err(|e| LicenseError::Other(format!("DB next: {}", e)))?
        {
            Some(r) => r,
            None => return Ok(None),
        };

        let id: String = row
            .get(0)
            .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?;
        let features_json: String = row
            .get(6)
            .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?;
        let features: Vec<String> = serde_json::from_str(&features_json)?;

        let created_str: String = row
            .get(4)
            .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?;
        let expires_str: String = row
            .get(5)
            .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?;

        let created = DateTime::parse_from_rfc3339(&created_str)
            .map_err(|e| LicenseError::Other(format!("Date parse: {}", e)))?
            .with_timezone(&Utc);
        let expires = if expires_str.is_empty() {
            None
        } else {
            Some(
                DateTime::parse_from_rfc3339(&expires_str)
                    .map_err(|e| LicenseError::Other(format!("Date parse: {}", e)))?
                    .with_timezone(&Utc),
            )
        };

        let lease_duration_hours: u32 = row
            .get(9)
            .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?;

        // Cleanup expired leases immediately
        self.cleanup_expired_leases(&id)?;

        let mut license = License {
            id: id.clone(),
            product: row
                .get(1)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?,
            customer: row
                .get(2)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?,
            license_key: row
                .get(3)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?,
            created,
            expires,
            features,
            max_machines: row
                .get::<_, u32>(7)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?,
            lease_duration_hours,
            lease_grace_hours: row
                .get(10)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?,
            machines: Vec::new(),
            revoked: row
                .get::<_, i32>(8)
                .map_err(|e| LicenseError::Other(format!("DB get: {}", e)))?
                != 0,
        };

        license.machines = self.get_machine_activations(&id)?;
        Ok(Some(license))
    }

    fn get_machine_activations(
        &self,
        license_id: &str,
    ) -> Result<Vec<MachineActivation>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT machine_code, friendly_name, activated_at, lease_expires_at
             FROM machine_activations WHERE license_id = ?1",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;

        let activations = stmt
            .query_map(params![license_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .filter_map(|(machine_code, friendly_name, activated_str, lease_str)| {
                let activated_at = DateTime::parse_from_rfc3339(&activated_str)
                    .ok()?
                    .with_timezone(&Utc);
                let lease_expires_at = if lease_str.is_empty() {
                    None
                } else {
                    Some(
                        DateTime::parse_from_rfc3339(&lease_str)
                            .ok()?
                            .with_timezone(&Utc),
                    )
                };
                Some(MachineActivation {
                    machine_code,
                    friendly_name,
                    activated_at,
                    lease_expires_at,
                })
            })
            .collect();

        Ok(activations)
    }

    pub fn add_machine_activation(
        &self,
        license_id: &str,
        machine_code: &str,
        friendly_name: &str,
        lease_expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), LicenseError> {
        let lease_str = lease_expires_at
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        self.conn
            .execute(
                "INSERT INTO machine_activations (license_id, machine_code, friendly_name, activated_at, lease_expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(license_id, machine_code) DO UPDATE SET
                activated_at = excluded.activated_at,
                lease_expires_at = excluded.lease_expires_at",
                params![
                    license_id,
                    machine_code,
                    friendly_name,
                    Utc::now().to_rfc3339(),
                    lease_str,
                ],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(())
    }

    pub fn remove_machine_activation(
        &self,
        license_id: &str,
        machine_code: &str,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "DELETE FROM machine_activations WHERE license_id = ?1 AND machine_code = ?2",
                params![license_id, machine_code],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(())
    }

    pub fn revoke_license(&self, license_key: &str) -> Result<bool, LicenseError> {
        let rows = self
            .conn
            .execute(
                "UPDATE licenses SET revoked = 1 WHERE license_key = ?1",
                params![license_key],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(rows > 0)
    }

    pub fn list_licenses(&self) -> Result<Vec<License>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, product, customer, license_key, created, expires, features, max_machines, revoked, lease_duration_hours, lease_grace_hours
             FROM licenses ORDER BY created DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, u32>(7)?,
                    row.get::<_, i32>(8)?,
                    row.get::<_, u32>(9)?,
                    row.get::<_, u32>(10)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;

        let mut licenses = Vec::new();
        for row in rows {
            let (
                id,
                product,
                customer,
                license_key,
                created_str,
                expires_str,
                features_json,
                max_machines,
                revoked,
                lease_duration_hours,
                lease_grace_hours,
            ) = row.map_err(|e| LicenseError::Other(format!("DB row: {}", e)))?;

            let features: Vec<String> = serde_json::from_str(&features_json).unwrap_or_default();
            let created = DateTime::parse_from_rfc3339(&created_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let expires = if expires_str.is_empty() {
                None
            } else {
                Some(
                    DateTime::parse_from_rfc3339(&expires_str)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                )
            };

            // Cleanup expired leases
            let _ = self.cleanup_expired_leases(&id);

            let machines = self.get_machine_activations(&id).unwrap_or_default();

            licenses.push(License {
                id,
                product,
                customer,
                license_key,
                created,
                expires,
                features,
                max_machines,
                lease_duration_hours,
                lease_grace_hours,
                machines,
                revoked: revoked != 0,
            });
        }

        Ok(licenses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use crate::license::DEFAULT_LEASE_DURATION_HOURS;

    fn test_db() -> LicenseDb {
        LicenseDb::open(":memory:").unwrap()
    }

    fn lease_expires(hours: i64) -> Option<DateTime<Utc>> {
        Some(Utc::now() + Duration::hours(hours))
    }

    #[test]
    fn test_create_and_get_license() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test Corp".to_string(),
            Some(Utc::now() + Duration::days(365)),
            vec!["full_fusion".to_string()],
            3,
        );

        db.insert_license(&license).unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.id, license.id);
        assert_eq!(retrieved.product, "FusionHub");
        assert_eq!(retrieved.customer, "Test Corp");
        assert_eq!(retrieved.features, vec!["full_fusion"]);
        assert_eq!(retrieved.max_machines, 3);
        assert_eq!(retrieved.lease_duration_hours, DEFAULT_LEASE_DURATION_HOURS);
        assert!(!retrieved.revoked);
    }

    #[test]
    fn test_machine_activations() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            2,
        );
        db.insert_license(&license).unwrap();

        let lease = lease_expires(168);
        db.add_machine_activation(&license.id, "machine1", "ECU-1", lease)
            .unwrap();
        db.add_machine_activation(&license.id, "machine2", "ECU-2", lease)
            .unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 2);
        assert!(retrieved.machines[0].lease_expires_at.is_some());

        db.remove_machine_activation(&license.id, "machine1")
            .unwrap();
        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 1);
        assert_eq!(retrieved.machines[0].machine_code, "machine2");
    }

    #[test]
    fn test_expired_lease_cleaned_on_access() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            1,
        );
        db.insert_license(&license).unwrap();

        // Add a machine with an already-expired lease
        let expired_lease = Some(Utc::now() - Duration::hours(1));
        db.add_machine_activation(&license.id, "old_machine", "Old", expired_lease)
            .unwrap();

        // Access triggers cleanup
        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 0);
    }

    #[test]
    fn test_lease_renewal_updates_expiry() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            1,
        );
        db.insert_license(&license).unwrap();

        let lease1 = Some(Utc::now() + Duration::hours(1));
        db.add_machine_activation(&license.id, "machine1", "M1", lease1)
            .unwrap();

        // Renew with longer lease
        let lease2 = Some(Utc::now() + Duration::hours(168));
        db.add_machine_activation(&license.id, "machine1", "M1", lease2)
            .unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 1);
        // The lease should have been updated (closer to 168h than 1h from now)
        let lease_dt = retrieved.machines[0].lease_expires_at.unwrap();
        let hours_remaining = (lease_dt - Utc::now()).num_hours();
        assert!(hours_remaining > 100);
    }

    #[test]
    fn test_no_lease_activation() {
        let db = test_db();
        let mut license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            1,
        );
        license.lease_duration_hours = 0;
        db.insert_license(&license).unwrap();

        db.add_machine_activation(&license.id, "machine1", "M1", None)
            .unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 1);
        assert!(retrieved.machines[0].lease_expires_at.is_none());
    }

    #[test]
    fn test_revoke_license() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            0,
        );
        db.insert_license(&license).unwrap();

        let revoked = db.revoke_license(&license.license_key).unwrap();
        assert!(revoked);

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert!(retrieved.revoked);
    }

    #[test]
    fn test_list_licenses() {
        let db = test_db();
        for i in 0..3 {
            let license = License::new(
                "FusionHub".to_string(),
                format!("Customer {}", i),
                Some(Utc::now() + Duration::days(30)),
                vec![],
                0,
            );
            db.insert_license(&license).unwrap();
        }

        let all = db.list_licenses().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_get_nonexistent_license() {
        let db = test_db();
        let result = db.get_license_by_key("NONEXISTENT").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_perpetual_license_roundtrip() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Perpetual Corp".to_string(),
            None,
            vec!["full_fusion".to_string()],
            0,
        );
        db.insert_license(&license).unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert!(retrieved.expires.is_none());
        assert!(!retrieved.is_expired());
    }

    #[test]
    fn test_duplicate_machine_renews() {
        let db = test_db();
        let license = License::new(
            "FusionHub".to_string(),
            "Test".to_string(),
            Some(Utc::now() + Duration::days(30)),
            vec![],
            0,
        );
        db.insert_license(&license).unwrap();

        let lease = lease_expires(168);
        db.add_machine_activation(&license.id, "machine1", "M1", lease)
            .unwrap();
        db.add_machine_activation(&license.id, "machine1", "M1 again", lease)
            .unwrap();

        let retrieved = db
            .get_license_by_key(&license.license_key)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.machines.len(), 1);
    }
}
