pub mod crypto;
#[cfg(feature = "db")]
pub mod db;
pub mod error;
pub mod fingerprint;
pub mod license;

pub use crypto::{generate_keypair, sign_license, verify_license};
pub use error::LicenseError;
pub use fingerprint::get_machine_code;
pub use license::{License, LicensePayload, MachineActivation, SignedLicense};
