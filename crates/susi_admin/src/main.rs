use anyhow::{bail, Context, Result};
use chrono::{Duration, NaiveDate, Utc};
use clap::{Parser, Subcommand};
use susi_core::crypto::{
    generate_keypair, private_key_from_pem, private_key_to_pem, public_key_to_pem, sign_license,
};
use susi_core::db::LicenseDb;
use susi_core::fingerprint;
use susi_core::License;

#[derive(Parser)]
#[command(name = "susi-admin", about = "Susi License Administration Tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate an RSA keypair for license signing
    Keygen {
        /// Key size in bits
        #[arg(long, default_value = "4096")]
        bits: usize,
        /// Output directory for key files
        #[arg(long, default_value = ".")]
        output_dir: String,
    },

    /// Create a new license
    Create {
        /// Product name
        #[arg(long, default_value = "FusionHub")]
        product: String,
        /// Customer name
        #[arg(long)]
        customer: String,
        /// Expiry date (YYYY-MM-DD)
        #[arg(long, group = "expiry")]
        expires: Option<String>,
        /// Days until expiry (alternative to --expires)
        #[arg(long, group = "expiry")]
        days: Option<i64>,
        /// Create a perpetual license that never expires
        #[arg(long, group = "expiry")]
        perpetual: bool,
        /// Comma-separated feature list
        #[arg(long, default_value = "")]
        features: String,
        /// Maximum number of machines (0 = unlimited)
        #[arg(long, default_value = "1")]
        max_machines: u32,
        /// Path to SQLite database
        #[arg(long, default_value = "licenses.db")]
        db: String,
    },

    /// Activate a license on a machine and export a signed license file
    Export {
        /// License key (XXXXX-XXXXX-XXXXX-XXXXX)
        #[arg(long)]
        key: String,
        /// Machine code (SHA256 fingerprint). Use --auto for current machine.
        #[arg(long, required_unless_present = "auto")]
        machine_code: Option<String>,
        /// Use current machine's fingerprint
        #[arg(long)]
        auto: bool,
        /// Friendly name for this machine
        #[arg(long, default_value = "")]
        name: String,
        /// Output file for the signed license
        #[arg(long, default_value = "license.json")]
        output: String,
        /// Path to private key PEM file
        #[arg(long, default_value = "private.pem")]
        private_key: String,
        /// Path to SQLite database
        #[arg(long, default_value = "licenses.db")]
        db: String,
    },

    /// List all licenses
    List {
        /// Path to SQLite database
        #[arg(long, default_value = "licenses.db")]
        db: String,
    },

    /// Revoke a license
    Revoke {
        /// License key to revoke
        #[arg(long)]
        key: String,
        /// Path to SQLite database
        #[arg(long, default_value = "licenses.db")]
        db: String,
    },

    /// Deactivate a machine from a license
    Deactivate {
        /// License key
        #[arg(long)]
        key: String,
        /// Machine code to deactivate
        #[arg(long)]
        machine_code: String,
        /// Path to SQLite database
        #[arg(long, default_value = "licenses.db")]
        db: String,
    },

    /// Print the hardware fingerprint of this machine
    Fingerprint,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { bits, output_dir } => cmd_keygen(bits, &output_dir),
        Commands::Create {
            product,
            customer,
            expires,
            days,
            perpetual,
            features,
            max_machines,
            db,
        } => cmd_create(&product, &customer, expires, days, perpetual, &features, max_machines, &db),
        Commands::Export {
            key,
            machine_code,
            auto,
            name,
            output,
            private_key,
            db,
        } => cmd_export(&key, machine_code, auto, &name, &output, &private_key, &db),
        Commands::List { db } => cmd_list(&db),
        Commands::Revoke { key, db } => cmd_revoke(&key, &db),
        Commands::Deactivate {
            key,
            machine_code,
            db,
        } => cmd_deactivate(&key, &machine_code, &db),
        Commands::Fingerprint => cmd_fingerprint(),
    }
}

fn cmd_keygen(bits: usize, output_dir: &str) -> Result<()> {
    println!("Generating {}-bit RSA keypair...", bits);
    let (private, public) = generate_keypair(bits)?;

    let priv_pem = private_key_to_pem(&private)?;
    let pub_pem = public_key_to_pem(&public)?;

    let priv_path = format!("{}/private.pem", output_dir);
    let pub_path = format!("{}/public.pem", output_dir);

    std::fs::create_dir_all(output_dir)?;
    std::fs::write(&priv_path, &priv_pem)
        .with_context(|| format!("Failed to write {}", priv_path))?;
    std::fs::write(&pub_path, &pub_pem)
        .with_context(|| format!("Failed to write {}", pub_path))?;

    println!("Private key: {}", priv_path);
    println!("Public key:  {}", pub_path);
    println!();
    println!("IMPORTANT: Keep private.pem secure! Only distribute public.pem.");
    Ok(())
}

fn cmd_create(
    product: &str,
    customer: &str,
    expires: Option<String>,
    days: Option<i64>,
    perpetual: bool,
    features: &str,
    max_machines: u32,
    db_path: &str,
) -> Result<()> {
    let expires_dt = if perpetual {
        None
    } else {
        Some(match (expires, days) {
            (Some(date_str), _) => {
                let date = NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
                    .with_context(|| {
                        format!("Invalid date format: {}. Use YYYY-MM-DD.", date_str)
                    })?;
                date.and_hms_opt(23, 59, 59).unwrap().and_utc()
            }
            (_, Some(d)) => Utc::now() + Duration::days(d),
            _ => Utc::now() + Duration::days(365),
        })
    };

    let feature_list: Vec<String> = features
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let license = License::new(
        product.to_string(),
        customer.to_string(),
        expires_dt,
        feature_list,
        max_machines,
    );

    let db = LicenseDb::open(db_path)?;
    db.insert_license(&license)?;

    println!("License created successfully!");
    println!();
    println!("  Key:          {}", license.license_key);
    println!("  Product:      {}", license.product);
    println!("  Customer:     {}", license.customer);
    println!(
        "  Expires:      {}",
        match &license.expires {
            Some(dt) => dt.format("%Y-%m-%d").to_string(),
            None => "PERPETUAL".to_string(),
        }
    );
    println!("  Features:     {}", license.features.join(", "));
    println!(
        "  Max machines: {}",
        if license.max_machines == 0 {
            "unlimited".to_string()
        } else {
            license.max_machines.to_string()
        }
    );
    println!("  ID:           {}", license.id);

    Ok(())
}

fn cmd_export(
    key: &str,
    machine_code: Option<String>,
    auto: bool,
    friendly_name: &str,
    output: &str,
    private_key_path: &str,
    db_path: &str,
) -> Result<()> {
    let machine_code = if auto {
        fingerprint::get_machine_code().context("Failed to compute machine fingerprint")?
    } else {
        machine_code.unwrap()
    };

    let priv_pem = std::fs::read_to_string(private_key_path)
        .with_context(|| format!("Failed to read private key from {}", private_key_path))?;
    let private_key = private_key_from_pem(&priv_pem)?;

    let db = LicenseDb::open(db_path)?;
    let license = db
        .get_license_by_key(key)?
        .with_context(|| format!("License key not found: {}", key))?;

    if license.revoked {
        bail!("License has been revoked");
    }

    if license.is_expired() {
        bail!(
            "License has expired ({})",
            license.expires.map(|dt| dt.format("%Y-%m-%d").to_string()).unwrap_or_default()
        );
    }

    // Check machine limit
    if !license.is_machine_activated(&machine_code) && !license.can_add_machine() {
        bail!(
            "Machine limit reached ({} of {})",
            license.machines.len(),
            license.max_machines
        );
    }

    // Add machine activation
    let name = if friendly_name.is_empty() {
        "Unknown".to_string()
    } else {
        friendly_name.to_string()
    };
    db.add_machine_activation(&license.id, &machine_code, &name)?;

    // Re-fetch license with the new activation
    let license = db.get_license_by_key(key)?.unwrap();
    let payload = license.to_payload();
    let signed = sign_license(&private_key, &payload)?;

    let json = serde_json::to_string_pretty(&signed)?;
    std::fs::write(output, &json)
        .with_context(|| format!("Failed to write license file to {}", output))?;

    println!("Signed license exported to: {}", output);
    println!("  Machine: {}", machine_code);
    println!(
        "  Expires: {}",
        match &license.expires {
            Some(dt) => dt.format("%Y-%m-%d").to_string(),
            None => "PERPETUAL".to_string(),
        }
    );
    Ok(())
}

fn cmd_list(db_path: &str) -> Result<()> {
    let db = LicenseDb::open(db_path)?;
    let licenses = db.list_licenses()?;

    if licenses.is_empty() {
        println!("No licenses found.");
        return Ok(());
    }

    println!(
        "{:<25} {:<20} {:<12} {:<8} {:<10} {}",
        "KEY", "CUSTOMER", "EXPIRES", "STATUS", "MACHINES", "FEATURES"
    );
    println!("{}", "-".repeat(90));

    for lic in &licenses {
        let status = if lic.revoked {
            "REVOKED"
        } else if lic.is_expired() {
            "EXPIRED"
        } else {
            "ACTIVE"
        };
        let machines = format!("{}/{}", lic.machines.len(), lic.max_machines);

        let expires_str = match &lic.expires {
            Some(dt) => dt.format("%Y-%m-%d").to_string(),
            None => "PERPETUAL".to_string(),
        };
        println!(
            "{:<25} {:<20} {:<12} {:<8} {:<10} {}",
            lic.license_key,
            truncate(&lic.customer, 18),
            expires_str,
            status,
            machines,
            lic.features.join(", "),
        );
    }

    println!();
    println!("Total: {} license(s)", licenses.len());
    Ok(())
}

fn cmd_revoke(key: &str, db_path: &str) -> Result<()> {
    let db = LicenseDb::open(db_path)?;
    let revoked = db.revoke_license(key)?;
    if revoked {
        println!("License {} has been revoked.", key);
    } else {
        println!("License key not found: {}", key);
    }
    Ok(())
}

fn cmd_deactivate(key: &str, machine_code: &str, db_path: &str) -> Result<()> {
    let db = LicenseDb::open(db_path)?;
    let license = db
        .get_license_by_key(key)?
        .with_context(|| format!("License key not found: {}", key))?;

    db.remove_machine_activation(&license.id, machine_code)?;
    println!("Machine {} deactivated from license {}.", machine_code, key);
    Ok(())
}

fn cmd_fingerprint() -> Result<()> {
    let code = fingerprint::get_machine_code().context("Failed to compute machine fingerprint")?;
    println!("{}", code);
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 1])
    } else {
        s.to_string()
    }
}
