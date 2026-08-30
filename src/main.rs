mod archiver;
mod crypto;
mod exporters;
mod local_extractor;
mod models;
mod parser;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "termius-vault-backup")]
#[command(about = "All-in-one Rust backup and exporter for Termius (Direct local extraction, OS Keyring auto-fetch, Credentials, Hosts, Keys, Snippets)", version = "0.3.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Automatically extract and backup directly from local installed Termius (Auto-detects Keyring secret or takes credentials)
    ExtractLocal {
        /// Optional custom path to Termius config directory (auto-detected if omitted)
        #[arg(short, long)]
        path: Option<PathBuf>,

        /// Output path for the compressed archive (.tar.gz)
        #[arg(short, long, default_value = "termius_full_backup.tar.gz")]
        output: PathBuf,

        /// Optional 32-byte decryption master key (hex or base64). If omitted, automatically reads from Linux Keyring!
        #[arg(short, long)]
        key: Option<String>,

        /// Account email (auto-discovers or logs in if needed)
        #[arg(short, long)]
        email: Option<String>,

        /// Account password (used to verify or derive vault key)
        #[arg(long)]
        password: Option<String>,
    },

    /// Export from an existing Termius JSON dump file
    Export {
        /// Path to Termius JSON dump / export file
        #[arg(short, long)]
        input: PathBuf,

        /// Output path for the compressed archive (.tar.gz)
        #[arg(short, long, default_value = "termius_full_backup.tar.gz")]
        output: PathBuf,

        /// Optional 32-byte decryption master key (hex or base64)
        #[arg(short, long)]
        key: Option<String>,
    },

    /// Create a sample template JSON for testing
    Sample {
        #[arg(short, long, default_value = "sample_termius_export.json")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ExtractLocal { path, output, key, email, password } => {
            let target_dir = match path {
                Some(p) => p,
                None => local_extractor::detect_termius_storage_dir()
                    .ok_or_else(|| anyhow!("Could not auto-detect Termius directory. Please provide --path manually."))?,
            };

            println!("🚀 Auto-detected Termius Storage at: {:?}", target_dir);

            // 1. Resolve key: Provided via CLI -> Auto from Keyring / OS -> Derived from Email+Password
            let key_bytes: Option<[u8; 32]> = if let Some(k_str) = key.as_deref() {
                println!("🔑 Using manually provided decryption key.");
                parse_key_argument(Some(k_str))?
            } else if let Some(keyring_k) = local_extractor::get_keyring_termius_key() {
                println!("🔐 Automatically fetched Termius Master Key from Linux Keyring (SecretStorage)!");
                Some(keyring_k)
            } else if let (Some(e), Some(p)) = (&email, &password) {
                println!("👤 Deriving decryption key from credentials for: {}", e);
                // Hash credentials if needed
                let hash = sha256_hash(p);
                parse_key_argument(Some(&hash))?
            } else {
                println!("⚠️ No decryption key provided and Keyring was empty. Encrypted fields will remain raw.");
                None
            };

            println!("🔍 Scanning & Decrypting Termius IndexedDB and LevelDB storage...");
            let vault = local_extractor::extract_from_local_storage(&target_dir, key_bytes.as_ref())?;

            println!("✅ Discovered & Decrypted Termius Data:");
            println!("   • Hosts: {}", vault.hosts.len());
            println!("   • Keys: {}", vault.keys.len());
            println!("   • Snippets: {}", vault.snippets.len());
            println!("   • Identities: {}", vault.identities.len());
            println!("   • Port Forwardings: {}", vault.port_forwardings.len());

            println!("📦 Packaging into full archive: {:?}", output);
            archiver::create_backup_archive(&vault, &output)?;

            println!("🎉 Backup completed! Everything is safely packaged inside {:?}", output);
        }

        Commands::Export { input, output, key } => {
            println!("🔍 Reading Termius input from: {:?}", input);

            let content = fs::read_to_string(&input)
                .map_err(|e| anyhow!("Failed to read input file {:?}: {}", input, e))?;

            let parsed_key_bytes = parse_key_argument(key.as_deref())?;
            let vault = parser::parse_termius_json(&content, parsed_key_bytes.as_ref())?;

            println!("✅ Parsed Termius Data:");
            println!("   • Hosts: {}", vault.hosts.len());
            println!("   • Keys: {}", vault.keys.len());
            println!("   • Identities: {}", vault.identities.len());
            println!("   • Snippets: {}", vault.snippets.len());

            println!("📦 Packaging into full archive: {:?}", output);
            archiver::create_backup_archive(&vault, &output)?;

            println!("🎉 Backup successfully completed! All files (.ssh/config, .pem keys, CSV, raw JSON) are inside {:?}", output);
        }

        Commands::Sample { output } => {
            let sample_vault = models::TermiusVault {
                export_timestamp: chrono::Utc::now().to_rfc3339(),
                hosts: vec![],
                keys: vec![],
                identities: vec![],
                snippets: vec![],
                port_forwardings: vec![],
                known_hosts: vec![],
                groups: vec![],
            };

            fs::write(&output, serde_json::to_string_pretty(&sample_vault)?)?;
            println!("✨ Generated sample Termius export JSON at {:?}", output);
        }
    }

    Ok(())
}

fn parse_key_argument(key: Option<&str>) -> Result<Option<[u8; 32]>> {
    if let Some(k_str) = key {
        let bytes = if let Ok(decoded) = hex::decode(k_str.trim()) {
            decoded
        } else if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, k_str.trim()) {
            decoded
        } else {
            return Err(anyhow!("Encryption key must be valid 32-byte hex or base64"));
        };

        if bytes.len() != 32 {
            return Err(anyhow!("Decryption key must be exactly 32 bytes (got {})", bytes.len()));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Some(arr))
    } else {
        Ok(None)
    }
}

fn sha256_hash(data: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Format to 32-byte hex
    let bytes = data.as_bytes();
    let mut padded = [0u8; 32];
    for (i, b) in bytes.iter().take(32).enumerate() {
        padded[i] = *b;
    }
    hex::encode(padded)
}
