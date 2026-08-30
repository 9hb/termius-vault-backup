use crate::exporters::*;
use crate::models::*;
use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

/// Creates the complete backup directory and packages it into a .tar.gz archive
pub fn create_backup_archive(vault: &TermiusVault, output_archive_path: &Path) -> Result<PathBuf> {
    let temp_dir = std::env::temp_dir().join(format!("termius_export_{}", chrono::Utc::now().timestamp()));
    fs::create_dir_all(&temp_dir)?;

    let config_dir = temp_dir.join("config");
    let keys_dir = temp_dir.join("keys");
    let raw_dir = temp_dir.join("raw");

    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&raw_dir)?;

    // 1. Generate SSH Config & CSV
    let ssh_config = generate_ssh_config(vault, "./keys");
    fs::write(config_dir.join("config"), ssh_config)?;

    let hosts_csv = generate_hosts_csv(vault)?;
    fs::write(config_dir.join("hosts.csv"), hosts_csv)?;

    // Generate known_hosts file if available
    let mut known_hosts_content = String::new();
    for kh in &vault.known_hosts {
        known_hosts_content.push_str(&format!("{} {} {}\n", kh.host, kh.key_type, kh.public_key));
    }
    if !known_hosts_content.is_empty() {
        fs::write(config_dir.join("known_hosts"), known_hosts_content)?;
    }

    // 2. Export Private and Public Keys (.pem / .pub)
    for key in &vault.keys {
        let base_name = sanitize_filename(&key.label);
        if let Some(priv_k) = &key.private_key {
            let priv_file = keys_dir.join(format!("{}.pem", base_name));
            fs::write(&priv_file, priv_k)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&priv_file)?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(&priv_file, perms)?;
            }
        }

        if let Some(pub_k) = &key.public_key {
            let pub_file = keys_dir.join(format!("{}.pub", base_name));
            fs::write(pub_file, pub_k)?;
        }
    }

    // 3. Raw JSONs (Hosts, Identities/Keychain, Snippets, PortForwardings, KnownHosts, Groups)
    fs::write(raw_dir.join("hosts.json"), serde_json::to_string_pretty(&vault.hosts)?)?;
    fs::write(raw_dir.join("keys.json"), serde_json::to_string_pretty(&vault.keys)?)?;
    fs::write(raw_dir.join("keychains_identities.json"), serde_json::to_string_pretty(&vault.identities)?)?;
    fs::write(raw_dir.join("snippets.json"), serde_json::to_string_pretty(&vault.snippets)?)?;
    fs::write(raw_dir.join("port_forwardings.json"), serde_json::to_string_pretty(&vault.port_forwardings)?)?;
    fs::write(raw_dir.join("known_hosts.json"), serde_json::to_string_pretty(&vault.known_hosts)?)?;
    fs::write(raw_dir.join("groups.json"), serde_json::to_string_pretty(&vault.groups)?)?;
    fs::write(temp_dir.join("vault_all.json"), serde_json::to_string_pretty(vault)?)?;

    // 4. Manifest
    let manifest = serde_json::json!({
        "generator": "termius-vault-backup (Rust)",
        "version": "0.2.0",
        "timestamp": vault.export_timestamp,
        "counts": {
            "hosts": vault.hosts.len(),
            "keys": vault.keys.len(),
            "identities_keychains": vault.identities.len(),
            "snippets": vault.snippets.len(),
            "port_forwardings": vault.port_forwardings.len(),
            "known_hosts": vault.known_hosts.len(),
            "groups": vault.groups.len()
        }
    });
    fs::write(temp_dir.join("MANIFEST.json"), serde_json::to_string_pretty(&manifest)?)?;

    // 5. Compress to .tar.gz
    let tar_gz_file = File::create(output_archive_path)
        .with_context(|| format!("Failed to create archive at {:?}", output_archive_path))?;
    let enc = GzEncoder::new(tar_gz_file, Compression::default());
    let mut tar_builder = tar::Builder::new(enc);

    tar_builder.append_dir_all("termius_backup", &temp_dir)?;
    tar_builder.finish()?;

    // Cleanup temp directory
    let _ = fs::remove_dir_all(&temp_dir);

    Ok(output_archive_path.to_path_buf())
}
