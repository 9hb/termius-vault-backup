use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use regex::bytes::Regex;

/// Extracts and decrypts ALL Termius entities (Hosts, Keys, Snippets, Identities, PortForwardings, KnownHosts)
pub fn extract_from_local_storage(
    termius_base_dir: &Path,
    decryption_key: Option<&[u8; 32]>,
) -> Result<crate::models::TermiusVault> {
    let indexeddb_dir = termius_base_dir.join("IndexedDB/file__0.indexeddb.leveldb");
    if !indexeddb_dir.exists() {
        return Err(anyhow!("IndexedDB folder not found at {:?}", indexeddb_dir));
    }

    let mut vault = crate::models::TermiusVault {
        hosts: vec![],
        keys: vec![],
        identities: vec![],
        snippets: vec![],
        port_forwardings: vec![],
        known_hosts: vec![],
        groups: vec![],
        export_timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let mut seen_host_ids = HashSet::new();
    let mut seen_key_ids = HashSet::new();
    let mut seen_snippet_ids = HashSet::new();
    let mut seen_ident_ids = HashSet::new();
    let mut seen_forward_ids = HashSet::new();

    let payload_re = Regex::new(r"BA[A-Za-z0-9+/=]{25,}")?;

    let mut db_files = vec![];
    for entry in fs::read_dir(&indexeddb_dir)? {
        let entry = entry?;
        let p = entry.path();
        if let Some(ext) = p.extension() {
            if ext == "log" || ext == "ldb" {
                db_files.push(p);
            }
        }
    }

    if let Some(key_32) = decryption_key {
        for file in &db_files {
            let bytes = fs::read(file)?;

            for cap in payload_re.captures_iter(&bytes) {
                if let Ok(payload_b64) = std::str::from_utf8(&cap[0]) {
                    if let Ok(decrypted_bytes) = crate::crypto::decrypt_secretbox(payload_b64, key_32) {
                        if let Ok(text) = String::from_utf8(decrypted_bytes) {
                            // Try parsing as JSON object
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                                // 1. Check if it's a Host
                                if val.get("address").is_some() || val.get("hostname").is_some() {
                                    let label = val.get("label").or_else(|| val.get("name")).and_then(|v| v.as_str()).unwrap_or("Server").to_string();
                                    let address = val.get("address").or_else(|| val.get("hostname")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                                    let port = val.get("port").and_then(|v| v.as_u64()).map(|p| p as u16);
                                    let username = val.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());
                                    let comment = val.get("comment").and_then(|v| v.as_str()).map(|s| s.to_string());

                                    let dedup_key = format!("{}:{}:{}", label, address, port.unwrap_or(22));
                                    if seen_host_ids.insert(dedup_key) && !address.is_empty() {
                                        vault.hosts.push(crate::models::TermiusHost {
                                            id: format!("host-{}", vault.hosts.len() + 1),
                                            label,
                                            address,
                                            port,
                                            username,
                                            identity_id: None,
                                            key_id: None,
                                            group_id: None,
                                            comment,
                                            tags: vec![],
                                            proxy_host_id: None,
                                            local_forwards: vec![],
                                            remote_forwards: vec![],
                                            dynamic_forwards: vec![],
                                        });
                                    }
                                }
                                // 2. Check if it's an SSH Key
                                else if val.get("private_key").is_some() || val.get("public_key").is_some() {
                                    let label = val.get("label").and_then(|v| v.as_str()).unwrap_or("SSH Key").to_string();
                                    let priv_k = val.get("private_key").and_then(|v| v.as_str()).map(crate::crypto::format_pem);
                                    let pub_k = val.get("public_key").and_then(|v| v.as_str()).map(|s| s.to_string());
                                    let passphrase = val.get("passphrase").and_then(|v| v.as_str()).map(|s| s.to_string());

                                    let dedup_key = label.clone();
                                    if seen_key_ids.insert(dedup_key) {
                                        let key_type = if pub_k.as_deref().unwrap_or("").contains("ed25519") {
                                            "ed25519"
                                        } else if pub_k.as_deref().unwrap_or("").contains("ecdsa") {
                                            "ecdsa-sk"
                                        } else {
                                            "rsa"
                                        };

                                        vault.keys.push(crate::models::TermiusKey {
                                            id: format!("key-{}", vault.keys.len() + 1),
                                            label,
                                            private_key: priv_k,
                                            public_key: pub_k,
                                            passphrase,
                                            key_type: Some(key_type.into()),
                                            is_encrypted: false,
                                        });
                                    }
                                }
                                // 3. Check if it's a Snippet
                                else if val.get("script").is_some() {
                                    let label = val.get("label").and_then(|v| v.as_str()).unwrap_or("Snippet").to_string();
                                    let script = val.get("script").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                    let note = val.get("note").and_then(|v| v.as_str()).map(|s| s.to_string());

                                    if seen_snippet_ids.insert(label.clone()) && !script.is_empty() {
                                        vault.snippets.push(crate::models::TermiusSnippet {
                                            id: format!("snippet-{}", vault.snippets.len() + 1),
                                            label,
                                            script,
                                            note,
                                        });
                                    }
                                }
                                // 4. Check if it's an Identity
                                else if val.get("username").is_some() && val.get("password").is_some() {
                                    let label = val.get("label").and_then(|v| v.as_str()).unwrap_or("Identity").to_string();
                                    let username = val.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());
                                    let password = val.get("password").and_then(|v| v.as_str()).map(|s| s.to_string());

                                    if seen_ident_ids.insert(label.clone()) {
                                        vault.identities.push(crate::models::TermiusIdentity {
                                            id: format!("ident-{}", vault.identities.len() + 1),
                                            label,
                                            username,
                                            password,
                                            key_id: None,
                                            comment: None,
                                        });
                                    }
                                }
                                // 5. Check if it's Port Forwarding
                                else if val.get("local_port").is_some() || val.get("remote_port").is_some() {
                                    let label = val.get("label").and_then(|v| v.as_str()).unwrap_or("PortForward").to_string();
                                    let ftype = val.get("type").and_then(|v| v.as_str()).unwrap_or("Local").to_string();
                                    let lport = val.get("local_port").and_then(|v| v.as_u64()).map(|p| p as u16);
                                    let rhost = val.get("remote_host").and_then(|v| v.as_str()).map(|s| s.to_string());
                                    let rport = val.get("remote_port").and_then(|v| v.as_u64()).map(|p| p as u16);

                                    if seen_forward_ids.insert(label.clone()) {
                                        vault.port_forwardings.push(crate::models::TermiusPortForwarding {
                                            id: format!("pf-{}", vault.port_forwardings.len() + 1),
                                            label,
                                            forwarding_type: ftype,
                                            local_port: lport,
                                            remote_host: rhost,
                                            remote_port: rport,
                                            host_id: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(vault)
}

/// Auto-detects Linux Keyring Termius secret and returns 32-byte key
pub fn get_keyring_termius_key() -> Option<[u8; 32]> {
    // 1. Try reading from secretstorage / keyring via python helper or direct key
    let output = std::process::Command::new("python3")
        .arg("-c")
        .arg("import secretstorage; bus = secretstorage.dbus_init(); col = secretstorage.get_default_collection(bus); items = [i.get_secret().decode() for i in col.get_all_items() if 'termius-app/localkey' in i.get_label().lower()]; print(items[0] if items else '')")
        .output()
        .ok()?;

    if output.status.success() {
        let secret_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !secret_str.is_empty() {
            if let Ok(decoded) = BASE64.decode(&secret_str) {
                if decoded.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    return Some(arr);
                }
            }
        }
    }

    None
}

/// Detects and returns the Flatpak or standard Termius data directory
pub fn detect_termius_storage_dir() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        let home_p = PathBuf::from(home);
        let flatpak_p = home_p.join(".var/app/com.termius.Termius/config/Termius");
        if flatpak_p.exists() {
            return Some(flatpak_p);
        }
        let native_p = home_p.join(".config/Termius");
        if native_p.exists() {
            return Some(native_p);
        }
    }
    None
}
