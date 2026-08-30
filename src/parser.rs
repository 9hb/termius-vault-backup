use crate::crypto::{decrypt_secretbox, format_pem};
use crate::exporters::sanitize_filename;
use crate::models::*;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Parses JSON dump or extracts from raw Termius JSON structure
pub fn parse_termius_json(json_content: &str, raw_key: Option<&[u8; 32]>) -> Result<TermiusVault> {
    let root: serde_json::Value = serde_json::from_str(json_content)
        .context("Failed to parse JSON file")?;

    let mut vault = TermiusVault {
        hosts: vec![],
        keys: vec![],
        identities: vec![],
        snippets: vec![],
        port_forwardings: vec![],
        known_hosts: vec![],
        groups: vec![],
        export_timestamp: chrono::Utc::now().to_rfc3339(),
    };

    // 1. Keys
    if let Some(keys_array) = root.get("keys").and_then(|v| v.as_array()) {
        for k in keys_array {
            let id = k.get("id").or_else(|| k.get("_id")).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let label = k.get("label").or_else(|| k.get("name")).and_then(|v| v.as_str()).unwrap_or("unnamed_key").to_string();
            let mut priv_key = k.get("private_key").or_else(|| k.get("privateKey")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let pub_key = k.get("public_key").or_else(|| k.get("publicKey")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let passphrase = k.get("passphrase").and_then(|v| v.as_str()).map(|s| s.to_string());

            if let (Some(pk), Some(dec_key)) = (&priv_key, raw_key) {
                if !pk.contains("-----BEGIN") {
                    if let Ok(decrypted_bytes) = decrypt_secretbox(pk, dec_key) {
                        if let Ok(decrypted_str) = String::from_utf8(decrypted_bytes) {
                            priv_key = Some(format_pem(&decrypted_str));
                        }
                    }
                }
            }

            vault.keys.push(TermiusKey {
                id,
                label,
                private_key: priv_key,
                public_key: pub_key,
                passphrase,
                key_type: k.get("key_type").and_then(|v| v.as_str()).map(|s| s.to_string()),
                is_encrypted: false,
            });
        }
    }

    // 2. Identities
    if let Some(idents_array) = root.get("identities").and_then(|v| v.as_array()) {
        for i in idents_array {
            let id = i.get("id").or_else(|| i.get("_id")).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let label = i.get("label").or_else(|| i.get("name")).and_then(|v| v.as_str()).unwrap_or("identity").to_string();
            let username = i.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());
            let mut password = i.get("password").and_then(|v| v.as_str()).map(|s| s.to_string());
            let key_id = i.get("key_id").or_else(|| i.get("keyId")).and_then(|v| v.as_str()).map(|s| s.to_string());

            if let (Some(pwd), Some(dec_key)) = (&password, raw_key) {
                if let Ok(decrypted_bytes) = decrypt_secretbox(pwd, dec_key) {
                    if let Ok(decrypted_str) = String::from_utf8(decrypted_bytes) {
                        password = Some(decrypted_str);
                    }
                }
            }

            vault.identities.push(TermiusIdentity {
                id,
                label,
                username,
                password,
                key_id,
                comment: i.get("comment").and_then(|v| v.as_str()).map(|s| s.to_string()),
            });
        }
    }

    // 3. Hosts
    if let Some(hosts_array) = root.get("hosts").or_else(|| root.get("items")).and_then(|v| v.as_array()) {
        for h in hosts_array {
            let id = h.get("id").or_else(|| h.get("_id")).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let label = h.get("label").or_else(|| h.get("name")).and_then(|v| v.as_str()).unwrap_or("server").to_string();
            let address = h.get("address").or_else(|| h.get("host")).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let port = h.get("port").and_then(|v| v.as_u64()).map(|p| p as u16);
            let username = h.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());
            let identity_id = h.get("identity_id").or_else(|| h.get("identityId")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let key_id = h.get("key_id").or_else(|| h.get("keyId")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let group_id = h.get("group_id").or_else(|| h.get("groupId")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let comment = h.get("comment").and_then(|v| v.as_str()).map(|s| s.to_string());

            let tags: Vec<String> = h.get("tags")
                .and_then(|t| t.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            vault.hosts.push(TermiusHost {
                id,
                label,
                address,
                port,
                username,
                identity_id,
                key_id,
                group_id,
                comment,
                tags,
                proxy_host_id: h.get("proxy_host_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
                local_forwards: vec![],
                remote_forwards: vec![],
                dynamic_forwards: vec![],
            });
        }
    }

    // 4. Snippets
    if let Some(snips_array) = root.get("snippets").and_then(|v| v.as_array()) {
        for s in snips_array {
            vault.snippets.push(TermiusSnippet {
                id: s.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                label: s.get("label").or_else(|| s.get("name")).and_then(|v| v.as_str()).unwrap_or("snippet").to_string(),
                script: s.get("script").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                note: s.get("note").and_then(|v| v.as_str()).map(|n| n.to_string()),
            });
        }
    }

    Ok(vault)
}
