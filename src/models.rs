use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermiusVault {
    pub hosts: Vec<TermiusHost>,
    pub keys: Vec<TermiusKey>,
    pub identities: Vec<TermiusIdentity>,
    pub snippets: Vec<TermiusSnippet>,
    pub port_forwardings: Vec<TermiusPortForwarding>,
    pub known_hosts: Vec<TermiusKnownHost>,
    pub groups: Vec<TermiusGroup>,
    #[serde(default)]
    pub export_timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermiusHost {
    pub id: String,
    pub label: String,
    pub address: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub identity_id: Option<String>,
    pub key_id: Option<String>,
    pub group_id: Option<String>,
    pub comment: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub proxy_host_id: Option<String>,
    #[serde(default)]
    pub local_forwards: Vec<String>,
    #[serde(default)]
    pub remote_forwards: Vec<String>,
    #[serde(default)]
    pub dynamic_forwards: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermiusKey {
    pub id: String,
    pub label: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub passphrase: Option<String>,
    pub key_type: Option<String>,
    #[serde(default)]
    pub is_encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermiusIdentity {
    pub id: String,
    pub label: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub key_id: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermiusPortForwarding {
    pub id: String,
    pub label: String,
    pub forwarding_type: String, // "Local", "Remote", "Dynamic"
    pub local_port: Option<u16>,
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
    pub host_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermiusKnownHost {
    pub host: String,
    pub key_type: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermiusSnippet {
    pub id: String,
    pub label: String,
    pub script: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermiusGroup {
    pub id: String,
    pub label: String,
    pub parent_id: Option<String>,
}
