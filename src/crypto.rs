use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use crypto_secretbox::aead::Aead;
use crypto_secretbox::{Key, KeyInit, Nonce, XSalsa20Poly1305};

/// Decrypts Termius libsodium secretbox payload (version 1 byte + options 1 byte + nonce 24 bytes + ciphertext)
pub fn decrypt_secretbox(encrypted_base64_or_hex: &str, raw_key_32_bytes: &[u8; 32]) -> Result<Vec<u8>> {
    let payload = if let Ok(decoded) = BASE64.decode(encrypted_base64_or_hex.trim()) {
        decoded
    } else if let Ok(decoded) = hex::decode(encrypted_base64_or_hex.trim()) {
        decoded
    } else {
        return Err(anyhow!("Invalid base64 or hex format for ciphertext"));
    };

    if payload.len() < 26 {
        return Err(anyhow!("Ciphertext payload too short (minimum 26 bytes)"));
    }

    // Termius format: [version: 1B, options: 1B, nonce: 24B, ciphertext + 16B poly1305 tag]
    let nonce_bytes = &payload[2..26];
    let ciphertext = &payload[26..];

    let cipher = XSalsa20Poly1305::new(Key::from_slice(raw_key_32_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Failed to decrypt secretbox: {:?}", e))?;

    Ok(decrypted)
}

/// Normalizes SSH private keys to valid PEM format with proper line breaks
pub fn format_pem(key_content: &str) -> String {
    let trimmed = key_content.trim();
    if trimmed.contains("-----BEGIN") {
        trimmed.to_string()
    } else {
        // Wrap raw base64 key into standard OpenSSH / RSA PEM block
        format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n", trimmed)
    }
}
