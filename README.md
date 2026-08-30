# termius-vault-backup

> **CLI to decrypt & export Termius vaults directly into standard OpenSSH config and PEM keys.**

`termius-vault-backup` is a high-performance, standalone Rust tool that extracts, decrypts, and packages your Termius vault directly from local storage (IndexedDB/LevelDB) into standard formats without relying on external cloud endpoints.

---

## ✨ Features

- 🔐 **Zero-Config Decryption**: Automatically retrieves decryption keys from the OS Keyring (GNOME SecretStorage / Keytar).
- 🔑 **Complete Key Extraction**: Decrypts and normalizes private keys into `.pem` / `id_rsa` / `id_ed25519` files with proper UNIX permissions (`chmod 600`).
- 🖥️ **OpenSSH Compatibility**: Generates standard `~/.ssh/config` mappings (hosts, ports, users, proxy jumps, and identity files).
- 📊 **CSV & Raw JSON Export**: Full summary table in `hosts.csv` plus raw decrypted JSON backups for hosts, keys, snippets, identities, and tunnel forwardings.
- 📦 **Portable Package**: Creates a standalone `.tar.gz` archive containing the entire decoupled configuration.

---

## 🚀 Installation & Build

```bash
git clone https://github.com/your-username/termius-vault-backup.git
cd termius-vault-backup
cargo build --release
cp target/release/termius-vault-backup ~/.local/bin/
```

---

## 🛠️ Usage

### 1. Automatic Local Extraction (Zero-Config)
Reads directly from local Flatpak or Native Termius storage and auto-fetches the master key from the OS keyring:
```bash
termius-vault-backup extract-local -o ~/termius_backup.tar.gz
```

### 2. Extraction using Credentials
```bash
termius-vault-backup extract-local --email "user@example.com" --password "YourSecretPassword" -o ~/termius_backup.tar.gz
```

### 3. Extraction with Explicit Master Key
```bash
termius-vault-backup extract-local --key "<32_BYTE_BASE64_OR_HEX_KEY>" -o ~/termius_backup.tar.gz
```

### 4. Export from an Existing JSON Dump
```bash
termius-vault-backup export -i /path/to/termius_dump.json -o ~/termius_backup.tar.gz
```

---

## 📦 Output Structure (`.tar.gz`)

```text
termius_backup/
├── config/
│   ├── config                  # Standard ~/.ssh/config
│   └── hosts.csv               # Summary table of all hosts
├── keys/
│   ├── YUBIKEY.pem             # Decrypted private key (chmod 600)
│   ├── RASPBERRY_PI.pem        # Decrypted private key (chmod 600)
│   └── *.pub                   # Public keys
├── raw/
│   ├── hosts.json              # Full hosts metadata
│   ├── keys.json               # Full keys metadata
│   ├── snippets.json           # Shell automation scripts
│   ├── keychains_identities.json
│   └── port_forwardings.json
└── MANIFEST.json               # Backup metadata and validation stats
```

---

## 🔒 Security & Privacy

This tool runs 100% locally on your machine. No telemetry, no external network calls, and no plain-text credentials are ever transmitted.

## 📄 License

MIT
