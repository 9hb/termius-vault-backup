# termius-vault-backup

A standalone Rust utility to decrypt and export Termius local storage databases directly into OpenSSH configuration files, PEM private keys, and structured JSON/CSV records.

```text
┌─────────────────────────┐
│   Termius Local Data    │ (IndexedDB / LevelDB storage)
└────────────┬────────────┘
             │
             │ secretbox (XSalsa20-Poly1305)
             ▼
┌─────────────────────────┐
│  termius-vault-backup   │ <─── OS Keyring / Master Key
└────────────┬────────────┘
             │
             ├───> ~/.ssh/config + hosts.csv
             ├───> keys/*.pem (chmod 600) + keys/*.pub
             └───> raw/*.json (hosts, snippets, tunnels)
```

---

## Features

- Direct LevelDB/IndexedDB parsing from local Flatpak and native installations
- Automatic decryption key retrieval from Linux SecretStorage / GNOME Keyring
- OpenSSH `~/.ssh/config` generation with host aliases, ports, and key mappings
- Private key export into standard PEM files with `0600` permissions
- Structured export of snippets, port forwardings, identities, and host tags

---

## Installation

### Prerequisites

- Rust toolchain (`cargo`, `rustc` 1.80+)

### Build from source

```bash
git clone https://github.com/9hb/termius-vault-backup.git
cd termius-vault-backup
cargo build --release
install -Dm755 target/release/termius-vault-backup ~/.local/bin/termius-vault-backup
```

---

## Usage

### 1. Automatic extraction (recommended)

Auto-detects the Termius installation directory and fetches the decryption key from the system keyring:

```bash
termius-vault-backup extract-local -o termius_backup.tar.gz
```

### 2. Manual key specification

If running in a headless environment without an active SecretStorage daemon:

```bash
termius-vault-backup extract-local --key "<32_BYTE_BASE64_KEY>" -o termius_backup.tar.gz
```

### 3. Custom storage directory

```bash
termius-vault-backup extract-local --path ~/.var/app/com.termius.Termius/config/Termius -o backup.tar.gz
```

### 4. Convert an existing raw JSON dump

```bash
termius-vault-backup export -i raw_dump.json -o backup.tar.gz
```

---

## Archive Layout

Extracted `.tar.gz` archives contain the following hierarchy:

```text
termius_backup/
├── config/
│   ├── config                  # Standard OpenSSH configuration file
│   └── hosts.csv               # Tabular CSV summary of all hosts
├── keys/
│   ├── id_ed25519_prod.pem     # Decrypted private key (chmod 0600)
│   ├── id_ed25519_prod.pub     # Public key
│   └── ...
├── raw/
│   ├── hosts.json              # Decrypted host objects
│   ├── keys.json               # Decrypted key material and passphrases
│   ├── snippets.json           # Automation scripts
│   ├── keychains_identities.json
│   └── port_forwardings.json   # Local, remote, and dynamic forward rules
└── MANIFEST.json               # Export metadata and record counts
```

> [!NOTE]
> All extracted private keys inside the archive are written with `chmod 0600` permissions. When extracting on UNIX systems, use `tar -zxpf` to preserve file permissions.
