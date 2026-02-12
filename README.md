# touchfs

Touch ID-gated encrypted files for macOS.

Seal sensitive files (`.env`, credentials, configs) in-place — they become ciphertext. Mount a FUSE filesystem to serve them decrypted, with Touch ID on every access.

## Install

```bash
brew tap tetratorus/tap && brew install --cask touchfs
```

## Usage

```bash
touchfs set              # Create password (one time setup)
touchfs seal <file>      # Encrypt a file in-place
touchfs unseal <file>    # Decrypt a sealed file
touchfs mount            # Mount FUSE, serve decrypted files from cwd
touchfs reset            # Delete key from Keychain
```

Use `-p` with `seal`/`unseal` to use a password instead of Touch ID.

## Build from source

```bash
make build
```

<details>
<summary>How it works</summary>

Your password is used once to derive an AES-256 key via PBKDF2 (600k iterations). The key is stored in macOS Keychain with biometric protection — Touch ID is required to retrieve it.

**Seal** replaces a file's contents with `#touchfs` + base64-encoded ciphertext (AES-256-GCM with random nonce).

**Mount** creates a FUSE filesystem backed by your sealed files. Files stay encrypted in memory. On `open()`, Touch ID is triggered via LocalAuthentication — only then is the file decrypted into a per-handle buffer. On `close()`, if modified, the file is re-encrypted. The original files are replaced with symlinks during mount and restored on unmount (or crash recovery via xattr).

</details>
