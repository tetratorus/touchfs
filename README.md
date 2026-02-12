# touchfs

Touch ID-gated encrypted files for macOS.

Seal sensitive files (`.env`, credentials, configs) in-place — they become ciphertext. Mount a virtual filesystem to serve them decrypted, with Touch ID on every access.

## Install

```
brew tap tetratorus/tap && brew install --cask touchfs
```

## Usage

```
touchfs set              # Create password (one time setup)
touchfs seal <file>      # Encrypt a file in-place
touchfs unseal <file>    # Decrypt a sealed file
touchfs mount            # Mount FUSE, serve decrypted files from cwd
touchfs reset            # Delete key from Keychain
```

Use `-p` with `seal`/`unseal` to use a password instead of Touch ID.

## Build from source

```
make build
```

<details>
<summary>How it works</summary>

Your password is used once to derive an AES-256 key via PBKDF2 (600k iterations). The key is stored in macOS Keychain with biometric protection — Touch ID is required to retrieve it. The password is never stored.

**Seal** replaces a file's contents with `#touchfs` + base64-encoded ciphertext (AES-256-GCM with random nonce).

**Mount** creates a virtual filesystem (via [FUSE](https://github.com/macos-fuse-t/fuse-t) — lets a program pretend to be a disk). Each sealed file becomes a symlink pointing to this virtual filesystem, with its encrypted contents stored in the symlink's extended attributes (xattrs) — no extra files created. Every time a program opens a file, Touch ID is triggered. Only after authentication is the file decrypted into memory. When the file is closed, any changes are re-encrypted and saved back.

**Transparent to apps** — VSCode, `cat`, `grep`, etc. just follow the symlink. They don't know touchfs exists.

**Crash recovery** — if the process dies mid-mount, broken symlinks are left behind. On next `touchfs mount`, it detects them, reads the encrypted content from xattrs, and restores the sealed files automatically.

**Key never on disk** — the AES key lives only in macOS Keychain (hardware-backed on Apple Silicon) and in process memory during mount.

</details>
