# touchfs

Touch ID-gated encrypted files. Seal sensitive files (`.env`, credentials, configs) in-place — they become ciphertext with a magic header. Mount a FUSE filesystem that serves them decrypted, gated by Touch ID on every access.

The encrypted file keeps its original name, so `.gitignore` still works. If accidentally committed, it's just ciphertext.

## Install

```bash
brew tap tetratorus/tap
brew install --cask touchfs
```

Requires [FUSE-T](https://www.fuse-t.org/): `brew install --cask fuse-t`

## Usage

### First time setup

```bash
touchfs seal .env
```

On first run, you'll create a password. The password is used once to derive an AES-256 key via PBKDF2, then the key is stored in macOS Keychain with Touch ID protection. You'll never need the password again.

### Seal a file

```bash
touchfs seal .env
```

Encrypts `.env` in-place with AES-256-GCM. The file now looks like:

```
#touchfs
iy522PKvoz9Whp9xAmmnFtQz5RJw8a+7G8LTTb19...
```

### Mount (serve decrypted files via FUSE)

```bash
cd ~/my-project
touchfs mount
```

This:
1. Scans the current directory for sealed files
2. Retrieves the AES key from Keychain (Touch ID)
3. Replaces each sealed file with a symlink to a FUSE mount
4. Every file open triggers Touch ID via LAContext
5. Files are decrypted on open, re-encrypted on close
6. Writes are supported — edits are re-encrypted when the file is closed
7. Ctrl+C unmounts and restores the encrypted files

### Unseal (permanently decrypt)

```bash
touchfs unseal .env
```

Touch ID retrieves key from Keychain, then decrypts the file back to plaintext.

### Password fallback

Use `-p` to seal/unseal with a password instead of Touch ID:

```bash
touchfs seal -p .env
touchfs unseal -p .env
```

### Reset

Delete the key from Keychain:

```bash
touchfs reset
```

### Crash recovery

If a previous `touchfs mount` was killed without cleanup (e.g. `kill -9`), the next `touchfs mount` automatically detects orphaned symlinks and restores the sealed files from xattr.

## How it works

- **Encryption**: AES-256-GCM via Go stdlib
- **Key derivation**: PBKDF2-SHA256 (600k iterations) — only runs once at setup
- **Key storage**: macOS Keychain with `kSecAccessControlBiometryAny` — Touch ID required to retrieve
- **FUSE**: Read-write filesystem via [cgofuse](https://github.com/winfsp/cgofuse) + [FUSE-T](https://www.fuse-t.org/)
- **Per-access Touch ID**: LAContext biometric check on every file open
- **Backup**: Sealed file content stored as xattr on symlinks during mount (no `.touchfs` temp files)
- **Codesigning**: .app bundle with Developer ID + provisioning profile for Keychain biometric entitlement

## Build from source

```bash
make build    # Development (Apple Development cert)
make dist     # Distribution (Developer ID cert + notarization-ready)
```
