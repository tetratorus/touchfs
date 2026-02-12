# touchfs

Touch ID-gated encrypted files. Seal sensitive files (`.env`, credentials, configs) in-place — they become ciphertext with a magic header. Mount a FUSE filesystem that serves them decrypted, gated by Touch ID.

The encrypted file keeps its original name, so `.gitignore` still works. If accidentally committed, it's just ciphertext.

## Requirements

- macOS with Touch ID
- [FUSE-T](https://www.fuse-t.org/) (`brew install --cask macfuse`)

## Build

```bash
go build -o touchfs .
```

## Usage

### Seal a file

```bash
touchfs seal .env
```

Encrypts `.env` in-place with AES-256-GCM. The file now looks like:

```
#touchfs:v1:a3f8...key-id
iy522PKvoz9Whp9xAmmnFtQz5RJw8a+7G8LTTb19...
```

A 32-byte encryption key is stored at `~/.config/touchfs/keys/<key-id>.key`.

### Mount (serve decrypted files via FUSE)

```bash
cd ~/my-project
touchfs mount
```

This:
1. Scans the current directory for sealed files
2. Renames each `<file>` to `<file>.touchfs` (backup)
3. Mounts a read-only FUSE filesystem at `/tmp/touchfs/<hash>/`
4. Symlinks `<file>` to the FUSE mount point
5. First `cat <file>` triggers Touch ID (5-second cache)
6. Ctrl+C unmounts and restores the encrypted files

### Unseal (permanently decrypt)

```bash
touchfs unseal .env
```

Touch ID prompt, then decrypts the file back to plaintext.

### Crash recovery

If a previous `touchfs mount` was killed without cleanup (e.g. `kill -9`), the next `touchfs mount` automatically detects orphaned `.touchfs` backups and restores them before proceeding.

## How it works

- **Encryption**: AES-256-GCM via Go stdlib (`crypto/aes` + `crypto/cipher`)
- **Key storage**: `~/.config/touchfs/keys/` — one 32-byte key file per sealed file, mode 0600
- **Key ID**: SHA-256 of the file's absolute path at seal time
- **FUSE**: Read-only filesystem via [cgofuse](https://github.com/winfsp/cgofuse) + FUSE-T
- **Touch ID**: Native macOS LocalAuthentication framework via cgo

## TODO

- **Auto-mount on login**: Register a LaunchAgent so sealed files are served automatically on startup — no need to run `touchfs mount` manually every time
- **Homebrew formula**: `brew tap lentan/touchfs && brew install touchfs` for easy distribution
