# touchfs

Touch ID-gated encrypted files for macOS.

AI code editors like Cursor, Windsurf, and Claude Code read your filesystem to provide context — including `.env` files, API keys, and credentials. There's no standard way to prevent this across tools. touchfs solves this at the filesystem level: sensitive files are encrypted at rest and only decrypted when you physically confirm via Touch ID. It works with every editor, CLI tool, and CI script without requiring plugins or API changes, because it operates below the application layer.

Seal files in-place — they become ciphertext on disk. When you need to work with them, mount a virtual filesystem that serves them decrypted, with each file access gated by Touch ID.

- **Transparent** — apps follow symlinks into the virtual filesystem. VSCode, `cat`, `grep`, and everything else just work. Nothing knows touchfs exists.
- **Crash-safe** — if the process dies mid-mount, encrypted content is preserved in symlink xattrs. The next `touchfs mount` detects broken symlinks and restores your files automatically.
- **Key never on disk** — the AES-256 key lives only in macOS Keychain (hardware-backed on Apple Silicon) and in process memory while mounted. Your password is used once to derive the key and is never stored.

## Install

```
brew tap tetratorus/tap && brew install --cask touchfs
```

## Usage

```
touchfs set              # Create password (one time setup)
touchfs seal <file>      # Encrypt a file in-place
touchfs unseal <file>    # Decrypt a sealed file
touchfs mount            # Mount FUSE, serve decrypted files from current working directory
touchfs reset            # Delete key from Keychain
touchfs version          # Print version
```

Use `-p` with `seal`/`unseal` to use a password instead of Touch ID.

### Example

```
$ cd ~/project
$ touchfs seal .env            # .env is now ciphertext on disk
$ touchfs mount                # Touch ID prompt → mounts virtual filesystem
                               # .env becomes a symlink to the mount
                               # apps read/write .env as normal, gated by Touch ID
# work as usual — editors, scripts, etc. all see the decrypted .env
^C                             # Ctrl+C unmounts and restores .env as ciphertext
```

While mounted, `touchfs` runs in the foreground. Sealed files become symlinks that apps follow transparently. When you're done, Ctrl+C unmounts, restores the encrypted files, and wipes the key from memory.

## How it actually works

Your password is used once to derive an AES-256 key via PBKDF2 (600k iterations, SHA-256). The key is stored in macOS Keychain with biometric protection — Touch ID is required to retrieve it. The password is never stored.

**Seal** replaces a file's contents with `#touchfs` + base64-encoded ciphertext (AES-256-GCM with random nonce). The file stays in place — same path, same name, just encrypted.

**Mount** scans the current directory for sealed files and creates a [FUSE](https://github.com/macos-fuse-t/fuse-t) virtual filesystem at `/tmp/touchfs/`. Each sealed file is replaced with a symlink pointing to the mount, and its encrypted contents are stored in the symlink's extended attributes (xattrs) — no extra files created. When an app opens a file, Touch ID is prompted (with a short cooldown to prevent repeated prompts), the content is decrypted in memory, and on close, modified files are re-encrypted and the xattr is updated. Unmounting restores the original sealed files and wipes the key from memory.

## Build from source

```
make build
```
