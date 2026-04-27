# touchfs

Touch ID-gated encrypted files for macOS.

AI code editors like Cursor, Windsurf, and Claude Code read your filesystem to provide context — including `.env` files, API keys, and credentials. There's no standard way to prevent this across tools. touchfs solves this at the filesystem level: sensitive files are encrypted at rest and only decrypted when you physically confirm via Touch ID. It works with every editor, CLI tool, and CI script without requiring plugins or API changes, because it operates below the application layer.

- **Transparent** — apps follow symlinks into the virtual filesystem. VSCode, `cat`, `grep`, and everything else just work. Nothing knows touchfs exists.
- **Crash-safe** — if the process dies mid-mount, encrypted content is preserved in symlink xattrs. The next mount detects broken symlinks and restores your files automatically.
- **Key never on disk** — the AES-256 key lives only in macOS Keychain (hardware-backed on Apple Silicon) and in process memory while mounted. Your password is used once to derive the key and is never stored.

## Install

### App (recommended)

Download the latest DMG from [Releases](https://github.com/tetratorus/touchfs/releases), open it, and drag TouchFS to Applications.

On first launch, the app installs the encryption engine and filesystem driver (fuse-t) automatically. Set a password, protect your files, done.

### CLI only

```
brew tap tetratorus/tap && brew install --cask touchfs
```

Requires [fuse-t](https://github.com/macos-fuse-t/fuse-t) (`brew install --cask fuse-t`).

## Usage

### App

1. Launch TouchFS — installs dependencies if needed
2. Set a password (one-time, stored in Keychain behind Touch ID)
3. Click **Protect Files** to select files to encrypt
4. Done — files are encrypted on disk, decrypted transparently via Touch ID

Cmd+Q hides the window — the app keeps running in the menu bar, files stay protected. Quit from the menu bar to stop protection and restore files to their encrypted state.

Settings: change password, find existing protected files, install/uninstall CLI tool, update the engine, or reset everything.

### CLI

```
touchfs set                       # Create password (one-time setup)
touchfs seal [-p] <file>          # Encrypt a file in-place
touchfs unseal [-p] <file>        # Decrypt a sealed file
touchfs mount [path...]           # Mount FUSE for files and/or directories (default: .)
touchfs status                    # Check key status (JSON)
touchfs scan [path]               # Find sealed files in directory (default: ~)
touchfs recover <file>            # Restore a broken symlink from a crashed mount
touchfs reset                     # Delete key from Keychain
touchfs version                   # Print version
```

Use `-p` with `seal`/`unseal` to use a password instead of Touch ID.

#### Example

```
$ touchfs seal ~/project/.env   # .env is now ciphertext on disk
$ touchfs mount ~/project       # Touch ID prompt → mounts virtual filesystem
                                # .env becomes a symlink to the mount
...
^C                              # Ctrl+C unmounts and restores .env as ciphertext
```

You can also mount individual files:

```
$ touchfs mount ~/.env ~/keys/api.key ~/project/.env
```

## How it works

Your password is used once to derive an AES-256 key via PBKDF2 (600k iterations, SHA-256). The key is stored in macOS Keychain with biometric protection — Touch ID is required to retrieve it. The password is never stored.

**Seal** replaces a file's contents with `#touchfs` + base64-encoded ciphertext (AES-256-GCM with random nonce). The file stays in place — same path, same name, just encrypted. Files larger than 100 MB are rejected.

**Mount** scans for sealed files and creates a [FUSE](https://github.com/macos-fuse-t/fuse-t) virtual filesystem at `/tmp/touchfs/`. Each sealed file is replaced with a symlink pointing to the mount, and its encrypted contents are stored in the symlink's extended attributes (xattrs). When an app opens a file, Touch ID is prompted (with a 500ms cooldown), the content is decrypted in memory, and on close, modified files are re-encrypted and the xattr is updated. Unmounting restores the original sealed files.

## Ignore list

When scanning directories, touchfs skips these by default:

```
.git  node_modules  vendor  __pycache__  .cache  .next  .nuxt  dist  build  .tox  .venv  .terraform
```

Customize with `~/.config/touchfs/ignore` (one directory name per line). If the file exists, it replaces the defaults entirely.

## Build from source

```
# CLI
make build

# App
cd app && xcodegen generate && xcodebuild -project TouchFS.xcodeproj -scheme TouchFS build

# Release (CLI + App, signed + notarized)
./release.sh v1.0.0
```
