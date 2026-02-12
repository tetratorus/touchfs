package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/winfsp/cgofuse/fuse"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

var version = "dev"

const xattrChunkSize = 63 * 1024 // 63 KB per chunk (APFS safe)

// setSymlinkXattr stores data across one or more xattrs on a symlink.
func setSymlinkXattr(path string, data []byte) error {
	chunks := 0
	for off := 0; off < len(data); off += xattrChunkSize {
		end := off + xattrChunkSize
		if end > len(data) {
			end = len(data)
		}
		attr := "touchfs.sealed." + strconv.Itoa(chunks)
		if err := unix.Lsetxattr(path, attr, data[off:end], 0); err != nil {
			return fmt.Errorf("lsetxattr %s: %w", attr, err)
		}
		chunks++
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(chunks))
	if err := unix.Lsetxattr(path, "touchfs.sealed.len", buf, 0); err != nil {
		return fmt.Errorf("lsetxattr len: %w", err)
	}
	return nil
}

// getSymlinkXattr reads data stored across xattrs on a symlink.
func getSymlinkXattr(path string) ([]byte, error) {
	lenBuf, err := lgetxattr(path, "touchfs.sealed.len")
	if err != nil {
		return nil, err
	}
	chunks := int(binary.LittleEndian.Uint32(lenBuf))

	var data []byte
	for i := 0; i < chunks; i++ {
		attr := "touchfs.sealed." + strconv.Itoa(i)
		chunk, err := lgetxattr(path, attr)
		if err != nil {
			return nil, fmt.Errorf("lgetxattr %s: %w", attr, err)
		}
		data = append(data, chunk...)
	}
	return data, nil
}

// lgetxattr is a helper that handles the two-call pattern for Lgetxattr.
func lgetxattr(path, attr string) ([]byte, error) {
	sz, err := unix.Lgetxattr(path, attr, nil)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, sz)
	_, err = unix.Lgetxattr(path, attr, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "seal":
		cmdSeal()
	case "mount":
		cmdMount()
	case "unseal":
		cmdUnseal()
	case "set":
		cmdSet()
	case "reset":
		cmdReset()
	case "version":
		fmt.Println(version)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `touchfs — Touch ID-gated encrypted files

On first run, you'll create a password. It's used once to derive an AES-256
key, which is stored in macOS Keychain (Touch ID protected). After setup,
Touch ID is all you need.

Usage:
  touchfs seal   [-p] <file>   Encrypt a file in-place
  touchfs unseal [-p] <file>   Decrypt a sealed file back to plaintext
  touchfs mount                Mount FUSE, serve decrypted files from cwd
  touchfs set                  Create or update password in Keychain
  touchfs reset                Delete key from Keychain

Options:
  -p    Use password instead of Touch ID/Keychain
`)
	os.Exit(1)
}

// promptPassword reads a password from the terminal with no echo.
func promptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	return pw, nil
}

// ensureKey returns the AES key. If no key exists in Keychain, prompts for a
// password, derives the key via PBKDF2 (once), and stores the key in Keychain.
func ensureKey() ([]byte, error) {
	key, err := keychainLoad()
	if err != nil {
		log.Printf("Keychain access failed: %v", err)
		if keychainHas() {
			// Key exists but Touch ID was denied — no fallback.
			return nil, fmt.Errorf("Touch ID required to access key")
		}
	}
	if key != nil {
		return key, nil
	}

	// No key in Keychain — create one from a password.
	pw, err := promptPassword("Create password: ")
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	confirm, err := promptPassword("Confirm password: ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pw, confirm) {
		return nil, fmt.Errorf("passwords do not match")
	}

	// Derive key once, store it. Password is never stored.
	key = deriveKey(pw)

	if err := keychainStore(key); err != nil {
		return nil, fmt.Errorf("failed to store key in Keychain: %w", err)
	}
	log.Println("Key stored in Keychain (Touch ID protected)")
	return key, nil
}

// getKey retrieves the AES key from Keychain (triggers Touch ID).
func getKey() ([]byte, error) {
	key, err := keychainLoad()
	if err != nil {
		return nil, fmt.Errorf("Keychain access failed: %w", err)
	}
	if key == nil {
		return nil, fmt.Errorf("no key in Keychain — run 'touchfs seal' first to set up")
	}
	return key, nil
}

// cmdSeal encrypts a file in-place.
func cmdSeal() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: touchfs seal [-p] <file>\n")
		os.Exit(1)
	}

	usePassword := os.Args[2] == "-p"
	path := os.Args[2]
	if usePassword {
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: touchfs seal [-p] <file>\n")
			os.Exit(1)
		}
		path = os.Args[3]
	}

	var key []byte
	var err error
	if usePassword {
		pw, err := promptPassword("Password: ")
		if err != nil {
			log.Fatalf("password: %v", err)
		}
		key = deriveKey(pw)
	} else {
		key, err = ensureKey()
		if err != nil {
			log.Fatalf("key: %v", err)
		}
	}

	if err := sealFile(path, key); err != nil {
		log.Fatalf("seal: %v", err)
	}
	abs, _ := filepath.Abs(path)
	fmt.Printf("Sealed %s\n", abs)
}

// cmdUnseal decrypts a sealed file.
func cmdUnseal() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: touchfs unseal [-p] <file>\n")
		os.Exit(1)
	}

	usePassword := os.Args[2] == "-p"
	path := os.Args[2]
	if usePassword {
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: touchfs unseal [-p] <file>\n")
			os.Exit(1)
		}
		path = os.Args[3]
	}

	if !isSealedFile(path) {
		log.Fatalf("%s is not a sealed file", path)
	}

	var key []byte
	var err error
	if usePassword {
		pw, err := promptPassword("Password: ")
		if err != nil {
			log.Fatalf("password: %v", err)
		}
		key = deriveKey(pw)
	} else {
		key, err = getKey()
		if err != nil {
			log.Fatalf("key: %v", err)
		}
	}

	if err := unsealFile(path, key); err != nil {
		log.Fatalf("unseal: %v", err)
	}
	fmt.Printf("Unsealed %s\n", path)
}

// cmdSet creates or updates the password-derived key in the Keychain.
func cmdSet() {
	pw, err := promptPassword("Password: ")
	if err != nil {
		log.Fatalf("password: %v", err)
	}
	if len(pw) == 0 {
		log.Fatal("password cannot be empty")
	}

	confirm, err := promptPassword("Confirm password: ")
	if err != nil {
		log.Fatalf("password: %v", err)
	}
	if !bytes.Equal(pw, confirm) {
		log.Fatal("passwords do not match")
	}

	key := deriveKey(pw)
	if err := keychainStore(key); err != nil {
		log.Fatalf("keychain: %v", err)
	}
	fmt.Println("Key stored in Keychain (Touch ID protected)")
}

// cmdReset deletes the key from the Keychain.
func cmdReset() {
	if err := keychainDelete(); err != nil {
		log.Fatalf("reset: %v", err)
	}
	fmt.Println("Key deleted from Keychain")
}

// cmdMount scans cwd for sealed files and mounts FUSE.
// Files stay encrypted in memory; decrypted on-demand after Touch ID in Open().
// On close, modified files are re-encrypted and xattr is updated.
func cmdMount() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("getwd: %v", err)
	}

	// Crash recovery: restore any broken symlinks from a previous crashed run.
	recoverCrashedFiles(cwd)

	// Scan for sealed files in cwd.
	sealed, err := scanSealedFiles(cwd)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	if len(sealed) == 0 {
		log.Fatal("No sealed files found in current directory")
	}

	// Get key once (triggers Touch ID via Keychain).
	key, err := getKey()
	if err != nil {
		log.Fatalf("key: %v", err)
	}

	// Build mount point: /tmp/touchfs/<sha256(cwd)>/
	h := sha256.Sum256([]byte(cwd))
	mountpoint := filepath.Join(os.TempDir(), "touchfs", hex.EncodeToString(h[:]))
	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		log.Fatalf("create mountpoint: %v", err)
	}

	// Set up symlinks: store sealed content as xattr, replace with symlink.
	var managed []string
	for name := range sealed {
		orig := filepath.Join(cwd, name)
		link := filepath.Join(mountpoint, name)

		content, err := os.ReadFile(orig)
		if err != nil {
			log.Fatalf("read %s: %v", name, err)
		}

		os.Remove(orig)
		if err := os.Symlink(link, orig); err != nil {
			os.WriteFile(orig, content, 0600)
			log.Fatalf("symlink %s → %s: %v", orig, link, err)
		}

		if err := setSymlinkXattr(orig, content); err != nil {
			os.Remove(orig)
			os.WriteFile(orig, content, 0600)
			log.Fatalf("setxattr %s: %v", name, err)
		}
		managed = append(managed, name)
	}

	// Build FUSE filesystem with encrypted content + key.
	secFS := NewSecureEnvFS(sealed, key)

	// On dirty close, update xattr so cleanup restores the updated sealed file.
	secFS.onDirty = func(name string, sealedContent []byte) {
		orig := filepath.Join(cwd, name)
		if err := setSymlinkXattr(orig, sealedContent); err != nil {
			log.Printf("Warning: update xattr for %s failed: %v", name, err)
		}
	}

	host := fuse.NewFileSystemHost(secFS)

	// Clean shutdown on signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		host.Unmount()
	}()

	log.Printf("Mounting touchfs at %s", mountpoint)
	for _, name := range managed {
		log.Printf("  %s → %s/%s", name, mountpoint, name)
	}
	log.Println("Press Ctrl+C to unmount and restore files")

	ok := host.Mount(mountpoint, []string{"-o", "volname=touchfs", "-o", "direct_io"})

	// Cleanup: remove symlinks, restore sealed files from xattr.
	cleanup(cwd, managed)

	if !ok {
		log.Fatal("Mount failed")
	}
}

// scanSealedFiles finds all sealed files in the given directory.
func scanSealedFiles(dir string) (map[string]*sealedFileInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}

	result := make(map[string]*sealedFileInfo)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if !isSealedFile(path) {
			continue
		}
		info, err := parseSealedFile(path)
		if err != nil {
			log.Printf("Warning: skipping %s: %v", e.Name(), err)
			continue
		}
		result[e.Name()] = info
	}
	return result, nil
}

// cleanup restores sealed files from xattr on symlinks.
func cleanup(cwd string, names []string) {
	for _, name := range names {
		orig := filepath.Join(cwd, name)

		content, err := getSymlinkXattr(orig)
		if err != nil {
			log.Printf("Warning: could not read xattr for %s: %v", name, err)
			continue
		}

		os.Remove(orig)
		if err := os.WriteFile(orig, content, 0600); err != nil {
			log.Printf("Warning: failed to restore %s: %v", name, err)
		} else {
			log.Printf("Restored %s", name)
		}
	}
}

// recoverCrashedFiles restores files from xattr on broken symlinks left by a crash.
func recoverCrashedFiles(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		origPath := filepath.Join(dir, e.Name())

		_, statErr := os.Stat(origPath)
		fi, lstatErr := os.Lstat(origPath)
		if lstatErr != nil || statErr == nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			continue
		}

		content, err := getSymlinkXattr(origPath)
		if err != nil {
			continue
		}

		os.Remove(origPath)
		if err := os.WriteFile(origPath, content, 0600); err != nil {
			log.Printf("Warning: crash recovery failed for %s: %v", e.Name(), err)
		} else {
			log.Printf("Recovered %s from previous crash", e.Name())
		}
	}
}
