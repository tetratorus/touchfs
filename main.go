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
	case "version", "-v":
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
  touchfs mount  [path]        Mount FUSE, serve decrypted files recursively
  touchfs set                  Create or update password in Keychain
  touchfs reset                Delete key from Keychain
  touchfs version              Print version

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

	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		log.Fatalf("Symlink detected: seal/unseal cannot work on mounted files. Unmount first (Ctrl+C the running mount), then try again.")
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

	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		log.Fatalf("Symlink detected: seal/unseal cannot work on mounted files. Unmount first (Ctrl+C the running mount), then try again.")
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

// cmdMount scans a directory tree for sealed files and mounts FUSE.
// Files stay encrypted in memory; decrypted on-demand after Touch ID in Open().
// On close, modified files are re-encrypted and xattr is updated.
func cmdMount() {
	var rootDir string
	if len(os.Args) >= 3 {
		rootDir = os.Args[2]
	} else {
		dir, err := os.Getwd()
		if err != nil {
			log.Fatalf("getwd: %v", err)
		}
		rootDir = dir
	}

	absDir, err := filepath.Abs(rootDir)
	if err != nil {
		log.Fatalf("resolve path: %v", err)
	}
	rootDir = absDir

	fi, err := os.Stat(rootDir)
	if err != nil {
		log.Fatalf("path: %v", err)
	}
	if !fi.IsDir() {
		log.Fatalf("%s is not a directory", rootDir)
	}

	// Crash recovery: restore any broken symlinks from a previous crashed run.
	recoverCrashedFiles(rootDir)

	// Scan for sealed files recursively.
	sealed, err := scanSealedFiles(rootDir)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	if len(sealed) == 0 {
		log.Fatalf("No sealed files found in %s", rootDir)
	}

	// Get key once (triggers Touch ID via Keychain).
	key, err := getKey()
	if err != nil {
		log.Fatalf("key: %v", err)
	}

	// Build mount point: /tmp/touchfs/<sha256(rootDir)>/
	h := sha256.Sum256([]byte(rootDir))
	mountpoint := filepath.Join(os.TempDir(), "touchfs", hex.EncodeToString(h[:]))
	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		log.Fatalf("create mountpoint: %v", err)
	}

	// Set up symlinks and build flat FUSE map (hash-keyed).
	fuseMap := make(map[string]*sealedFileInfo)
	var managed []string
	for rel, info := range sealed {
		info.relPath = rel
		fh := sha256.Sum256([]byte(rel))
		fuseKey := hex.EncodeToString(fh[:])
		fuseMap[fuseKey] = info

		orig := filepath.Join(rootDir, rel)
		link := filepath.Join(mountpoint, fuseKey)

		content, err := os.ReadFile(orig)
		if err != nil {
			log.Fatalf("read %s: %v", rel, err)
		}

		os.Remove(orig)
		if err := os.Symlink(link, orig); err != nil {
			os.WriteFile(orig, content, 0600)
			log.Fatalf("symlink %s → %s: %v", orig, link, err)
		}

		if err := setSymlinkXattr(orig, content); err != nil {
			os.Remove(orig)
			os.WriteFile(orig, content, 0600)
			log.Fatalf("setxattr %s: %v", rel, err)
		}
		managed = append(managed, rel)
	}

	// Build FUSE filesystem with flat hash-keyed map + key.
	secFS := NewSecureEnvFS(fuseMap, key)

	// On dirty close, update xattr so cleanup restores the updated sealed file.
	secFS.onDirty = func(relPath string, sealedContent []byte) {
		orig := filepath.Join(rootDir, relPath)
		if err := setSymlinkXattr(orig, sealedContent); err != nil {
			log.Printf("Warning: update xattr for %s failed: %v", relPath, err)
		}
	}

	host := fuse.NewFileSystemHost(secFS)

	// Clean shutdown on signal.
	var userUnmount bool
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		userUnmount = true
		log.Println("Shutting down...")
		host.Unmount()
	}()

	log.Printf("touchfs %s", version)
	log.Printf("Root: %s", rootDir)
	log.Printf("Mounting at %s", mountpoint)
	for _, rel := range managed {
		log.Printf("  %s", rel)
	}
	log.Println("Press Ctrl+C to unmount and restore files")

	ok := host.Mount(mountpoint, []string{"-o", "volname=touchfs", "-o", "direct_io"})

	// Cleanup: remove symlinks, restore sealed files from xattr.
	cleanup(rootDir, managed)

	if !ok && !userUnmount {
		log.Fatal("Mount failed")
	}
}

// scanSealedFiles recursively finds all sealed files under dir.
// Keys in the returned map are paths relative to dir.
func scanSealedFiles(dir string) (map[string]*sealedFileInfo, error) {
	result := make(map[string]*sealedFileInfo)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip inaccessible entries
		}
		if d.IsDir() {
			return nil
		}
		// Skip symlinks (e.g. leftover from previous mount).
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !isSealedFile(path) {
			return nil
		}
		info, err := parseSealedFile(path)
		if err != nil {
			log.Printf("Warning: skipping %s: %v", path, err)
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		result[rel] = info
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk dir: %w", err)
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

// recoverCrashedFiles recursively restores files from xattr on broken symlinks left by a crash.
func recoverCrashedFiles(dir string) {
	filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		// Only look at symlinks.
		if d.Type()&os.ModeSymlink == 0 {
			return nil
		}

		// Check if symlink target is missing (crashed state).
		if _, err := os.Stat(path); err == nil {
			return nil // target exists, not crashed
		}

		content, err := getSymlinkXattr(path)
		if err != nil {
			return nil
		}

		os.Remove(path)
		if err := os.WriteFile(path, content, 0600); err != nil {
			log.Printf("Warning: crash recovery failed for %s: %v", path, err)
		} else {
			log.Printf("Recovered %s from previous crash", path)
		}
		return nil
	})
}
