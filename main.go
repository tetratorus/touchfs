package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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
	case "status":
		cmdStatus()
	case "scan":
		cmdScan()
	case "recover":
		cmdRecover()
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
  touchfs seal   [-p] <file>    Encrypt a file in-place
  touchfs unseal [-p] <file>    Decrypt a sealed file back to plaintext
  touchfs mount  [path...]      Mount FUSE for files and/or directories (default: .)
  touchfs set    [--stdin]      Create or update password in Keychain
  touchfs reset                 Delete key from Keychain
  touchfs status                Check key status (JSON, no Touch ID)
  touchfs scan   [path]         Find sealed files in directory (default: ~)
  touchfs recover <file>        Restore a broken symlink from a crashed mount
  touchfs version               Print version

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
		if keychainHas() {
			return nil, fmt.Errorf("Touch ID required to access key")
		}
		return nil, fmt.Errorf("Keychain access failed: %w", err)
	}
	if key == nil {
		if keychainHas() {
			return nil, fmt.Errorf("Touch ID required to access key")
		}
		return nil, fmt.Errorf("no key in Keychain — run 'touchfs set' first")
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
	useStdin := len(os.Args) >= 3 && os.Args[2] == "--stdin"

	var pw, confirm []byte
	var err error

	if useStdin {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Fatal("expected password on stdin")
		}
		pw = []byte(scanner.Text())
		if !scanner.Scan() {
			log.Fatal("expected password confirmation on stdin")
		}
		confirm = []byte(scanner.Text())
	} else {
		pw, err = promptPassword("Password: ")
		if err != nil {
			log.Fatalf("password: %v", err)
		}
		confirm, err = promptPassword("Confirm password: ")
		if err != nil {
			log.Fatalf("password: %v", err)
		}
	}

	if len(pw) == 0 {
		log.Fatal("password cannot be empty")
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

// cmdStatus prints key status as JSON.
func cmdStatus() {
	key, err := keychainLoad()
	hasKey := key != nil || err != nil
	status := struct {
		HasKey  bool   `json:"has_key"`
		Version string `json:"version"`
	}{
		HasKey:  hasKey,
		Version: version,
	}
	json.NewEncoder(os.Stdout).Encode(status)
}

// cmdScan walks a directory tree and prints absolute paths of sealed files.
func cmdScan() {
	var dir string
	if len(os.Args) >= 3 {
		dir = os.Args[2]
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("home dir: %v", err)
		}
		dir = home
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		log.Fatalf("resolve path: %v", err)
	}

	fi, err := os.Stat(absDir)
	if err != nil {
		log.Fatalf("path: %v", err)
	}
	if !fi.IsDir() {
		log.Fatalf("%s is not a directory", absDir)
	}

	sealed, err := scanSealedFiles(absDir)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	for rel := range sealed {
		fmt.Println(filepath.Join(absDir, rel))
	}
}

// cmdRecover restores a broken symlink from a crashed mount.
func cmdRecover() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: touchfs recover <file>\n")
		os.Exit(1)
	}

	path, err := filepath.Abs(os.Args[2])
	if err != nil {
		log.Fatalf("resolve path: %v", err)
	}

	fi, err := os.Lstat(path)
	if err != nil {
		log.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		log.Fatalf("%s is not a symlink", path)
	}

	if err := restoreFromXattr(path); err != nil {
		log.Fatalf("recover: %v", err)
	}
	fmt.Printf("Recovered %s\n", path)
}

// cmdMount mounts sealed files via FUSE. Accepts any mix of files and directories.
// Directories are scanned recursively for sealed files. Individual files are mounted directly.
// Files stay encrypted in memory; decrypted on-demand after Touch ID in Open().
// On close, modified files are re-encrypted and xattr is updated.
func cmdMount() {
	args := os.Args[2:]
	if len(args) == 0 {
		dir, err := os.Getwd()
		if err != nil {
			log.Fatalf("getwd: %v", err)
		}
		args = []string{dir}
	}

	// Classify args into files and directories.
	var dirs []string
	var files []string
	for _, arg := range args {
		abs, err := filepath.Abs(arg)
		if err != nil {
			log.Fatalf("resolve path %s: %v", arg, err)
		}

		// Check for broken symlink from a previous crash.
		fi, statErr := os.Lstat(abs)
		if statErr != nil {
			log.Fatalf("path: %v", statErr)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if err := restoreFromXattr(abs); err != nil {
				log.Fatalf("recover %s: %v", abs, err)
			}
			log.Printf("Recovered %s from previous crash", abs)
			fi, statErr = os.Lstat(abs)
			if statErr != nil {
				log.Fatalf("path: %v", statErr)
			}
		}

		if fi.IsDir() {
			dirs = append(dirs, abs)
		} else {
			files = append(files, abs)
		}
	}

	// Collect sealed files keyed by absolute path.
	sealed := make(map[string]*sealedFileInfo)

	for _, dir := range dirs {
		recoverCrashedFiles(dir)
		scanned, err := scanSealedFiles(dir)
		if err != nil {
			log.Fatalf("scan %s: %v", dir, err)
		}
		for rel, info := range scanned {
			abs := filepath.Join(dir, rel)
			sealed[abs] = info
		}
	}

	for _, f := range files {
		if !isSealedFile(f) {
			log.Fatalf("%s is not a sealed file", f)
		}
		info, err := parseSealedFile(f)
		if err != nil {
			log.Fatalf("parse %s: %v", f, err)
		}
		sealed[f] = info
	}

	if len(sealed) == 0 {
		log.Fatalf("No sealed files found")
	}

	// Get key once (triggers Touch ID via Keychain).
	key, err := getKey()
	if err != nil {
		log.Fatalf("key: %v", err)
	}

	// Build mount point from resolved absolute paths.
	var sortedPaths []string
	for absPath := range sealed {
		sortedPaths = append(sortedPaths, absPath)
	}
	h := sha256.Sum256([]byte(strings.Join(sortedPaths, "\x00")))
	mountpoint := filepath.Join(os.TempDir(), "touchfs", hex.EncodeToString(h[:]))
	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		log.Fatalf("create mountpoint: %v", err)
	}

	// Set up symlinks and build flat FUSE map (hash-keyed).
	fuseMap := make(map[string]*sealedFileInfo)
	var managed []string
	for absPath, info := range sealed {
		info.relPath = absPath
		fh := sha256.Sum256([]byte(absPath))
		fuseKey := hex.EncodeToString(fh[:])
		fuseMap[fuseKey] = info

		link := filepath.Join(mountpoint, fuseKey)

		content, err := os.ReadFile(absPath)
		if err != nil {
			log.Fatalf("read %s: %v", absPath, err)
		}

		os.Remove(absPath)
		if err := os.Symlink(link, absPath); err != nil {
			os.WriteFile(absPath, content, 0600)
			log.Fatalf("symlink %s → %s: %v", absPath, link, err)
		}

		if err := setSymlinkXattr(absPath, content); err != nil {
			os.Remove(absPath)
			os.WriteFile(absPath, content, 0600)
			log.Fatalf("setxattr %s: %v", absPath, err)
		}

		// Store original file mode for cleanup/recovery.
		modeBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(modeBuf, uint32(info.mode))
		if err := unix.Lsetxattr(absPath, "touchfs.mode", modeBuf, 0); err != nil {
			log.Printf("Warning: failed to store mode for %s: %v", absPath, err)
		}

		managed = append(managed, absPath)
	}

	// Build FUSE filesystem with flat hash-keyed map + key.
	secFS := NewSecureEnvFS(fuseMap, key)

	// On dirty close, update xattr so cleanup restores the updated sealed file.
	secFS.onDirty = func(absPath string, sealedContent []byte) {
		if err := setSymlinkXattr(absPath, sealedContent); err != nil {
			log.Printf("Warning: update xattr for %s failed: %v", absPath, err)
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
	log.Printf("Mounting at %s", mountpoint)
	for _, abs := range managed {
		log.Printf("  %s", abs)
	}
	log.Println("Press Ctrl+C to unmount and restore files")

	ok := host.Mount(mountpoint, []string{"-o", "volname=touchfs", "-o", "direct_io"})

	// Cleanup: remove symlinks, restore sealed files from xattr.
	cleanupFiles(managed)

	if !ok && !userUnmount {
		log.Fatal("Mount failed")
	}
}

// defaultSkipDirs are directories skipped when no config file exists.
var defaultSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"__pycache__":  true,
	".cache":       true,
	".next":        true,
	".nuxt":        true,
	"dist":         true,
	"build":        true,
	".tox":         true,
	".venv":        true,
	".terraform":   true,
}

// loadSkipDirs reads ~/.config/touchfs/ignore if it exists, otherwise returns defaults.
// The file contains one directory name per line. Lines starting with # are comments.
func loadSkipDirs() map[string]bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultSkipDirs
	}
	path := filepath.Join(home, ".config", "touchfs", "ignore")
	f, err := os.Open(path)
	if err != nil {
		return defaultSkipDirs
	}
	defer f.Close()

	dirs := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		dirs[line] = true
	}
	if len(dirs) == 0 {
		return defaultSkipDirs
	}
	return dirs
}

// scanSealedFiles recursively finds all sealed files under dir.
// Keys in the returned map are paths relative to dir.
func scanSealedFiles(dir string) (map[string]*sealedFileInfo, error) {
	skip := loadSkipDirs()
	result := make(map[string]*sealedFileInfo)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip inaccessible entries
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
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

// restoreFromXattr replaces a symlink with its sealed content stored in xattr.
func restoreFromXattr(path string) error {
	content, err := getSymlinkXattr(path)
	if err != nil {
		return fmt.Errorf("read xattr: %w", err)
	}

	modeBuf, err := lgetxattr(path, "touchfs.mode")
	mode := os.FileMode(0600)
	if err == nil && len(modeBuf) == 4 {
		mode = os.FileMode(binary.LittleEndian.Uint32(modeBuf))
	}

	os.Remove(path)
	if err := os.WriteFile(path, content, mode); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// cleanupFiles restores sealed files from xattr on symlinks.
func cleanupFiles(paths []string) {
	for _, path := range paths {
		if err := restoreFromXattr(path); err != nil {
			log.Printf("Warning: failed to restore %s: %v", path, err)
		} else {
			log.Printf("Restored %s", path)
		}
	}
}

// recoverCrashedFiles recursively restores broken symlinks left by a crash.
func recoverCrashedFiles(dir string) {
	skip := loadSkipDirs()
	filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() && skip[d.Name()] {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink == 0 {
			return nil
		}
		// Only recover broken symlinks (target missing = crashed state).
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if err := restoreFromXattr(path); err == nil {
			log.Printf("Recovered %s from previous crash", path)
		}
		return nil
	})
}
