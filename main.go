package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/winfsp/cgofuse/fuse"
)

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
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `touchfs — Touch ID-gated encrypted files

Usage:
  touchfs seal   <file>   Encrypt a file in-place
  touchfs mount            Mount FUSE, serve decrypted files from cwd
  touchfs unseal <file>   Decrypt a sealed file back to plaintext
`)
	os.Exit(1)
}

// cmdSeal encrypts a file in-place.
func cmdSeal() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: touchfs seal <file>\n")
		os.Exit(1)
	}
	path := os.Args[2]

	if err := sealFile(path); err != nil {
		log.Fatalf("seal: %v", err)
	}
	abs, _ := filepath.Abs(path)
	fmt.Printf("Sealed %s\n", abs)
	fmt.Printf("Key stored in ~/.config/touchfs/keys/\n")
}

// cmdUnseal decrypts a sealed file after Touch ID.
func cmdUnseal() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: touchfs unseal <file>\n")
		os.Exit(1)
	}
	path := os.Args[2]

	if !isSealedFile(path) {
		log.Fatalf("%s is not a sealed file", path)
	}

	ok, err := authenticateTouchID("touchfs: unseal "+filepath.Base(path), authTTL)
	if err != nil {
		log.Fatalf("Touch ID error: %v", err)
	}
	if !ok {
		log.Fatal("Touch ID denied")
	}

	if err := unsealFile(path); err != nil {
		log.Fatalf("unseal: %v", err)
	}
	fmt.Printf("Unsealed %s\n", path)
}

// cmdMount scans cwd for sealed files, sets up symlinks, and mounts FUSE.
func cmdMount() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("getwd: %v", err)
	}

	// Crash recovery: restore any .touchfs backups from a previous crashed run.
	recoverCrashedFiles(cwd)

	// Scan for sealed files in cwd.
	sealed, err := scanSealedFiles(cwd)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	if len(sealed) == 0 {
		log.Fatal("No sealed files found in current directory")
	}

	// Build mount point: /tmp/touchfs/<sha256(cwd)>/
	h := sha256.Sum256([]byte(cwd))
	mountpoint := filepath.Join(os.TempDir(), "touchfs", hex.EncodeToString(h[:]))
	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		log.Fatalf("create mountpoint: %v", err)
	}

	// Set up symlinks: rename originals to .touchfs, symlink to mount point.
	var managed []string
	for name := range sealed {
		orig := filepath.Join(cwd, name)
		backup := orig + ".touchfs"
		link := filepath.Join(mountpoint, name)

		if err := os.Rename(orig, backup); err != nil {
			log.Fatalf("rename %s → %s: %v", orig, backup, err)
		}

		// Remove any stale symlink/file at original path before creating.
		os.Remove(orig)
		if err := os.Symlink(link, orig); err != nil {
			// Restore on failure.
			os.Rename(backup, orig)
			log.Fatalf("symlink %s → %s: %v", orig, link, err)
		}
		managed = append(managed, name)
	}

	// Build FUSE filesystem.
	fsFiles := make(map[string]*sealedFileInfo)
	for name, info := range sealed {
		fsFiles[name] = info
	}
	secFS := NewSecureEnvFS(fsFiles)
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
		log.Printf("  %s → %s/%s (Touch ID gated)", name, mountpoint, name)
	}
	log.Println("Press Ctrl+C to unmount and restore files")

	ok := host.Mount(mountpoint, []string{"-o", "ro", "-o", "volname=touchfs"})

	// Cleanup: remove symlinks, restore backups.
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
		id, encrypted, err := parseSealedFile(path)
		if err != nil {
			log.Printf("Warning: skipping %s: %v", e.Name(), err)
			continue
		}
		result[e.Name()] = &sealedFileInfo{
			name:      e.Name(),
			keyID:     id,
			encrypted: encrypted,
		}
	}
	return result, nil
}

// cleanup removes symlinks and restores .touchfs backups.
func cleanup(cwd string, names []string) {
	for _, name := range names {
		orig := filepath.Join(cwd, name)
		backup := orig + ".touchfs"

		// Remove symlink.
		os.Remove(orig)

		// Restore backup.
		if _, err := os.Stat(backup); err == nil {
			if err := os.Rename(backup, orig); err != nil {
				log.Printf("Warning: failed to restore %s: %v", name, err)
			} else {
				log.Printf("Restored %s", name)
			}
		}
	}
}

// recoverCrashedFiles restores .touchfs backups left by a previous crashed run.
func recoverCrashedFiles(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".touchfs") {
			continue
		}
		origName := strings.TrimSuffix(e.Name(), ".touchfs")
		origPath := filepath.Join(dir, origName)
		backupPath := filepath.Join(dir, e.Name())

		// Check if original is a broken symlink.
		_, statErr := os.Stat(origPath)
		_, lstatErr := os.Lstat(origPath)

		if lstatErr == nil && statErr != nil {
			// Lstat succeeds (symlink exists) but Stat fails (target missing) → broken symlink.
			os.Remove(origPath)
			if err := os.Rename(backupPath, origPath); err != nil {
				log.Printf("Warning: crash recovery failed for %s: %v", origName, err)
			} else {
				log.Printf("Recovered %s from previous crash", origName)
			}
		} else if os.IsNotExist(lstatErr) {
			// Original doesn't exist at all — just restore.
			if err := os.Rename(backupPath, origPath); err != nil {
				log.Printf("Warning: crash recovery failed for %s: %v", origName, err)
			} else {
				log.Printf("Recovered %s from previous crash", origName)
			}
		}
	}
}
