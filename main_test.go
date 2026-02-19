package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestScanSealedFilesRecursive(t *testing.T) {
	dir := t.TempDir()
	key := deriveKey([]byte("test-password"))

	// Create nested sealed files.
	paths := []string{
		"top.env",
		"sub/nested.env",
		"sub/deep/secret.env",
	}
	for _, rel := range paths {
		abs := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(abs), 0755)
		if err := os.WriteFile(abs, []byte("data-"+rel), 0644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
		if err := sealFile(abs, key); err != nil {
			t.Fatalf("seal %s: %v", rel, err)
		}
	}

	result, err := scanSealedFiles(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result) != len(paths) {
		t.Fatalf("expected %d sealed files, got %d", len(paths), len(result))
	}

	for _, rel := range paths {
		if _, ok := result[rel]; !ok {
			t.Fatalf("missing sealed file: %s", rel)
		}
	}
}

func TestScanSkipsNonSealed(t *testing.T) {
	dir := t.TempDir()
	key := deriveKey([]byte("test-password"))

	// One sealed, one plain.
	sealed := filepath.Join(dir, "sealed.env")
	os.WriteFile(sealed, []byte("secret"), 0644)
	sealFile(sealed, key)

	plain := filepath.Join(dir, "plain.txt")
	os.WriteFile(plain, []byte("not sealed"), 0644)

	result, err := scanSealedFiles(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 sealed file, got %d", len(result))
	}
	if _, ok := result["sealed.env"]; !ok {
		t.Fatal("missing sealed.env")
	}
}

func TestScanSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	key := deriveKey([]byte("test-password"))

	// Create a sealed file.
	sealed := filepath.Join(dir, "real.env")
	os.WriteFile(sealed, []byte("data"), 0644)
	sealFile(sealed, key)

	// Create a symlink to it.
	link := filepath.Join(dir, "link.env")
	os.Symlink(sealed, link)

	result, err := scanSealedFiles(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 sealed file (symlink skipped), got %d", len(result))
	}
	if _, ok := result["real.env"]; !ok {
		t.Fatal("missing real.env")
	}
}

func TestScanSkipsIgnoredDirs(t *testing.T) {
	dir := t.TempDir()
	key := deriveKey([]byte("test-password"))

	// Sealed file in .git (should be skipped).
	gitDir := filepath.Join(dir, ".git")
	os.MkdirAll(gitDir, 0755)
	gitFile := filepath.Join(gitDir, "secret.env")
	os.WriteFile(gitFile, []byte("data"), 0644)
	sealFile(gitFile, key)

	// Sealed file in node_modules (should be skipped).
	nmDir := filepath.Join(dir, "node_modules")
	os.MkdirAll(nmDir, 0755)
	nmFile := filepath.Join(nmDir, "secret.env")
	os.WriteFile(nmFile, []byte("data"), 0644)
	sealFile(nmFile, key)

	// Sealed file at root (should be found).
	rootFile := filepath.Join(dir, "found.env")
	os.WriteFile(rootFile, []byte("data"), 0644)
	sealFile(rootFile, key)

	result, err := scanSealedFiles(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 sealed file (ignored dirs skipped), got %d", len(result))
	}
	if _, ok := result["found.env"]; !ok {
		t.Fatal("missing found.env")
	}
}

func TestXattrRoundtrip(t *testing.T) {
	dir := t.TempDir()

	// Create a symlink to set xattrs on.
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("x"), 0644)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)

	data := []byte("sealed-content-here")
	if err := setSymlinkXattr(link, data); err != nil {
		t.Fatalf("setSymlinkXattr: %v", err)
	}

	got, err := getSymlinkXattr(link)
	if err != nil {
		t.Fatalf("getSymlinkXattr: %v", err)
	}

	if !bytes.Equal(got, data) {
		t.Fatalf("xattr roundtrip mismatch: got %q, want %q", got, data)
	}
}

func TestXattrChunking(t *testing.T) {
	dir := t.TempDir()

	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("x"), 0644)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)

	// Create data larger than one chunk (63KB).
	data := bytes.Repeat([]byte("A"), 70*1024)
	if err := setSymlinkXattr(link, data); err != nil {
		t.Fatalf("setSymlinkXattr large: %v", err)
	}

	got, err := getSymlinkXattr(link)
	if err != nil {
		t.Fatalf("getSymlinkXattr large: %v", err)
	}

	if !bytes.Equal(got, data) {
		t.Fatalf("chunked xattr mismatch: got %d bytes, want %d", len(got), len(data))
	}
}

func TestCleanupRestoresFile(t *testing.T) {
	dir := t.TempDir()

	// Simulate mounted state: original replaced by symlink with xattr.
	orig := filepath.Join(dir, "secret.env")
	content := []byte("#touchfs\nZW5jcnlwdGVk\n")

	target := filepath.Join(dir, "fuse-target")
	os.WriteFile(target, []byte("x"), 0644)

	os.Symlink(target, orig)
	if err := setSymlinkXattr(orig, content); err != nil {
		t.Fatalf("setxattr: %v", err)
	}

	// Store mode xattr.
	modeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(modeBuf, uint32(0644))
	unix.Lsetxattr(orig, "touchfs.mode", modeBuf, 0)

	cleanup(dir, []string{"secret.env"})

	// Verify file was restored.
	fi, err := os.Lstat(orig)
	if err != nil {
		t.Fatalf("lstat after cleanup: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("file should no longer be a symlink after cleanup")
	}

	got, err := os.ReadFile(orig)
	if err != nil {
		t.Fatalf("read after cleanup: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: got %q, want %q", got, content)
	}
}

func TestCleanupRestoresPermissions(t *testing.T) {
	dir := t.TempDir()

	orig := filepath.Join(dir, "secret.env")
	content := []byte("sealed data")

	target := filepath.Join(dir, "fuse-target")
	os.WriteFile(target, []byte("x"), 0644)

	os.Symlink(target, orig)
	setSymlinkXattr(orig, content)

	modeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(modeBuf, uint32(0640))
	unix.Lsetxattr(orig, "touchfs.mode", modeBuf, 0)

	cleanup(dir, []string{"secret.env"})

	fi, err := os.Stat(orig)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0640 {
		t.Fatalf("permissions: got %o, want 0640", fi.Mode().Perm())
	}
}

func TestRecoverCrashedFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a broken symlink (target doesn't exist) with xattr.
	orig := filepath.Join(dir, "crashed.env")
	brokenTarget := filepath.Join(dir, "nonexistent-fuse-mount")
	os.Symlink(brokenTarget, orig)

	content := []byte("recovered sealed content")
	setSymlinkXattr(orig, content)

	modeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(modeBuf, uint32(0644))
	unix.Lsetxattr(orig, "touchfs.mode", modeBuf, 0)

	recoverCrashedFiles(dir)

	fi, err := os.Lstat(orig)
	if err != nil {
		t.Fatalf("lstat after recovery: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("file should no longer be a symlink after recovery")
	}

	got, err := os.ReadFile(orig)
	if err != nil {
		t.Fatalf("read after recovery: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: got %q, want %q", got, content)
	}
}

func TestRecoverSkipsValidSymlinks(t *testing.T) {
	dir := t.TempDir()

	// Create a valid symlink (target exists).
	target := filepath.Join(dir, "real-target")
	os.WriteFile(target, []byte("x"), 0644)

	link := filepath.Join(dir, "valid.env")
	os.Symlink(target, link)

	recoverCrashedFiles(dir)

	// Should still be a symlink.
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("valid symlink should not be recovered")
	}
}

func TestLoadSkipDirsDefault(t *testing.T) {
	// With no config file, should return defaults.
	dirs := loadSkipDirs()

	for _, d := range []string{".git", "node_modules", "vendor"} {
		if !dirs[d] {
			t.Fatalf("default skip dirs should include %q", d)
		}
	}
}

func TestLoadSkipDirsCustom(t *testing.T) {
	// Create a temp config dir.
	home := t.TempDir()
	t.Setenv("HOME", home)

	configDir := filepath.Join(home, ".config", "touchfs")
	os.MkdirAll(configDir, 0755)

	configFile := filepath.Join(configDir, "ignore")
	content := strings.Join([]string{
		"# comment",
		"custom_dir",
		"another_dir",
		"",
	}, "\n")
	os.WriteFile(configFile, []byte(content), 0644)

	dirs := loadSkipDirs()

	if !dirs["custom_dir"] {
		t.Fatal("custom config should include custom_dir")
	}
	if !dirs["another_dir"] {
		t.Fatal("custom config should include another_dir")
	}
	if dirs[".git"] {
		t.Fatal("custom config should NOT include default .git when overridden")
	}
}
