package main

import (
	"bytes"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/winfsp/cgofuse/fuse"
)

// newTestFS creates a SecureEnvFS with a single encrypted file and auth always allowed.
func newTestFS(t *testing.T, name string, plaintext []byte, mode os.FileMode) *SecureEnvFS {
	t.Helper()
	key := deriveKey([]byte("test-password"))
	enc, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	files := map[string]*sealedFileInfo{
		name: {
			name:      name,
			relPath:   name,
			encrypted: enc,
			mode:      mode,
			uid:       501,
			gid:       20,
		},
	}

	fs := NewSecureEnvFS(files, key)
	fs.authFunc = func(reason string) bool { return true }
	return fs
}

func TestGetattrRoot(t *testing.T) {
	fs := newTestFS(t, "test.env", []byte("data"), 0644)
	var stat fuse.Stat_t

	rc := fs.Getattr("/", &stat, ^uint64(0))
	if rc != 0 {
		t.Fatalf("Getattr root: %d", rc)
	}
	if stat.Mode&0777 != 0755 {
		t.Fatalf("root mode: got %o, want 0755", stat.Mode&0777)
	}
	if stat.Mode&fuse.S_IFDIR == 0 {
		t.Fatal("root should be a directory")
	}
}

func TestGetattrFile(t *testing.T) {
	plaintext := []byte("hello world")
	fs := newTestFS(t, "test.env", plaintext, 0640)
	var stat fuse.Stat_t

	rc := fs.Getattr("/test.env", &stat, ^uint64(0))
	if rc != 0 {
		t.Fatalf("Getattr file: %d", rc)
	}
	if stat.Mode&0777 != 0640 {
		t.Fatalf("file mode: got %o, want 0640", stat.Mode&0777)
	}
	if stat.Size != int64(len(plaintext)) {
		t.Fatalf("file size: got %d, want %d", stat.Size, len(plaintext))
	}
}

func TestGetattrNotFound(t *testing.T) {
	fs := newTestFS(t, "test.env", []byte("data"), 0644)
	var stat fuse.Stat_t

	rc := fs.Getattr("/nonexistent", &stat, ^uint64(0))
	if rc != -fuse.ENOENT {
		t.Fatalf("expected ENOENT, got %d", rc)
	}
}

func TestReaddirRoot(t *testing.T) {
	key := deriveKey([]byte("test-password"))
	enc1, _ := encrypt([]byte("a"), key)
	enc2, _ := encrypt([]byte("b"), key)

	files := map[string]*sealedFileInfo{
		"file1": {name: "file1", relPath: "file1", encrypted: enc1, mode: 0644, uid: 501, gid: 20},
		"file2": {name: "file2", relPath: "file2", encrypted: enc2, mode: 0644, uid: 501, gid: 20},
	}

	fs := NewSecureEnvFS(files, key)
	fs.authFunc = func(reason string) bool { return true }

	var names []string
	fill := func(name string, stat *fuse.Stat_t, ofst int64) bool {
		names = append(names, name)
		return true
	}

	rc := fs.Readdir("/", fill, 0, 0)
	if rc != 0 {
		t.Fatalf("Readdir: %d", rc)
	}

	if len(names) != 4 {
		t.Fatalf("expected 4 entries (., .., file1, file2), got %d: %v", len(names), names)
	}

	has := make(map[string]bool)
	for _, n := range names {
		has[n] = true
	}
	for _, want := range []string{".", "..", "file1", "file2"} {
		if !has[want] {
			t.Fatalf("missing entry %q in %v", want, names)
		}
	}
}

func TestReaddirNonRoot(t *testing.T) {
	fs := newTestFS(t, "test.env", []byte("data"), 0644)
	fill := func(name string, stat *fuse.Stat_t, ofst int64) bool { return true }

	rc := fs.Readdir("/subdir", fill, 0, 0)
	if rc != -fuse.ENOENT {
		t.Fatalf("expected ENOENT for non-root readdir, got %d", rc)
	}
}

func TestAccessFile(t *testing.T) {
	fs := newTestFS(t, "test.env", []byte("data"), 0644)

	rc := fs.Access("/test.env", 0)
	if rc != 0 {
		t.Fatalf("Access existing file: %d", rc)
	}
}

func TestAccessNotFound(t *testing.T) {
	fs := newTestFS(t, "test.env", []byte("data"), 0644)

	rc := fs.Access("/missing", 0)
	if rc != -fuse.ENOENT {
		t.Fatalf("expected ENOENT, got %d", rc)
	}
}

func TestOpenReadRelease(t *testing.T) {
	plaintext := []byte("decrypted content here")
	fs := newTestFS(t, "test.env", plaintext, 0644)

	rc, fh := fs.Open("/test.env", 0)
	if rc != 0 {
		t.Fatalf("Open: %d", rc)
	}

	buf := make([]byte, 1024)
	n := fs.Read("/test.env", buf, 0, fh)
	if n != len(plaintext) {
		t.Fatalf("Read: got %d bytes, want %d", n, len(plaintext))
	}
	if !bytes.Equal(buf[:n], plaintext) {
		t.Fatalf("Read: got %q, want %q", buf[:n], plaintext)
	}

	rc = fs.Release("/test.env", fh)
	if rc != 0 {
		t.Fatalf("Release: %d", rc)
	}
}

func TestOpenAuthDenied(t *testing.T) {
	plaintext := []byte("secret")
	fs := newTestFS(t, "test.env", plaintext, 0644)
	fs.authFunc = func(reason string) bool { return false }

	rc, _ := fs.Open("/test.env", 0)
	if rc != -fuse.EACCES {
		t.Fatalf("expected EACCES when auth denied, got %d", rc)
	}
}

func TestWriteReencrypt(t *testing.T) {
	plaintext := []byte("original")
	fs := newTestFS(t, "test.env", plaintext, 0644)

	var dirtyCalled bool
	var dirtyPath string
	var dirtyData []byte
	fs.onDirty = func(relPath string, sealed []byte) {
		dirtyCalled = true
		dirtyPath = relPath
		dirtyData = sealed
	}

	rc, fh := fs.Open("/test.env", 0)
	if rc != 0 {
		t.Fatalf("Open: %d", rc)
	}

	newContent := []byte("updated!")
	n := fs.Write("/test.env", newContent, 0, fh)
	if n != len(newContent) {
		t.Fatalf("Write: got %d, want %d", n, len(newContent))
	}

	rc = fs.Release("/test.env", fh)
	if rc != 0 {
		t.Fatalf("Release: %d", rc)
	}

	if !dirtyCalled {
		t.Fatal("onDirty should have been called after writing different content")
	}
	if dirtyPath != "test.env" {
		t.Fatalf("onDirty relPath: got %q, want %q", dirtyPath, "test.env")
	}
	if len(dirtyData) == 0 {
		t.Fatal("onDirty sealed data should not be empty")
	}
}

func TestWriteNoChangeNoReencrypt(t *testing.T) {
	plaintext := []byte("same content")
	fs := newTestFS(t, "test.env", plaintext, 0644)

	var dirtyCalled bool
	fs.onDirty = func(relPath string, sealed []byte) {
		dirtyCalled = true
	}

	rc, fh := fs.Open("/test.env", 0)
	if rc != 0 {
		t.Fatalf("Open: %d", rc)
	}

	// Read only, no write.
	buf := make([]byte, 1024)
	fs.Read("/test.env", buf, 0, fh)

	rc = fs.Release("/test.env", fh)
	if rc != 0 {
		t.Fatalf("Release: %d", rc)
	}

	if dirtyCalled {
		t.Fatal("onDirty should NOT be called when content is unchanged")
	}
}

func TestTruncate(t *testing.T) {
	plaintext := []byte("1234567890")
	fs := newTestFS(t, "test.env", plaintext, 0644)

	rc, fh := fs.Open("/test.env", 0)
	if rc != 0 {
		t.Fatalf("Open: %d", rc)
	}

	rc = fs.Truncate("/test.env", 5, fh)
	if rc != 0 {
		t.Fatalf("Truncate: %d", rc)
	}

	buf := make([]byte, 1024)
	n := fs.Read("/test.env", buf, 0, fh)
	if n != 5 {
		t.Fatalf("after truncate: got %d bytes, want 5", n)
	}
	if !bytes.Equal(buf[:n], []byte("12345")) {
		t.Fatalf("after truncate: got %q, want %q", buf[:n], "12345")
	}

	fs.Release("/test.env", fh)
}

func TestAuthCachePerFilePid(t *testing.T) {
	key := deriveKey([]byte("test-password"))
	enc, _ := encrypt([]byte("data"), key)

	files := map[string]*sealedFileInfo{
		"file1": {name: "file1", relPath: "file1", encrypted: enc, mode: 0644, uid: 501, gid: 20},
	}

	fs := NewSecureEnvFS(files, key)

	var mu sync.Mutex
	authCalls := 0
	fs.authFunc = func(reason string) bool {
		mu.Lock()
		authCalls++
		mu.Unlock()
		return true
	}

	// First open triggers auth.
	rc, fh := fs.Open("/file1", 0)
	if rc != 0 {
		t.Fatalf("Open 1: %d", rc)
	}
	fs.Release("/file1", fh)

	mu.Lock()
	c := authCalls
	mu.Unlock()
	if c != 1 {
		t.Fatalf("expected 1 auth call, got %d", c)
	}

	// Second open within TTL should use cache (same pid=0 in test).
	rc, fh = fs.Open("/file1", 0)
	if rc != 0 {
		t.Fatalf("Open 2: %d", rc)
	}
	fs.Release("/file1", fh)

	mu.Lock()
	c = authCalls
	mu.Unlock()
	if c != 1 {
		t.Fatalf("expected auth to be cached (still 1 call), got %d", c)
	}

	// Wait for TTL to expire, then open again should trigger auth.
	time.Sleep(authTTL + 50*time.Millisecond)

	rc, fh = fs.Open("/file1", 0)
	if rc != 0 {
		t.Fatalf("Open 3: %d", rc)
	}
	fs.Release("/file1", fh)

	mu.Lock()
	c = authCalls
	mu.Unlock()
	if c != 2 {
		t.Fatalf("expected 2 auth calls after TTL expiry, got %d", c)
	}
}
