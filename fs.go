package main

import (
	"bytes"
	"encoding/base64"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/winfsp/cgofuse/fuse"
)

const authTTL = 500 * time.Millisecond

// openFile tracks the state of a single open file descriptor.
type openFile struct {
	name     string // FUSE key (hash) for encrypted map lookup
	relPath  string // original relative path for onDirty/logging
	data     []byte // decrypted content
	origData []byte // original plaintext at open time
	dirty    bool
}

// SecureEnvFS is a FUSE filesystem that serves encrypted files,
// decrypting on open (after Touch ID) and re-encrypting on close.
type SecureEnvFS struct {
	fuse.FileSystemBase
	mu        sync.Mutex
	key       []byte                     // AES key (from Keychain at mount)
	rootDir   string                     // absolute path of the mounted directory
	encrypted map[string]*sealedFileInfo // fuseKey → sealed info
	handles   map[uint64]*openFile       // fh → open file state
	nextFH    uint64
	lastAuth  map[string]time.Time               // per-file Touch ID cache
	onDirty   func(relPath string, sealed []byte) // callback to update xattr on write
	authFunc  func(reason string) bool             // defaults to authenticateTouchID
}

// NewSecureEnvFS creates a filesystem with encrypted file contents and the AES key.
func NewSecureEnvFS(files map[string]*sealedFileInfo, key []byte) *SecureEnvFS {
	return &SecureEnvFS{
		key:       key,
		encrypted: files,
		handles:   make(map[uint64]*openFile),
		nextFH:    1,
		lastAuth:  make(map[string]time.Time),
		authFunc:  authenticateTouchID,
	}
}

func (fs *SecureEnvFS) Getattr(path string, stat *fuse.Stat_t, fh uint64) int {
	if path == "/" {
		stat.Mode = fuse.S_IFDIR | 0755
		stat.Nlink = 2
		// Use first file's ownership for root dir.
		for _, info := range fs.encrypted {
			stat.Uid = info.uid
			stat.Gid = info.gid
			break
		}
		return 0
	}

	name := path[1:]
	fs.mu.Lock()
	defer fs.mu.Unlock()

	info, ok := fs.encrypted[name]
	if !ok {
		return -fuse.ENOENT
	}

	// If there's an open handle for this file, use its size.
	for _, of := range fs.handles {
		if of.name == name {
			stat.Mode = fuse.S_IFREG | uint32(info.mode.Perm())
			stat.Nlink = 1
			stat.Size = int64(len(of.data))
			stat.Uid = info.uid
			stat.Gid = info.gid
			return 0
		}
	}

	// Otherwise, decrypt to get accurate size.
	plaintext, err := decrypt(info.encrypted, fs.key)
	if err != nil {
		log.Printf("decrypt error for %s: %v", info.relPath, err)
		return -fuse.EIO
	}

	stat.Mode = fuse.S_IFREG | uint32(info.mode.Perm())
	stat.Nlink = 1
	stat.Size = int64(len(plaintext))
	stat.Uid = info.uid
	stat.Gid = info.gid
	return 0
}

func (fs *SecureEnvFS) Readdir(path string,
	fill func(name string, stat *fuse.Stat_t, ofst int64) bool,
	ofst int64, fh uint64) int {

	if path != "/" {
		return -fuse.ENOENT
	}

	fill(".", nil, 0)
	fill("..", nil, 0)
	fs.mu.Lock()
	for name := range fs.encrypted {
		fill(name, nil, 0)
	}
	fs.mu.Unlock()
	return 0
}

func (fs *SecureEnvFS) Access(path string, mask uint32) int {
	if path == "/" {
		return 0
	}
	name := path[1:]
	fs.mu.Lock()
	_, ok := fs.encrypted[name]
	fs.mu.Unlock()
	if !ok {
		return -fuse.ENOENT
	}
	return 0
}

func (fs *SecureEnvFS) Open(path string, flags int) (int, uint64) {
	name := path[1:]
	fs.mu.Lock()
	info, ok := fs.encrypted[name]
	fs.mu.Unlock()
	if !ok {
		return -fuse.ENOENT, 0
	}

	log.Printf("Open called: %s (flags=%d)", info.relPath, flags)

	// Touch ID gate via LAContext (skip if within TTL for this file).
	fs.mu.Lock()
	cached := time.Since(fs.lastAuth[name]) < authTTL
	fs.mu.Unlock()
	if !cached {
		absPath := filepath.Join(fs.rootDir, info.relPath)
		reason := "access " + absPath
		if !fs.authFunc(reason) {
			log.Printf("Touch ID denied for %s", info.relPath)
			return -fuse.EACCES, 0
		}
		fs.mu.Lock()
		fs.lastAuth[name] = time.Now()
		fs.mu.Unlock()
	}

	// Decrypt on open.
	plaintext, err := decrypt(info.encrypted, fs.key)
	if err != nil {
		log.Printf("decrypt error for %s: %v", info.relPath, err)
		return -fuse.EIO, 0
	}

	fs.mu.Lock()
	fh := fs.nextFH
	fs.nextFH++
	orig := make([]byte, len(plaintext))
	copy(orig, plaintext)
	fs.handles[fh] = &openFile{
		name:     name,
		relPath:  info.relPath,
		data:     plaintext,
		origData: orig,
	}
	fs.mu.Unlock()

	log.Printf("Touch ID OK — opened %s (fh=%d)", info.relPath, fh)
	return 0, fh
}

func (fs *SecureEnvFS) Read(path string, buff []byte, ofst int64, fh uint64) int {
	fs.mu.Lock()
	of, ok := fs.handles[fh]
	fs.mu.Unlock()
	if !ok {
		return -fuse.EBADF
	}

	if ofst >= int64(len(of.data)) {
		return 0
	}
	n := copy(buff, of.data[ofst:])
	return n
}

func (fs *SecureEnvFS) Write(path string, buff []byte, ofst int64, fh uint64) int {
	fs.mu.Lock()
	of, ok := fs.handles[fh]
	if !ok {
		fs.mu.Unlock()
		return -fuse.EBADF
	}

	end := ofst + int64(len(buff))
	if end > int64(len(of.data)) {
		grown := make([]byte, end)
		copy(grown, of.data)
		of.data = grown
	}
	copy(of.data[ofst:], buff)
	of.dirty = true
	fs.mu.Unlock()
	return len(buff)
}

func (fs *SecureEnvFS) Truncate(path string, size int64, fh uint64) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Try file handle first.
	if fh != ^uint64(0) {
		of, ok := fs.handles[fh]
		if ok {
			if size < int64(len(of.data)) {
				of.data = of.data[:size]
			} else if size > int64(len(of.data)) {
				grown := make([]byte, size)
				copy(grown, of.data)
				of.data = grown
			}
			of.dirty = true
			return 0
		}
	}

	// Path-based truncate (no open handle).
	name := path[1:]
	if _, ok := fs.encrypted[name]; !ok {
		return -fuse.ENOENT
	}
	return 0
}

func (fs *SecureEnvFS) Release(path string, fh uint64) int {
	fs.mu.Lock()
	of, ok := fs.handles[fh]
	if !ok {
		fs.mu.Unlock()
		return 0
	}
	delete(fs.handles, fh)
	fs.mu.Unlock()

	if of.dirty && !bytes.Equal(of.data, of.origData) {
		// Re-encrypt and update stored encrypted content.
		enc, err := encrypt(of.data, fs.key)
		if err != nil {
			log.Printf("re-encrypt error for %s: %v", of.relPath, err)
			return -fuse.EIO
		}

		fs.mu.Lock()
		if info, ok := fs.encrypted[of.name]; ok {
			info.encrypted = enc
		}
		fs.mu.Unlock()

		// Notify main to update xattr.
		if fs.onDirty != nil {
			sealed := magic + base64.StdEncoding.EncodeToString(enc) + "\n"
			fs.onDirty(of.relPath, []byte(sealed))
		}

		log.Printf("Re-encrypted %s on close", of.relPath)
	}
	return 0
}
