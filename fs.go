package main

import (
	"log"
	"sync"
	"time"

	"github.com/winfsp/cgofuse/fuse"
)

const authTTL = 5 * time.Second

// SecureEnvFS is a read-only FUSE filesystem that serves decrypted versions
// of sealed files, gated by Touch ID authentication.
type SecureEnvFS struct {
	fuse.FileSystemBase
	files map[string]*sealedFileInfo // filename → sealed info

	// cache stores decrypted content with a TTL
	cacheMu    sync.Mutex
	cache      map[string][]byte
	cacheTime  map[string]time.Time
	cacheTTL   time.Duration
}

// NewSecureEnvFS creates a filesystem serving the given sealed files.
func NewSecureEnvFS(files map[string]*sealedFileInfo) *SecureEnvFS {
	return &SecureEnvFS{
		files:     files,
		cache:     make(map[string][]byte),
		cacheTime: make(map[string]time.Time),
		cacheTTL:  30 * time.Second,
	}
}

// decryptFile returns the decrypted content for a sealed file, using a cache.
func (fs *SecureEnvFS) decryptFile(name string) ([]byte, error) {
	fs.cacheMu.Lock()
	defer fs.cacheMu.Unlock()

	if data, ok := fs.cache[name]; ok {
		if time.Since(fs.cacheTime[name]) < fs.cacheTTL {
			return data, nil
		}
		delete(fs.cache, name)
		delete(fs.cacheTime, name)
	}

	info := fs.files[name]
	key, err := loadKey(info.keyID)
	if err != nil {
		return nil, err
	}
	plaintext, err := decrypt(info.encrypted, key)
	if err != nil {
		return nil, err
	}

	fs.cache[name] = plaintext
	fs.cacheTime[name] = time.Now()
	return plaintext, nil
}

func (fs *SecureEnvFS) Getattr(path string, stat *fuse.Stat_t, fh uint64) int {
	if path == "/" {
		stat.Mode = fuse.S_IFDIR | 0555
		stat.Nlink = 2
		return 0
	}

	name := path[1:] // strip leading "/"
	info, ok := fs.files[name]
	if !ok {
		return -fuse.ENOENT
	}

	// We need the decrypted size for accurate stat
	plaintext, err := fs.decryptFile(info.name)
	if err != nil {
		log.Printf("decrypt error for %s: %v", name, err)
		return -fuse.EIO
	}

	stat.Mode = fuse.S_IFREG | 0444
	stat.Nlink = 1
	stat.Size = int64(len(plaintext))
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
	for name := range fs.files {
		fill(name, nil, 0)
	}
	return 0
}

func (fs *SecureEnvFS) Open(path string, flags int) (int, uint64) {
	name := path[1:]
	if _, ok := fs.files[name]; !ok {
		return -fuse.ENOENT, 0
	}

	ok, err := authenticateTouchID("touchfs: access "+name, authTTL)
	if err != nil {
		log.Printf("Touch ID error: %v", err)
		return -fuse.EACCES, 0
	}
	if !ok {
		log.Printf("Touch ID denied for %s", name)
		return -fuse.EACCES, 0
	}

	log.Printf("Touch ID OK — serving %s", name)
	return 0, 0
}

func (fs *SecureEnvFS) Read(path string, buff []byte, ofst int64, fh uint64) int {
	name := path[1:]
	info, ok := fs.files[name]
	if !ok {
		return -fuse.ENOENT
	}

	plaintext, err := fs.decryptFile(info.name)
	if err != nil {
		log.Printf("decrypt error for %s: %v", name, err)
		return -fuse.EIO
	}

	if ofst >= int64(len(plaintext)) {
		return 0
	}
	n := copy(buff, plaintext[ofst:])
	return n
}
