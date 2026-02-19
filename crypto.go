package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
)

const (
	magic       = "#touchfs\n"
	pbkdf2Iter  = 600_000
	keyLen      = 32
	maxFileSize = 100 * 1024 * 1024 // 100 MB
)

// deriveKey derives a 32-byte AES-256 key from a password using PBKDF2-SHA256.
// Only used once during initial setup — the derived key is stored in Keychain.
func deriveKey(password []byte) []byte {
	// Fixed salt derived from app identity — the password is the only secret.
	salt := []byte("touchfs-v1-salt")
	return pbkdf2.Key(password, salt, pbkdf2Iter, keyLen, sha256.New)
}

// encrypt encrypts plaintext using AES-256-GCM. Returns nonce‖ciphertext‖tag.
func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts data produced by encrypt (nonce‖ciphertext‖tag).
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// sealFile encrypts a file in-place.
func sealFile(path string, key []byte) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("abs path: %w", err)
	}

	if isSealedFile(absPath) {
		return fmt.Errorf("%s is already sealed", path)
	}

	fi, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	if fi.Size() > maxFileSize {
		return fmt.Errorf("%s is too large (%d MB, max %d MB)", path, fi.Size()/(1024*1024), maxFileSize/(1024*1024))
	}

	plaintext, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	encrypted, err := encrypt(plaintext, key)
	if err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(encrypted)
	content := magic + encoded + "\n"

	if err := os.WriteFile(absPath, []byte(content), fi.Mode()); err != nil {
		return fmt.Errorf("write sealed file: %w", err)
	}
	return nil
}

// unsealFile decrypts a sealed file back to plaintext.
func unsealFile(path string, key []byte) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("abs path: %w", err)
	}

	sfi, err := parseSealedFile(absPath)
	if err != nil {
		return err
	}

	plaintext, err := decrypt(sfi.encrypted, key)
	if err != nil {
		return err
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}

	if err := os.WriteFile(absPath, plaintext, info.Mode()); err != nil {
		return fmt.Errorf("write unsealed file: %w", err)
	}
	return nil
}

// isSealedFile checks if a file starts with the touchfs magic header.
func isSealedFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, len(magic))
	n, err := f.Read(buf)
	if err != nil || n < len(magic) {
		return false
	}
	return string(buf) == magic
}

// parseSealedFile reads a sealed file and returns its encrypted bytes + original stat.
func parseSealedFile(path string) (*sealedFileInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat sealed file: %w", err)
	}
	sys := fi.Sys().(*syscall.Stat_t)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sealed file: %w", err)
	}

	content := string(data)
	if !strings.HasPrefix(content, magic) {
		return nil, fmt.Errorf("not a sealed file")
	}

	encoded := strings.TrimSpace(content[len(magic):])
	encrypted, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	return &sealedFileInfo{
		name:      filepath.Base(path),
		encrypted: encrypted,
		mode:      fi.Mode(),
		uid:       sys.Uid,
		gid:       sys.Gid,
	}, nil
}

// sealedFileInfo holds the encrypted content of a sealed file.
type sealedFileInfo struct {
	name      string
	relPath   string // relative path from root dir (set during mount)
	encrypted []byte
	mode      os.FileMode
	uid       uint32
	gid       uint32
}
