package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	magicPrefix = "#touchfs:v1:"
	keyDirRel   = ".config/touchfs/keys"
)

// generateKey returns 32 cryptographically random bytes for AES-256.
func generateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

// keyID returns the hex-encoded SHA-256 of the absolute path.
func keyID(absPath string) string {
	h := sha256.Sum256([]byte(absPath))
	return hex.EncodeToString(h[:])
}

// keyDir returns the path to ~/.config/touchfs/keys/.
func keyDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(home, keyDirRel), nil
}

// saveKey writes a key to ~/.config/touchfs/keys/<id>.key with mode 0600.
func saveKey(id string, key []byte) error {
	dir, err := keyDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	path := filepath.Join(dir, id+".key")
	if err := os.WriteFile(path, key, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

// loadKey reads a key from ~/.config/touchfs/keys/<id>.key.
func loadKey(id string) ([]byte, error) {
	dir, err := keyDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, id+".key")
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", id, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length %d for %s", len(key), id)
	}
	return key, nil
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
	// Seal appends ciphertext+tag after nonce
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

// sealFile encrypts a file in-place, adding the touchfs header.
func sealFile(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("abs path: %w", err)
	}

	if isSealedFile(absPath) {
		return fmt.Errorf("%s is already sealed", path)
	}

	plaintext, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	key, err := generateKey()
	if err != nil {
		return err
	}

	id := keyID(absPath)
	if err := saveKey(id, key); err != nil {
		return err
	}

	encrypted, err := encrypt(plaintext, key)
	if err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(encrypted)
	content := magicPrefix + id + "\n" + encoded + "\n"

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}

	if err := os.WriteFile(absPath, []byte(content), info.Mode()); err != nil {
		return fmt.Errorf("write sealed file: %w", err)
	}
	return nil
}

// unsealFile decrypts a sealed file back to plaintext.
func unsealFile(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("abs path: %w", err)
	}

	id, encrypted, err := parseSealedFile(absPath)
	if err != nil {
		return err
	}

	key, err := loadKey(id)
	if err != nil {
		return err
	}

	plaintext, err := decrypt(encrypted, key)
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

	buf := make([]byte, len(magicPrefix))
	n, err := f.Read(buf)
	if err != nil || n < len(magicPrefix) {
		return false
	}
	return string(buf) == magicPrefix
}

// parseSealedFile reads a sealed file and returns the key ID and encrypted bytes.
func parseSealedFile(path string) (string, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read sealed file: %w", err)
	}

	content := string(data)
	lines := strings.SplitN(content, "\n", 3)
	if len(lines) < 2 {
		return "", nil, fmt.Errorf("invalid sealed file format")
	}

	header := lines[0]
	if !strings.HasPrefix(header, magicPrefix) {
		return "", nil, fmt.Errorf("not a sealed file (missing magic header)")
	}

	id := strings.TrimPrefix(header, magicPrefix)
	if id == "" {
		return "", nil, fmt.Errorf("missing key ID in header")
	}

	encoded := strings.TrimSpace(lines[1])
	encrypted, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", nil, fmt.Errorf("decode base64: %w", err)
	}

	return id, encrypted, nil
}

// sealedFileInfo holds the metadata needed to serve a decrypted file via FUSE.
type sealedFileInfo struct {
	name      string // original filename (e.g. ".env")
	keyID     string // key identifier
	encrypted []byte // raw encrypted bytes (nonce‖ciphertext‖tag)
}
