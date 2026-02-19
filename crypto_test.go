package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := deriveKey([]byte("test-password"))
	plaintext := []byte("hello, touchfs!")

	enc, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	dec, err := decrypt(enc, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, dec) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", dec, plaintext)
	}
}

func TestEncryptProducesDifferentCiphertext(t *testing.T) {
	key := deriveKey([]byte("test-password"))
	plaintext := []byte("same data")

	enc1, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt 1: %v", err)
	}
	enc2, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt 2: %v", err)
	}

	if bytes.Equal(enc1, enc2) {
		t.Fatal("two encryptions of the same data produced identical ciphertext")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := deriveKey([]byte("password-1"))
	key2 := deriveKey([]byte("password-2"))
	plaintext := []byte("secret")

	enc, err := encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = decrypt(enc, key2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDecryptTamperedData(t *testing.T) {
	key := deriveKey([]byte("test-password"))
	plaintext := []byte("do not tamper")

	enc, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Flip a byte in the ciphertext (after the nonce).
	enc[len(enc)-1] ^= 0xff

	_, err = decrypt(enc, key)
	if err == nil {
		t.Fatal("expected GCM authentication failure on tampered data")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	k1 := deriveKey([]byte("same-password"))
	k2 := deriveKey([]byte("same-password"))

	if !bytes.Equal(k1, k2) {
		t.Fatal("same password produced different keys")
	}
}

func TestDeriveKeyDifferentPasswords(t *testing.T) {
	k1 := deriveKey([]byte("password-a"))
	k2 := deriveKey([]byte("password-b"))

	if bytes.Equal(k1, k2) {
		t.Fatal("different passwords produced the same key")
	}
}

func TestSealUnsealRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.env")
	original := []byte("API_KEY=hunter2\n")

	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	key := deriveKey([]byte("test-password"))

	if err := sealFile(path, key); err != nil {
		t.Fatalf("seal: %v", err)
	}

	if !isSealedFile(path) {
		t.Fatal("file should be sealed after sealFile")
	}

	if err := unsealFile(path, key); err != nil {
		t.Fatalf("unseal: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", got, original)
	}
}

func TestSealPreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.env")

	if err := os.WriteFile(path, []byte("data"), 0640); err != nil {
		t.Fatalf("write: %v", err)
	}

	key := deriveKey([]byte("test-password"))
	if err := sealFile(path, key); err != nil {
		t.Fatalf("seal: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if fi.Mode().Perm() != 0640 {
		t.Fatalf("permissions changed: got %o, want 0640", fi.Mode().Perm())
	}
}

func TestSealTooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.bin")

	// Create a file just over the limit.
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(maxFileSize + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	key := deriveKey([]byte("test-password"))
	err = sealFile(path, key)
	if err == nil {
		t.Fatal("expected error sealing file over 100MB")
	}
}

func TestSealAlreadySealed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.env")

	if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	key := deriveKey([]byte("test-password"))
	if err := sealFile(path, key); err != nil {
		t.Fatalf("first seal: %v", err)
	}

	err := sealFile(path, key)
	if err == nil {
		t.Fatal("expected error sealing an already sealed file")
	}
}

func TestUnsealNonSealed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.txt")

	if err := os.WriteFile(path, []byte("not sealed"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	key := deriveKey([]byte("test-password"))
	err := unsealFile(path, key)
	if err == nil {
		t.Fatal("expected error unsealing a non-sealed file")
	}
}

func TestIsSealedFile(t *testing.T) {
	dir := t.TempDir()
	key := deriveKey([]byte("test-password"))

	sealed := filepath.Join(dir, "sealed.env")
	if err := os.WriteFile(sealed, []byte("data"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sealFile(sealed, key); err != nil {
		t.Fatalf("seal: %v", err)
	}

	plain := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plain, []byte("plain data"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if !isSealedFile(sealed) {
		t.Fatal("isSealedFile should return true for sealed file")
	}
	if isSealedFile(plain) {
		t.Fatal("isSealedFile should return false for plain file")
	}
}

func TestParseSealedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.env")
	original := []byte("SECRET=value\n")

	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	key := deriveKey([]byte("test-password"))
	if err := sealFile(path, key); err != nil {
		t.Fatalf("seal: %v", err)
	}

	sfi, err := parseSealedFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if sfi.name != "secret.env" {
		t.Fatalf("name: got %q, want %q", sfi.name, "secret.env")
	}
	if len(sfi.encrypted) == 0 {
		t.Fatal("encrypted bytes should not be empty")
	}

	// Verify the encrypted bytes actually decrypt to the original.
	dec, err := decrypt(sfi.encrypted, key)
	if err != nil {
		t.Fatalf("decrypt parsed sealed: %v", err)
	}
	if !bytes.Equal(dec, original) {
		t.Fatalf("parsed content mismatch: got %q, want %q", dec, original)
	}
}
