package secure

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"testing"
)

func setKey(t *testing.T) {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	os.Setenv("ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(k))
	t.Cleanup(func() { os.Unsetenv("ENCRYPTION_KEY") })
}

func TestHash_Len(t *testing.T) {
	h, err := SecurePasswordHash("pw")
	if err != nil || len(h) != 48 {
		t.Error("want 48")
	}
}

func TestHash_Unique(t *testing.T) {
	a, _ := SecurePasswordHash("same")
	b, _ := SecurePasswordHash("same")
	if string(a) == string(b) {
		t.Error("salt should differ")
	}
}

func TestToken_32(t *testing.T) {
	if len(SecureTokenGeneration("x")) != 32 {
		t.Error("SHA-256 = 32")
	}
}

func TestToken_Deterministic(t *testing.T) {
	if string(SecureTokenGeneration("h")) != string(SecureTokenGeneration("h")) {
		t.Error("should match")
	}
}

func TestAES_Encrypts(t *testing.T) {
	setKey(t)
	if ct, err := SecureAESEncryption([]byte("s")); err != nil || len(ct) == 0 {
		t.Error("failed")
	}
}

func TestAES_NonDeterministic(t *testing.T) {
	setKey(t)
	a, _ := SecureAESEncryption([]byte("x"))
	b, _ := SecureAESEncryption([]byte("x"))
	if string(a) == string(b) {
		t.Error("nonce should differ")
	}
}

func TestAES_NoKey(t *testing.T) {
	os.Unsetenv("ENCRYPTION_KEY")
	if _, err := SecureAESEncryption([]byte("x")); err == nil {
		t.Error("want error")
	}
}

func TestGCM_RoundTrip(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	e := NewSecureGCMEncryptor(k)
	ct, _ := e.Encrypt([]byte("rt"))
	pt, err := e.Decrypt(ct)
	if err != nil || string(pt) != "rt" {
		t.Error("mismatch")
	}
}

func TestGCM_NonDeterministic(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	e := NewSecureGCMEncryptor(k)
	a, _ := e.Encrypt([]byte("h"))
	b, _ := e.Encrypt([]byte("h"))
	if string(a) == string(b) {
		t.Error("nonce differ")
	}
}

func TestGCM_Tampered(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	e := NewSecureGCMEncryptor(k)
	ct, _ := e.Encrypt([]byte("d"))
	ct[len(ct)-1] ^= 0xFF
	if _, err := e.Decrypt(ct); err == nil {
		t.Error("should fail auth")
	}
}

func TestGCM_BadKey(t *testing.T) {
	if _, err := NewSecureGCMEncryptor([]byte("short")).Encrypt([]byte("x")); err == nil {
		t.Error("bad key")
	}
}
