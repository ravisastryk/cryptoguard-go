package vulnerable

import (
	"bytes"
	"testing"
)

func TestHardcodedAESKey_Encrypts(t *testing.T) {
	ct, err := HardcodedAESKey([]byte("hello world12345"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) == 0 {
		t.Error("empty")
	}
}

func TestHardcodedAESKey_Deterministic(t *testing.T) {
	a, _ := HardcodedAESKey([]byte("deterministic!16"))
	b, _ := HardcodedAESKey([]byte("deterministic!16"))
	if !bytes.Equal(a, b) {
		t.Error("static key+iv should match")
	}
}

func TestWeakPasswordHash_16(t *testing.T) {
	if len(WeakPasswordHash("pw")) != 16 {
		t.Error("MD5 = 16 bytes")
	}
}

func TestWeakPasswordHash_Diff(t *testing.T) {
	if bytes.Equal(WeakPasswordHash("a"), WeakPasswordHash("b")) {
		t.Error("should differ")
	}
}

func TestWeakToken_20(t *testing.T) {
	if len(WeakTokenGeneration("x")) != 20 {
		t.Error("SHA1 = 20 bytes")
	}
}

func TestUnsafe_Encrypts(t *testing.T) {
	if ct, err := NewUnsafeEncryptor().Encrypt([]byte("t")); err != nil || len(ct) == 0 {
		t.Error("encrypt failed")
	}
}

func TestUnsafe_NonceReuse(t *testing.T) {
	e := NewUnsafeEncryptor()
	a, _ := e.Encrypt([]byte("one"))
	b, _ := e.Encrypt([]byte("two"))
	if len(a) == 0 || len(b) == 0 {
		t.Error("both should succeed")
	}
}

func TestPkcs7Pad(t *testing.T) {
	for _, tt := range []struct{ in, bs, want int }{{15, 16, 16}, {16, 16, 32}, {1, 16, 16}} {
		if got := len(pkcs7Pad(make([]byte, tt.in), tt.bs)); got != tt.want {
			t.Errorf("pkcs7(%d,%d)=%d want %d", tt.in, tt.bs, got, tt.want)
		}
	}
}
