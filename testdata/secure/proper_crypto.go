package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

func SecureAESEncryption(plaintext []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func SecurePasswordHash(password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return append(salt, argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)...), nil
}

func SecureTokenGeneration(data string) []byte { h := sha256.Sum256([]byte(data)); return h[:] }

type SecureGCMEncryptor struct{ key []byte }

func NewSecureGCMEncryptor(key []byte) *SecureGCMEncryptor { return &SecureGCMEncryptor{key: key} }

func (e *SecureGCMEncryptor) Encrypt(pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, pt, nil), nil
}

func (e *SecureGCMEncryptor) Decrypt(ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ct) < ns {
		return nil, err
	}
	return gcm.Open(nil, ct[:ns], ct[ns:], nil)
}
