package vulnerable

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
)

func HardcodedAESKey(plaintext []byte) ([]byte, error) {
	key := []byte("my-secret-key-16")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := []byte("1234567890123456")
	mode := cipher.NewCBCEncrypter(block, iv)
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ct := make([]byte, len(padded))
	mode.CryptBlocks(ct, padded)
	return ct, nil
}

func WeakPasswordHash(password string) []byte { h := md5.Sum([]byte(password)); return h[:] }
func WeakTokenGeneration(data string) []byte  { h := sha1.Sum([]byte(data)); return h[:] }

type UnsafeEncryptor struct{ key, nonce []byte }

func NewUnsafeEncryptor() *UnsafeEncryptor {
	return &UnsafeEncryptor{key: []byte("0123456789abcdef0123456789abcdef"), nonce: []byte("static-nonce")}
}

func (e *UnsafeEncryptor) Encrypt(pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, e.nonce, pt, nil), nil
}

func pkcs7Pad(data []byte, bs int) []byte {
	p := bs - len(data)%bs
	pad := make([]byte, p)
	for i := range pad {
		pad[i] = byte(p)
	}
	return append(data, pad...)
}
