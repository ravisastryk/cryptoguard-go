# CryptoGuard-Go Detailed Remediation Guide

**Generated:** 2026-02-01

This report provides detailed, actionable remediation steps for each identified vulnerability with code-level examples.

---

## Quick Reference

| Vulnerability | Severity | Recommended Fix | Priority |
|---------------|----------|-----------------|----------|
| MD5 Usage (CRYPTO001) | HIGH | Replace with SHA-256 | IMMEDIATE |
| SHA-1 Usage (CRYPTO002) | HIGH | Replace with SHA-256 | IMMEDIATE |
| Hardcoded Keys (CRYPTO010) | CRITICAL | Use environment variables/secrets | IMMEDIATE |
| Static IV (CRYPTO020) | CRITICAL | Use crypto/rand for generation | IMMEDIATE |
| Quantum-Vulnerable (CRYPTO040) | MEDIUM | Plan hybrid PQ migration | 2027-2029 |

---


## Repository-Specific Findings

<a name="fatedier-frp"></a>

### Repository: [fatedier/frp](https://github.com/fatedier/frp)

**Total Issues:** 8
**Breakdown:** 0 Critical, 3 High, 5 Medium, 0 Low

#### Code Locations:

| Severity | Rule | File:Line | Description |
|----------|------|-----------|-------------|

**Recommended Actions:**
1. Address HIGH/CRITICAL issues immediately
2. Replace MD5 with SHA-256: `find . -name "*.go" -exec sed -i 's/crypto\/md5/crypto\/sha256/g' {} \;`
4. Consider post-quantum migration planning (informational)

---

<a name="kubernetes-kubernetes"></a>

### Repository: [kubernetes/kubernetes](https://github.com/kubernetes/kubernetes)

**Total Issues:** 42
**Breakdown:** 0 Critical, 0 High, 42 Medium, 0 Low

#### Code Locations:

| Severity | Rule | File:Line | Description |
|----------|------|-----------|-------------|

**Recommended Actions:**
4. Consider post-quantum migration planning (informational)

---

<a name="ollama-ollama"></a>

### Repository: [ollama/ollama](https://github.com/ollama/ollama)

**Total Issues:** 1
**Breakdown:** 0 Critical, 1 High, 0 Medium, 0 Low

#### Code Locations:

| Severity | Rule | File:Line | Description |
|----------|------|-----------|-------------|

**Recommended Actions:**
1. Address HIGH/CRITICAL issues immediately
2. Replace MD5 with SHA-256: `find . -name "*.go" -exec sed -i 's/crypto\/md5/crypto\/sha256/g' {} \;`

---


## Code Fix Examples

### Fix: Replace MD5 with SHA-256

**Before:**
```go
import "crypto/md5"

func GenerateHash(data []byte) string {
    hash := md5.Sum(data)
    return hex.EncodeToString(hash[:])
}
```

**After:**
```go
import "crypto/sha256"

func GenerateHash(data []byte) string {
    hash := sha256.Sum256(data)
    return hex.EncodeToString(hash[:])
}
```

**Effort:** Low (1-2 hours)
**Priority:** IMMEDIATE

---

### Fix: Replace SHA-1 with SHA-256

**Before:**
```go
import "crypto/sha1"

h := sha1.New()
h.Write(data)
result := h.Sum(nil)
```

**After:**
```go
import "crypto/sha256"

h := sha256.New()
h.Write(data)
result := h.Sum(nil)
```

**Effort:** Low (1-2 hours)
**Priority:** IMMEDIATE

---

### Fix: Remove Hardcoded Keys

**Before:**
```go
var encryptionKey = []byte("hardcoded-secret-key-32bytes!!")

func encrypt(data []byte) ([]byte, error) {
    block, _ := aes.NewCipher(encryptionKey)
    // ...
}
```

**After:**
```go
import "os"

func getEncryptionKey() []byte {
    key := os.Getenv("ENCRYPTION_KEY")
    if key == "" {
        panic("ENCRYPTION_KEY environment variable not set")
    }
    return []byte(key)
}

func encrypt(data []byte) ([]byte, error) {
    block, _ := aes.NewCipher(getEncryptionKey())
    // ...
}
```

**Effort:** Medium (4-8 hours including deployment)
**Priority:** IMMEDIATE

---

### Fix: Generate Random IV

**Before:**
```go
var staticIV = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

func encrypt(plaintext []byte) []byte {
    block, _ := aes.NewCipher(key)
    cbc := cipher.NewCBCEncrypter(block, staticIV)
    // ...
}
```

**After:**
```go
import "crypto/rand"

func encrypt(plaintext []byte) ([]byte, error) {
    block, _ := aes.NewCipher(key)

    // Generate random IV
    iv := make([]byte, aes.BlockSize)
    if _, err := rand.Read(iv); err != nil {
        return nil, err
    }

    cbc := cipher.NewCBCEncrypter(block, iv)
    // Prepend IV to ciphertext for decryption
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    copy(ciphertext[:aes.BlockSize], iv)
    // ...
    return ciphertext, nil
}
```

**Effort:** Medium (4-6 hours)
**Priority:** IMMEDIATE

---

### Future-Proofing: Post-Quantum Readiness

**Current RSA Usage:**
```go
privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
```

**Recommended Interim Upgrade:**
```go
// Use larger key size while PQ standards mature
privateKey, _ := rsa.GenerateKey(rand.Reader, 4096)
```

**Future (2027+):**
```go
// Monitor Go's ML-KEM implementation (FIPS 203)
// Plan hybrid RSA + ML-KEM deployment
```

**Effort:** High (research required)
**Priority:** MEDIUM (plan now, implement 2027-2029)

---

## Testing Checklist

- [ ] All MD5 usages replaced with SHA-256
- [ ] All SHA-1 usages replaced with SHA-256
- [ ] All hardcoded keys moved to environment variables
- [ ] All static IVs replaced with random generation
- [ ] Unit tests updated for new hash values
- [ ] Integration tests pass
- [ ] Security scan shows no HIGH/CRITICAL issues
- [ ] Documentation updated

---

## Resources

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Go Crypto Package Documentation](https://pkg.go.dev/crypto)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

*Generated by CryptoGuard-Go - Automated Cryptographic Vulnerability Scanner*
