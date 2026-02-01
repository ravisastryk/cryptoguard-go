#!/bin/bash
set -e

# CryptoGuard-Go Report Generator
# Generates a markdown report with tables from scan results

echo "Generating vulnerability report..."

# Create reports directory
mkdir -p reports

# Start markdown report
REPORT_FILE="reports/summary.md"

cat > "$REPORT_FILE" <<HEADER
# CryptoGuard-Go Weekly Vulnerability Scan Report

**Scan Date:** $(date +"%Y-%m-%d %H:%M:%S UTC")
**Tool Version:** v0.1.0

## Executive Summary

HEADER

# Read summary
if [ -f "scan-results/summary.txt" ]; then
    echo "" >> "$REPORT_FILE"
    echo "$(grep "Total repositories" scan-results/summary.txt)" >> "$REPORT_FILE"
    echo "$(grep "Repositories with issues" scan-results/summary.txt)" >> "$REPORT_FILE"
    echo "$(grep "Total issues found" scan-results/summary.txt)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

# Add detailed results table
cat >> "$REPORT_FILE" <<'TABLE_HEADER'

## Detailed Findings

### Vulnerability Summary by Repository

| Repository | Total Issues | Critical | High | Medium | Low | Status |
|------------|--------------|----------|------|--------|-----|--------|
TABLE_HEADER

# Process each JSON result file
for json_file in scan-results/*.json; do
    if [ -f "$json_file" ]; then
        # Extract repository name from filename
        filename=$(basename "$json_file" .json)
        repo_name="${filename//-/\/}"

        # Count issues by severity using jq if available, otherwise use grep
        if command -v jq &> /dev/null; then
            total=$(jq '. | length' "$json_file" 2>/dev/null || echo "0")
            critical=$(jq '[.[] | select(.severity == "CRITICAL")] | length' "$json_file" 2>/dev/null || echo "0")
            high=$(jq '[.[] | select(.severity == "HIGH")] | length' "$json_file" 2>/dev/null || echo "0")
            medium=$(jq '[.[] | select(.severity == "MEDIUM")] | length' "$json_file" 2>/dev/null || echo "0")
            low=$(jq '[.[] | select(.severity == "LOW")] | length' "$json_file" 2>/dev/null || echo "0")
        else
            # Fallback to text file parsing
            txt_file="${json_file%.json}.txt"
            total=$(grep -c "Rule:" "$txt_file" 2>/dev/null || echo "0")
            critical=$(grep -c "CRITICAL:" "$txt_file" 2>/dev/null || echo "0")
            high=$(grep -c "HIGH:" "$txt_file" 2>/dev/null || echo "0")
            medium=$(grep -c "MEDIUM:" "$txt_file" 2>/dev/null || echo "0")
            low=$(grep -c "LOW:" "$txt_file" 2>/dev/null || echo "0")
        fi

        # Determine status
        if [ "$critical" -gt 0 ]; then
            status="✗ Critical"
        elif [ "$high" -gt 0 ]; then
            status="✗ High"
        elif [ "$total" -gt 0 ]; then
            status="✗ Issues Found"
        else
            status="✓ Clean"
        fi

        # Add row to table
        echo "| $repo_name | $total | $critical | $high | $medium | $low | $status |" >> "$REPORT_FILE"
    fi
done

# Add issue breakdown section
cat >> "$REPORT_FILE" <<'BREAKDOWN_HEADER'

## Issue Breakdown

### Issues by Rule Type

| Rule ID | Description | Severity | Count | CWE |
|---------|-------------|----------|-------|-----|
BREAKDOWN_HEADER

# Create a temporary file to aggregate rule counts
TEMP_RULES=$(mktemp)

# Process all text files to count issues by rule
for txt_file in scan-results/*.txt; do
    if [ -f "$txt_file" ]; then
        # Extract rule information
        grep -A1 "Rule:" "$txt_file" | grep -v "^--$" >> "$TEMP_RULES" 2>/dev/null || true
    fi
done

# Count and display unique rules
if [ -s "$TEMP_RULES" ]; then
    # Parse rules (simplified version)
    echo "| CRYPTO001 | MD5 usage for security purposes | HIGH | - | CWE-328 |" >> "$REPORT_FILE"
    echo "| CRYPTO002 | SHA1 usage for security purposes | HIGH | - | CWE-328 |" >> "$REPORT_FILE"
    echo "| CRYPTO010 | Hardcoded cryptographic key | CRITICAL | - | CWE-321 |" >> "$REPORT_FILE"
    echo "| CRYPTO020 | Static IV/nonce detected | CRITICAL | - | CWE-329 |" >> "$REPORT_FILE"
    echo "| CRYPTO040 | Quantum-vulnerable algorithm | MEDIUM | - | CWE-327 |" >> "$REPORT_FILE"
fi

rm -f "$TEMP_RULES"

# Add recommendations section
cat >> "$REPORT_FILE" <<'RECOMMENDATIONS'

## Recommendations

### Critical Actions Required

1. **Immediate Review**: All CRITICAL severity issues should be reviewed immediately
2. **Remediation Plan**: Create tickets for HIGH severity issues
3. **Security Best Practices**:
   - Never hardcode cryptographic keys
   - Use crypto/rand for IV/nonce generation
   - Replace MD5/SHA1 with SHA-256 or stronger
   - Consider post-quantum cryptography for long-term secrets

### Next Steps

- [ ] Review all CRITICAL findings
- [ ] Patch hardcoded keys immediately
- [ ] Update cryptographic algorithms
- [ ] Implement secure key management
- [ ] Run follow-up scan after remediation

## Resources

- [CryptoGuard-Go Documentation](https://github.com/ravisastryk/cryptoguard-go)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Go Crypto Best Practices](https://golang.org/pkg/crypto/)

---

*Report generated by CryptoGuard-Go - Automated Cryptographic Vulnerability Scanner*
*For questions or issues, please visit: https://github.com/ravisastryk/cryptoguard-go/issues*
RECOMMENDATIONS

echo "[OK] Summary report generated: $REPORT_FILE"

# Generate detailed remediation guide
echo ""
echo "Generating detailed remediation guide..."

REMEDIATION_FILE="reports/detailed-remediation.md"

cat > "$REMEDIATION_FILE" <<REMEDIATION_HEADER
# CryptoGuard-Go Detailed Remediation Guide

**Generated:** $(date +"%Y-%m-%d")

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

REMEDIATION_HEADER

# Add repository-specific remediation details
echo "" >> "$REMEDIATION_FILE"
echo "## Repository-Specific Findings" >> "$REMEDIATION_FILE"
echo "" >> "$REMEDIATION_FILE"

# Process each text result file for detailed findings
for txt_file in scan-results/*.txt; do
    if [ -f "$txt_file" ]; then
        filename=$(basename "$txt_file" .txt)
        repo_name="${filename//-/\/}"
        repo_anchor=$(echo "$filename" | tr '[:upper:]' '[:lower:]')

        # Count issues by severity
        total=$(grep -c "Rule:" "$txt_file" 2>/dev/null || echo "0")

        if [ "$total" -gt 0 ]; then
            # Add anchor for linking from README
            echo "<a name=\"$repo_anchor\"></a>" >> "$REMEDIATION_FILE"
            echo "" >> "$REMEDIATION_FILE"
            echo "### Repository: $repo_name" >> "$REMEDIATION_FILE"
            echo "" >> "$REMEDIATION_FILE"
            echo "**Total Issues:** $total" >> "$REMEDIATION_FILE"

            # Count by severity (ensure single value)
            critical=$(grep -c "CRITICAL:" "$txt_file" 2>/dev/null | head -1)
            high=$(grep -c "HIGH:" "$txt_file" 2>/dev/null | head -1)
            medium=$(grep -c "MEDIUM:" "$txt_file" 2>/dev/null | head -1)
            low=$(grep -c "LOW:" "$txt_file" 2>/dev/null | head -1)

            # Default to 0 if empty
            critical=${critical:-0}
            high=${high:-0}
            medium=${medium:-0}
            low=${low:-0}

            echo "**Breakdown:** $critical Critical, $high High, $medium Medium, $low Low" >> "$REMEDIATION_FILE"
            echo "" >> "$REMEDIATION_FILE"

            # Extract issues with code pointers (showing actual file:line)
            echo "#### Code Locations:" >> "$REMEDIATION_FILE"
            echo "" >> "$REMEDIATION_FILE"
            echo "| Severity | Rule | File:Line | Description |" >> "$REMEDIATION_FILE"
            echo "|----------|------|-----------|-------------|" >> "$REMEDIATION_FILE"

            # Parse each issue and format as table row
            grep -A3 "Rule:" "$txt_file" 2>/dev/null | while IFS= read -r line; do
                if [[ $line =~ ^(CRITICAL|HIGH|MEDIUM|LOW): ]]; then
                    severity=$(echo "$line" | cut -d: -f1)
                    message=$(echo "$line" | cut -d: -f2- | xargs)
                    # Read next 3 lines for Rule, File, Fix
                    read -r rule_line
                    read -r file_line
                    read -r fix_line

                    rule=$(echo "$rule_line" | sed 's/.*Rule: \([^ ]*\).*/\1/')
                    file=$(echo "$file_line" | sed 's/.*File: //' | sed 's|.*/temp-scan-[^/]*/||')

                    if [ "$file" != "-" ] && [ -n "$file" ]; then
                        # Clean up file path
                        clean_file=$(echo "$file" | sed 's|^/.*github.com/[^/]*/[^/]*/||')
                        echo "| $severity | $rule | \`$clean_file\` | $message |" >> "$REMEDIATION_FILE"
                    fi
                fi
            done | head -10  # Show top 10 issues per repo

            echo "" >> "$REMEDIATION_FILE"
            echo "**Recommended Actions:**" >> "$REMEDIATION_FILE"

            # Add specific recommendations based on what we found
            if [ "$critical" -gt 0 ] || [ "$high" -gt 0 ]; then
                echo "1. Address HIGH/CRITICAL issues immediately" >> "$REMEDIATION_FILE"
            fi
            if grep -q "CRYPTO001" "$txt_file"; then
                echo "2. Replace MD5 with SHA-256: \`find . -name \"*.go\" -exec sed -i 's/crypto\/md5/crypto\/sha256/g' {} \\;\`" >> "$REMEDIATION_FILE"
            fi
            if grep -q "CRYPTO002" "$txt_file"; then
                echo "3. Replace SHA-1 with SHA-256: \`find . -name \"*.go\" -exec sed -i 's/crypto\/sha1/crypto\/sha256/g' {} \\;\`" >> "$REMEDIATION_FILE"
            fi
            if grep -q "CRYPTO040" "$txt_file"; then
                echo "4. Consider post-quantum migration planning (informational)" >> "$REMEDIATION_FILE"
            fi

            echo "" >> "$REMEDIATION_FILE"
            echo "---" >> "$REMEDIATION_FILE"
            echo "" >> "$REMEDIATION_FILE"
        fi
    fi
done

# Add fix examples
cat >> "$REMEDIATION_FILE" <<'FIX_EXAMPLES'

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
FIX_EXAMPLES

echo "[OK] Detailed remediation guide generated: $REMEDIATION_FILE"

# Display the report
echo ""
echo "Preview:"
echo "========================================"
head -50 "$REPORT_FILE"
echo "========================================"
echo ""
echo "Full report saved to: $REPORT_FILE"
