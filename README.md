# CryptoGuard-Go

[![Go Report Card](https://goreportcard.com/badge/github.com/ravisastryk/cryptoguard-go)](https://goreportcard.com/report/github.com/ravisastryk/cryptoguard-go)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**CryptoGuard-Go** is a cryptographic misuse detection tool for Go. It uses
static analysis to find security vulnerabilities in cryptographic code:

- Weak algorithm detection (MD5, SHA1, DES, RC4)
- Hardcoded cryptographic keys
- Static/predictable IV/nonce detection
- Timing side-channel vulnerabilities
- Post-quantum readiness assessment (novel)
- Cross-function IV reuse detection (novel)

## Comparison

| Feature | gosec | semgrep | CryptoGuard-Go |
|---------|-------|---------|----------------|
| Taint analysis | Yes | No | Yes |
| Context-aware detection | No | No | Yes |
| Post-quantum scanning | No | No | Yes |
| Cross-function tracking | No | No | Yes |
| SARIF output | Yes | Yes | Yes |
| CWE mapping | Partial | Partial | Full |

Note: gosec (v2.22+) includes taint analysis via AST and SSA inspection.
CryptoGuard-Go extends this with crypto-specific taint tracking for IV/key
material propagation across function boundaries and post-quantum readiness
scanning.

## Installation

```bash
go install github.com/ravisastryk/cryptoguard-go/cmd/cryptoguard@latest
```

## Quick Start

```bash
# Scan current project
cryptoguard ./...

# Only high+ severity
cryptoguard -severity high ./...

# Output SARIF for GitHub Security tab
cryptoguard -format sarif ./... > results.sarif
```

## Example Output

```
CRITICAL: Hardcoded cryptographic key detected
  Rule: CRYPTO010 (CWE-321)
  File: crypto/encrypt.go:42
  Fix: Load keys from environment variables or secret management service

HIGH: MD5 used for security purposes
  Rule: CRYPTO001 (CWE-328)
  File: auth/password.go:28
  Fix: Use SHA-256 or bcrypt/argon2 for password hashing
```

## Rules

| ID | Category | Severity | Description |
|----|----------|----------|-------------|
| CRYPTO001 | weak-algorithm | HIGH | MD5 usage for security |
| CRYPTO002 | weak-algorithm | HIGH | SHA1 usage for security |
| CRYPTO003 | weak-algorithm | CRITICAL | DES/3DES encryption |
| CRYPTO010 | key-management | CRITICAL | Hardcoded keys |
| CRYPTO011 | key-management | HIGH | Insufficient key length |
| CRYPTO020 | iv-misuse | CRITICAL | Static IV/nonce |
| CRYPTO021 | iv-misuse | CRITICAL | IV/nonce reuse |
| CRYPTO030 | timing | MEDIUM | Non-constant-time comparison |
| CRYPTO040 | post-quantum | MEDIUM | Quantum-vulnerable algorithm |
| CRYPTO050 | iv-misuse | CRITICAL | Cross-function IV reuse |

## GitHub Action

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  cryptoguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Install CryptoGuard-Go
        run: go install github.com/ravisastryk/cryptoguard-go/cmd/cryptoguard@latest

      - name: Run CryptoGuard
        run: cryptoguard -format sarif ./... > results.sarif
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

## Academic Background

This tool builds upon and extends:

1. **CryptoGo** (ACSAC 2022) -- Automatic detection of Go cryptographic API misuses
2. **CryptoLint** (CCS 2012) -- First large-scale crypto misuse study
3. **NIST Post-Quantum Standards** (2024) -- FIPS 203, 204, 205

### Novel Contributions

- Post-quantum readiness analysis: first tool to identify quantum-vulnerable crypto in Go.
- Cross-function taint analysis: tracks IV/key material across function boundaries.
- Context-aware detection: reduces false positives by understanding security context.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please open an issue first before
submitting large changes.

## Security

See [SECURITY.md](SECURITY.md). To report a vulnerability, open a GitHub issue
or use GitHub's private vulnerability reporting.

## License

Apache 2.0 -- See [LICENSE](LICENSE)
