# Contributing to CryptoGuard-Go

Please **open an issue first** before submitting large changes so we can
discuss the approach.

## Development Setup

```bash
git clone https://github.com/ravisastryk/cryptoguard-go
cd cryptoguard-go
go mod download
make build
make test
```

## Adding Rules

See existing rules in `pkg/analyzer/analyzer.go`. Each rule must implement the
`Rule` interface and provide: unique ID (CRYPTOXXX), CWE mapping, clear
description, fix recommendation, and test cases.

## Rule ID Ranges

- `CRYPTO0XX`: Weak algorithms
- `CRYPTO01X`: Key management
- `CRYPTO02X`: IV/nonce issues
- `CRYPTO03X`: Timing attacks
- `CRYPTO04X`: Post-quantum
- `CRYPTO05X`: Advanced/novel

## Code Style

Run `go fmt` and `go vet` before committing. Add tests for new rules.

## License

By contributing, you agree that your contributions will be licensed under
Apache 2.0.
