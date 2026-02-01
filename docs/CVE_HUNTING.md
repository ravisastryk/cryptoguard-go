# CVE Hunting Guide

Use CryptoGuard-Go to find real vulnerabilities and get CVE credit.

## 1. Select Targets

**Tier 1 (maximum impact):** Authentication libraries, password hashing,
TLS implementations, key management systems.

**Tier 2:** Database encryption, file encryption, API middleware, session
management.

### Finding Targets

```
GitHub search: "crypto/aes" language:go stars:>100
GitHub search: "crypto/md5" language:go stars:>50
GitHub search: "jwt" "golang" language:go stars:>500
```

## 2. Run CryptoGuard

```bash
git clone https://github.com/target/project && cd project
cryptoguard ./...
cryptoguard -format json ./... > findings.json
```

## 3. Validate Findings

- Is the code reachable by attackers?
- Is it used in a security context?  (MD5 for checksums is acceptable.)
- Can you demonstrate impact?

## 4. Responsible Disclosure

```
Subject: Security Vulnerability in [Project] — Cryptographic Misuse

## Summary
[one-liner]

## Vulnerability Details
- Type: [CWE-XXX]
- Location: [file:line]
- Severity: [Critical/High/Medium/Low]
- Tool: CryptoGuard-Go

## Impact
[what an attacker could do]

## Remediation
[suggested fix with code]

## Credit
I request credit as the discoverer if a CVE is assigned.
```

## 5. Request CVE

- **Option A:** Ask maintainer via GitHub Security Advisories.
- **Option B:** Submit to MITRE: https://cveform.mitre.org/
- **Option C:** Through a CNA (Google, Microsoft, Red Hat, GitHub).

## Timeline

| Stage | Time |
|-------|------|
| Ack | 1-3 days |
| Assessment | 1-2 weeks |
| Fix | 2-4 weeks |
| Disclosure | 90 days |
