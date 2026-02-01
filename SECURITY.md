# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |
| < latest| No        |

We apply security fixes to the latest release only. Users should upgrade promptly.

## Reporting a Vulnerability

### Step 1 — Open a GitHub Issue (preferred)

Open an issue at <https://github.com/ravisastryk/cryptoguard-go/issues> using the
**Security vulnerability** template. If the issue can be described without
disclosing exploit details, a public issue is fine and helps the community track
progress.

### Step 2 — Private Disclosure (sensitive issues only)

If the vulnerability could be exploited before a fix is available, use GitHub's
**Private vulnerability reporting** feature:

1. Navigate to the repository **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the advisory form.

GitHub notifies the maintainers directly and keeps the report confidential until
a fix is released. See [GitHub docs][gh-pvr] for details.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability

### What to Include

- A clear description of the vulnerability.
- Steps to reproduce or a minimal proof of concept.
- Affected version(s) and configuration.
- Potential impact (data disclosure, denial of service, etc.).
- Suggested fix, if any.

### What to Expect

| Stage               | Time          |
|----------------------|---------------|
| Acknowledgment       | 3 business days |
| Initial assessment   | 1 week        |
| Fix or mitigation    | 2-4 weeks     |
| Public disclosure    | Coordinated, typically within 90 days |

We will keep you informed as the issue moves through triage, fix, and release.
If a CVE is assigned, you will be credited as the discoverer unless you request
otherwise.

## Scope

This policy covers the CryptoGuard-Go tool and its published packages,
official documentation, and example code in this repository.

Out of scope: vulnerabilities in third-party dependencies (report upstream) and
vulnerabilities found *by* this tool in other projects (report to those projects;
see [docs/CVE_HUNTING.md](docs/CVE_HUNTING.md) for responsible disclosure guidance).

## Disclosure Policy

We follow coordinated disclosure. Please do not file public exploits or blog
posts before a fix is released. Security fixes are released as patch versions
and announced in GitHub Releases.
