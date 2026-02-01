// Package rules implements security rules for detecting cryptographic vulnerabilities.
// Each rule checks for specific patterns of cryptographic misuse in Go code.
package rules

import (
	"github.com/ravisastryk/cryptoguard-go/pkg/analyzer"
	"golang.org/x/tools/go/ssa"
)

// MD5Rule detects usage of the MD5 hashing algorithm.
// MD5 is cryptographically broken and should not be used for security purposes.
type MD5Rule struct{}

// ID returns the unique identifier for the MD5 rule.
func (r *MD5Rule) ID() string { return "CRYPTO001" }

// Category returns the category for the MD5 rule.
func (r *MD5Rule) Category() string { return "weak-algorithm" }

// Description returns a description of the MD5 rule.
func (r *MD5Rule) Description() string { return "MD5 is cryptographically broken" }

// Severity returns the severity level for MD5 usage.
func (r *MD5Rule) Severity() analyzer.Severity { return analyzer.SeverityHigh }

// CWE returns the CWE identifier for MD5 usage.
func (r *MD5Rule) CWE() string { return "CWE-328" }

// Check analyzes the function for MD5 usage and returns any findings.
func (r *MD5Rule) Check(fn *ssa.Function, prog *ssa.Program) []analyzer.Finding {
	if fn == nil || fn.Blocks == nil {
		return nil
	}
	var out []analyzer.Finding
	for _, b := range fn.Blocks {
		for _, i := range b.Instrs {
			if c, ok := i.(*ssa.Call); ok {
				if f := c.Call.StaticCallee(); f != nil && f.Pkg != nil && f.Pkg.Pkg.Path() == "crypto/md5" {
					out = append(out, analyzer.Finding{
						RuleID:   r.ID(),
						Category: r.Category(),
						Severity: r.Severity(),
						Message:  "MD5 is cryptographically broken and should not be used for security",
						Position: prog.Fset.Position(c.Pos()),
						CWE:      r.CWE(),
						Fix:      "Use SHA-256 or stronger hash function",
					})
				}
			}
		}
	}
	return out
}

// SHA1Rule detects usage of the SHA-1 hashing algorithm.
// SHA-1 is cryptographically broken and should not be used for security purposes.
type SHA1Rule struct{}

// ID returns the unique identifier for the SHA1 rule.
func (r *SHA1Rule) ID() string { return "CRYPTO002" }

// Category returns the category for the SHA1 rule.
func (r *SHA1Rule) Category() string { return "weak-algorithm" }

// Description returns a description of the SHA1 rule.
func (r *SHA1Rule) Description() string { return "SHA1 is cryptographically broken" }

// Severity returns the severity level for SHA1 usage.
func (r *SHA1Rule) Severity() analyzer.Severity { return analyzer.SeverityHigh }

// CWE returns the CWE identifier for SHA1 usage.
func (r *SHA1Rule) CWE() string { return "CWE-328" }

// Check analyzes the function for SHA1 usage and returns any findings.
func (r *SHA1Rule) Check(fn *ssa.Function, prog *ssa.Program) []analyzer.Finding {
	if fn == nil || fn.Blocks == nil {
		return nil
	}
	var out []analyzer.Finding
	for _, b := range fn.Blocks {
		for _, i := range b.Instrs {
			if c, ok := i.(*ssa.Call); ok {
				if f := c.Call.StaticCallee(); f != nil && f.Pkg != nil && f.Pkg.Pkg.Path() == "crypto/sha1" {
					out = append(out, analyzer.Finding{
						RuleID:   r.ID(),
						Category: r.Category(),
						Severity: r.Severity(),
						Message:  "SHA1 is cryptographically broken and should not be used for security",
						Position: prog.Fset.Position(c.Pos()),
						CWE:      r.CWE(),
						Fix:      "Use SHA-256 or stronger hash function",
					})
				}
			}
		}
	}
	return out
}

// HardcodedKeyRule detects hardcoded cryptographic keys in the source code.
// Hardcoded keys are a critical security vulnerability.
type HardcodedKeyRule struct{}

// ID returns the unique identifier for the HardcodedKey rule.
func (r *HardcodedKeyRule) ID() string { return "CRYPTO010" }

// Category returns the category for the HardcodedKey rule.
func (r *HardcodedKeyRule) Category() string { return "key-management" }

// Description returns a description of the HardcodedKey rule.
func (r *HardcodedKeyRule) Description() string { return "Hardcoded cryptographic key" }

// Severity returns the severity level for hardcoded keys.
func (r *HardcodedKeyRule) Severity() analyzer.Severity { return analyzer.SeverityCritical }

// CWE returns the CWE identifier for hardcoded keys.
func (r *HardcodedKeyRule) CWE() string { return "CWE-321" }

// Check analyzes the function for hardcoded cryptographic keys and returns any findings.
func (r *HardcodedKeyRule) Check(fn *ssa.Function, prog *ssa.Program) []analyzer.Finding {
	if fn == nil || fn.Blocks == nil {
		return nil
	}
	targets := map[string]bool{
		"crypto/aes.NewCipher":          true,
		"crypto/des.NewCipher":          true,
		"crypto/des.NewTripleDESCipher": true,
	}
	var out []analyzer.Finding
	for _, b := range fn.Blocks {
		for _, i := range b.Instrs {
			if c, ok := i.(*ssa.Call); ok {
				if f := c.Call.StaticCallee(); f != nil && f.Pkg != nil {
					if targets[f.Pkg.Pkg.Path()+"."+f.Name()] && len(c.Call.Args) > 0 {
						if _, isConst := c.Call.Args[0].(*ssa.Const); isConst {
							out = append(out, analyzer.Finding{
								RuleID:   r.ID(),
								Category: r.Category(),
								Severity: r.Severity(),
								Message:  "Cryptographic key appears to be hardcoded",
								Position: prog.Fset.Position(c.Pos()),
								CWE:      r.CWE(),
								Fix:      "Load keys from environment variables or secret management",
							})
						}
					}
				}
			}
		}
	}
	return out
}

// StaticIVRule detects static initialization vectors or nonces in encryption.
// Static IVs break encryption security and allow pattern-based attacks.
type StaticIVRule struct{}

// ID returns the unique identifier for the StaticIV rule.
func (r *StaticIVRule) ID() string { return "CRYPTO020" }

// Category returns the category for the StaticIV rule.
func (r *StaticIVRule) Category() string { return "iv-misuse" }

// Description returns a description of the StaticIV rule.
func (r *StaticIVRule) Description() string { return "Static IV/nonce detected" }

// Severity returns the severity level for static IV usage.
func (r *StaticIVRule) Severity() analyzer.Severity { return analyzer.SeverityCritical }

// CWE returns the CWE identifier for static IV usage.
func (r *StaticIVRule) CWE() string { return "CWE-329" }

// Check analyzes the function for static IV/nonce usage and returns any findings.
func (r *StaticIVRule) Check(fn *ssa.Function, prog *ssa.Program) []analyzer.Finding {
	if fn == nil || fn.Blocks == nil {
		return nil
	}
	ivFuncs := map[string]int{
		"crypto/cipher.NewCBCEncrypter": 1,
		"crypto/cipher.NewCBCDecrypter": 1,
		"crypto/cipher.NewCTR":          1,
		"crypto/cipher.NewOFB":          1,
		"crypto/cipher.NewCFBEncrypter": 1,
	}
	var out []analyzer.Finding
	for _, b := range fn.Blocks {
		for _, i := range b.Instrs {
			if c, ok := i.(*ssa.Call); ok {
				if f := c.Call.StaticCallee(); f != nil && f.Pkg != nil {
					if idx, ok := ivFuncs[f.Pkg.Pkg.Path()+"."+f.Name()]; ok && len(c.Call.Args) > idx {
						if _, isConst := c.Call.Args[idx].(*ssa.Const); isConst {
							out = append(out, analyzer.Finding{
								RuleID:   r.ID(),
								Category: r.Category(),
								Severity: r.Severity(),
								Message:  "Static IV/nonce used — this breaks encryption security",
								Position: prog.Fset.Position(c.Pos()),
								CWE:      r.CWE(),
								Fix:      "Generate IV randomly using crypto/rand",
							})
						}
					}
				}
			}
		}
	}
	return out
}

// PQVulnerableRule detects cryptographic algorithms vulnerable to quantum computing attacks.
// This includes RSA, ECDSA, and ECDH which are susceptible to Shor's algorithm.
type PQVulnerableRule struct{}

// ID returns the unique identifier for the PQVulnerable rule.
func (r *PQVulnerableRule) ID() string { return "CRYPTO040" }

// Category returns the category for the PQVulnerable rule.
func (r *PQVulnerableRule) Category() string { return "post-quantum" }

// Description returns a description of the PQVulnerable rule.
func (r *PQVulnerableRule) Description() string { return "Algorithm vulnerable to quantum attacks" }

// Severity returns the severity level for quantum-vulnerable algorithms.
func (r *PQVulnerableRule) Severity() analyzer.Severity { return analyzer.SeverityMedium }

// CWE returns the CWE identifier for quantum-vulnerable algorithms.
func (r *PQVulnerableRule) CWE() string { return "CWE-327" }

// Check analyzes the function for quantum-vulnerable algorithms and returns any findings.
func (r *PQVulnerableRule) Check(fn *ssa.Function, prog *ssa.Program) []analyzer.Finding {
	if fn == nil || fn.Blocks == nil {
		return nil
	}
	vuln := map[string]string{
		"crypto/rsa":   "RSA is vulnerable to Shor's algorithm",
		"crypto/ecdsa": "ECDSA is vulnerable to quantum attacks",
		"crypto/ecdh":  "ECDH is vulnerable to quantum attacks",
	}
	var out []analyzer.Finding
	for _, b := range fn.Blocks {
		for _, i := range b.Instrs {
			if c, ok := i.(*ssa.Call); ok {
				if f := c.Call.StaticCallee(); f != nil && f.Pkg != nil {
					if msg, v := vuln[f.Pkg.Pkg.Path()]; v {
						out = append(out, analyzer.Finding{
							RuleID:   r.ID(),
							Category: r.Category(),
							Severity: r.Severity(),
							Message:  msg,
							Position: prog.Fset.Position(c.Pos()),
							CWE:      r.CWE(),
							Fix:      "Consider hybrid approach with ML-KEM (FIPS 203) for future-proofing",
						})
					}
				}
			}
		}
	}
	return out
}

// All returns all available security rules.
func All() []analyzer.Rule {
	return []analyzer.Rule{
		&MD5Rule{},
		&SHA1Rule{},
		&HardcodedKeyRule{},
		&StaticIVRule{},
		&PQVulnerableRule{},
	}
}
