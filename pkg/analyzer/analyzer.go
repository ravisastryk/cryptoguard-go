// Package analyzer provides static analysis capabilities for detecting
// cryptographic vulnerabilities in Go code. It orchestrates the execution
// of security rules and manages analysis configuration.
package analyzer

import (
	"fmt"
	"go/token"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Severity represents the severity level of a security finding.
// Severity levels are aligned with CVSS scoring.
type Severity int

const (
	// SeverityLow indicates a low-severity issue that should be reviewed.
	SeverityLow Severity = iota

	// SeverityMedium indicates a moderate security concern.
	SeverityMedium

	// SeverityHigh indicates a serious security vulnerability.
	SeverityHigh

	// SeverityCritical indicates a critical security flaw requiring immediate attention.
	SeverityCritical
)

// String returns the string representation of the severity level.
func (s Severity) String() string {
	return []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}[s]
}

// Finding represents a detected cryptographic issue in the analyzed code.
type Finding struct {
	// RuleID is the unique identifier for the rule that detected this issue.
	RuleID string

	// Category classifies the type of vulnerability (e.g., "weak-algorithm").
	Category string

	// Severity indicates the severity level of this finding.
	Severity Severity

	// Message is a human-readable description of the issue.
	Message string

	// Description provides additional context about the vulnerability.
	Description string

	// Position specifies the source location where the issue was found.
	Position token.Position

	// CWE is the Common Weakness Enumeration identifier.
	CWE string

	// Fix suggests how to remediate the issue.
	Fix string

	// Confidence indicates how certain we are about this finding (0.0-1.0).
	Confidence float64

	// CodeSnippet contains the relevant source code (if available).
	CodeSnippet string
}

// Config holds analyzer configuration options.
type Config struct {
	// MinSeverity filters findings below this severity level.
	MinSeverity Severity

	// EnabledRules specifies which rules to run (empty = all rules).
	EnabledRules []string

	// DisabledRules specifies rules to skip.
	DisabledRules []string

	// Verbose enables detailed logging during analysis.
	Verbose bool
}

// Rule defines the interface for a cryptographic security check.
// Each rule implements detection logic for a specific vulnerability pattern.
type Rule interface {
	// ID returns the unique identifier for this rule (e.g., "CRYPTO001").
	ID() string

	// Category returns the category this rule belongs to.
	Category() string

	// Description returns a human-readable description of what this rule detects.
	Description() string

	// Severity returns the severity level for findings from this rule.
	Severity() Severity

	// CWE returns the Common Weakness Enumeration identifier.
	CWE() string

	// Check analyzes the given function and returns any findings.
	Check(fn *ssa.Function, prog *ssa.Program) []Finding
}

// Analyzer is the main analysis engine that orchestrates rule execution.
type Analyzer struct {
	// config holds the analyzer configuration.
	config Config

	// rules contains all registered security rules.
	rules []Rule

	// fset is the file set for tracking source positions.
	fset *token.FileSet

	// disabledRulesMap provides O(1) lookup for disabled rules.
	disabledRulesMap map[string]bool

	// enabledRulesMap provides O(1) lookup for enabled rules.
	enabledRulesMap map[string]bool
}

// New creates a new Analyzer instance with an empty rule set.
// Use SetRules to configure which rules to run, or use NewWithDefaultRules
// for the default rule set.
func New(config Config) (*Analyzer, error) {
	// Build maps for O(1) rule lookup
	disabledMap := make(map[string]bool, len(config.DisabledRules))
	for _, id := range config.DisabledRules {
		disabledMap[id] = true
	}

	enabledMap := make(map[string]bool, len(config.EnabledRules))
	for _, id := range config.EnabledRules {
		enabledMap[id] = true
	}

	return &Analyzer{
		config:           config,
		fset:             token.NewFileSet(),
		rules:            []Rule{},
		disabledRulesMap: disabledMap,
		enabledRulesMap:  enabledMap,
	}, nil
}

// SetRules sets the rules to be used by the analyzer.
// This allows for custom rule sets and better testability.
func (a *Analyzer) SetRules(rules []Rule) {
	a.rules = rules
}

// Analyze runs all enabled security rules against the specified package pattern.
// The pattern follows Go package path conventions (e.g., "./...", "mypackage").
// It returns all findings that meet the minimum severity threshold.
func (a *Analyzer) Analyze(pattern string) ([]Finding, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo,
		Fset: a.fset,
	}
	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, fmt.Errorf("loading packages: %w", err)
	}

	// Check for package loading errors
	var hasErrors bool
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			hasErrors = true
			for _, e := range pkg.Errors {
				if a.config.Verbose {
					fmt.Printf("Warning: %v\n", e)
				}
			}
		}
	}
	if hasErrors {
		return nil, fmt.Errorf("package loading failed with errors")
	}

	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.SanityCheckFunctions)
	prog.Build()

	var all []Finding
	for _, sp := range ssaPkgs {
		if sp == nil {
			continue
		}
		all = append(all, a.analyzePackage(sp, prog)...)
	}

	var filtered []Finding
	for _, f := range all {
		if f.Severity >= a.config.MinSeverity {
			filtered = append(filtered, f)
		}
	}
	return filtered, nil
}

// analyzePackage runs all rules against functions in the given SSA package.
// It analyzes both regular functions and anonymous functions.
func (a *Analyzer) analyzePackage(pkg *ssa.Package, prog *ssa.Program) []Finding {
	var findings []Finding
	for _, member := range pkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			findings = append(findings, a.analyzeFunction(fn, prog)...)
			for _, anon := range fn.AnonFuncs {
				findings = append(findings, a.analyzeFunction(anon, prog)...)
			}
		}
	}
	return findings
}

// analyzeFunction runs all enabled rules against a single function.
func (a *Analyzer) analyzeFunction(fn *ssa.Function, prog *ssa.Program) []Finding {
	var findings []Finding
	for _, rule := range a.rules {
		if a.isRuleEnabled(rule.ID()) {
			findings = append(findings, rule.Check(fn, prog)...)
		}
	}
	return findings
}

// isRuleEnabled checks if a rule with the given ID should be executed.
// DisabledRules take precedence over EnabledRules.
// Uses O(1) map lookups for improved performance.
func (a *Analyzer) isRuleEnabled(id string) bool {
	// Check disabled rules first (takes precedence)
	if a.disabledRulesMap[id] {
		return false
	}

	// If enabled rules are specified, only run those
	if len(a.enabledRulesMap) > 0 {
		return a.enabledRulesMap[id]
	}

	// Otherwise, run all rules
	return true
}
