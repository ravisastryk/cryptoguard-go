// Package main provides the command-line interface for CryptoGuard-Go.
// CryptoGuard-Go is a static analysis tool that detects cryptographic vulnerabilities
// in Go codebases including weak algorithms, hardcoded keys, IV misuse, and
// post-quantum vulnerabilities.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ravisastryk/cryptoguard-go/pkg/analyzer"
	"github.com/ravisastryk/cryptoguard-go/pkg/reporter"
	"github.com/ravisastryk/cryptoguard-go/pkg/rules"
)

var (
	version = "0.1.0"

	outputFormat = flag.String("format", "text", "Output format: text, json, sarif")
	severity     = flag.String("severity", "low", "Minimum severity: low, medium, high, critical")
	showVersion  = flag.Bool("version", false, "Show version")
	verbose      = flag.Bool("verbose", false, "Verbose output")
	showRules    = flag.Bool("rules", false, "List all available rules")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "CryptoGuard-Go v%s\n", version)
		fmt.Fprintf(os.Stderr, "A cryptographic misuse detection tool for Go\n\n")
		fmt.Fprintf(os.Stderr, "Usage: cryptoguard [flags] <package-path>\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  cryptoguard ./...                    # Scan current project\n")
		fmt.Fprintf(os.Stderr, "  cryptoguard -format sarif ./...      # Output SARIF\n")
		fmt.Fprintf(os.Stderr, "  cryptoguard -severity high ./...     # Only high+ severity\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("cryptoguard version %s\n", version)
		os.Exit(0)
	}
	if *showRules {
		printRules()
		os.Exit(0)
	}
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	config := analyzer.Config{
		MinSeverity: parseSeverity(*severity),
		Verbose:     *verbose,
	}

	a, err := analyzer.New(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing analyzer: %v\n", err)
		os.Exit(1)
	}

	// Set all available rules
	a.SetRules(rules.All())

	findings, err := a.Analyze(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing package: %v\n", err)
		os.Exit(1)
	}

	rep := reporter.New(*outputFormat)
	rep.Report(findings, os.Stdout)

	if len(findings) > 0 {
		os.Exit(1)
	}
}

// parseSeverity converts a string severity level to an analyzer.Severity value.
// Valid values are "low", "medium", "high", and "critical". Defaults to low.
func parseSeverity(s string) analyzer.Severity {
	switch s {
	case "critical":
		return analyzer.SeverityCritical
	case "high":
		return analyzer.SeverityHigh
	case "medium":
		return analyzer.SeverityMedium
	default:
		return analyzer.SeverityLow
	}
}

// printRules displays all available security rules with their IDs, severity levels, and descriptions.
func printRules() {
	fmt.Println("CryptoGuard-Go Rules")
	fmt.Println("====================")
	fmt.Println()
	fmt.Println("Weak Algorithms:")
	fmt.Println("  CRYPTO001  HIGH      MD5 usage for security purposes")
	fmt.Println("  CRYPTO002  HIGH      SHA1 usage for security purposes")
	fmt.Println("  CRYPTO003  CRITICAL  DES/3DES encryption")
	fmt.Println("  CRYPTO004  HIGH      RC4 stream cipher")
	fmt.Println()
	fmt.Println("Key Management:")
	fmt.Println("  CRYPTO010  CRITICAL  Hardcoded cryptographic key")
	fmt.Println("  CRYPTO011  HIGH      Insufficient key length")
	fmt.Println()
	fmt.Println("IV/Nonce Issues:")
	fmt.Println("  CRYPTO020  CRITICAL  Static IV/nonce")
	fmt.Println("  CRYPTO021  CRITICAL  IV/nonce reuse")
	fmt.Println()
	fmt.Println("Timing Attacks:")
	fmt.Println("  CRYPTO030  MEDIUM    Non-constant-time comparison")
	fmt.Println()
	fmt.Println("Post-Quantum (NOVEL):")
	fmt.Println("  CRYPTO040  MEDIUM    Quantum-vulnerable algorithm")
	fmt.Println()
	fmt.Println("Advanced (NOVEL):")
	fmt.Println("  CRYPTO050  CRITICAL  Cross-function IV reuse")
}
