// Package reporter provides multiple output formats for security findings.
// It supports text, JSON, and SARIF formats for integration with various tools and workflows.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ravisastryk/cryptoguard-go/pkg/analyzer"
)

// Reporter formats and outputs security findings in various formats.
type Reporter struct {
	// format specifies the output format (text, json, or sarif).
	format string
}

// New creates a new Reporter with the specified output format.
// Supported formats are "text", "json", and "sarif".
func New(format string) *Reporter { return &Reporter{format: format} }

// Report writes the findings to the given writer in the configured format.
// It automatically selects the appropriate formatter based on the Reporter's format setting.
func (r *Reporter) Report(findings []analyzer.Finding, w io.Writer) {
	switch r.format {
	case "json":
		r.reportJSON(findings, w)
	case "sarif":
		r.reportSARIF(findings, w)
	default:
		r.reportText(findings, w)
	}
}

// reportText outputs findings in a human-readable text format.
// It displays severity, message, rule ID, CWE, file location, and suggested fixes.
func (r *Reporter) reportText(findings []analyzer.Finding, w io.Writer) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No issues found.")
		return
	}
	for i, f := range findings {
		fmt.Fprintf(w, "%s: %s\n  Rule: %s (%s)\n  File: %s\n", f.Severity, f.Message, f.RuleID, f.CWE, f.Position)
		if f.Fix != "" {
			fmt.Fprintf(w, "  Fix: %s\n", f.Fix)
		}
		if i < len(findings)-1 {
			fmt.Fprintln(w, strings.Repeat("-", 60))
		}
	}
	fmt.Fprintf(w, "\n%d issue(s) found\n", len(findings))
}

// reportJSON outputs findings in JSON format for machine-readable consumption.
// Each finding includes rule ID, category, severity, location, CWE, and fix suggestions.
func (r *Reporter) reportJSON(findings []analyzer.Finding, w io.Writer) {
	type jf struct {
		RuleID     string  `json:"rule_id"`
		Category   string  `json:"category"`
		Severity   string  `json:"severity"`
		Message    string  `json:"message"`
		File       string  `json:"file"`
		Line       int     `json:"line"`
		Column     int     `json:"column"`
		CWE        string  `json:"cwe"`
		Fix        string  `json:"fix,omitempty"`
		Confidence float64 `json:"confidence,omitempty"`
	}
	out := make([]jf, len(findings))
	for i, f := range findings {
		out[i] = jf{f.RuleID, f.Category, f.Severity.String(), f.Message,
			f.Position.Filename, f.Position.Line, f.Position.Column, f.CWE, f.Fix, f.Confidence}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

// reportSARIF outputs findings in SARIF v2.1.0 format for integration with
// CI/CD systems and security platforms like GitHub Code Scanning.
func (r *Reporter) reportSARIF(findings []analyzer.Finding, w io.Writer) {
	type msg struct {
		Text string `json:"text"`
	}
	type al struct {
		URI string `json:"uri"`
	}
	type rg struct{ StartLine, StartColumn int }
	type pl struct {
		ArtifactLocation al `json:"artifactLocation"`
		Region           rg `json:"region"`
	}
	type loc struct {
		PhysicalLocation pl `json:"physicalLocation"`
	}
	type res struct {
		RuleID    string `json:"ruleId"`
		Level     string `json:"level"`
		Message   msg    `json:"message"`
		Locations []loc  `json:"locations"`
	}
	type sd struct {
		Text string `json:"text"`
	}
	type rl struct {
		ID               string `json:"id"`
		ShortDescription sd     `json:"shortDescription"`
	}
	type dr struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Rules   []rl   `json:"rules,omitempty"`
	}
	type tl struct {
		Driver dr `json:"driver"`
	}
	type rn struct {
		Tool    tl    `json:"tool"`
		Results []res `json:"results"`
	}
	type sf struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []rn   `json:"runs"`
	}

	rm := map[string]bool{}
	var rules []rl
	for _, f := range findings {
		if !rm[f.RuleID] {
			rm[f.RuleID] = true
			rules = append(rules, rl{f.RuleID, sd{f.Message}})
		}
	}
	var results []res
	for _, f := range findings {
		lv := "warning"
		if f.Severity >= analyzer.SeverityHigh {
			lv = "error"
		}
		results = append(results, res{f.RuleID, lv, msg{f.Message}, []loc{{pl{al{f.Position.Filename}, rg{f.Position.Line, f.Position.Column}}}}})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(sf{
		"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"2.1.0", []rn{{tl{dr{"cryptoguard-go", "0.1.0", rules}}, results}},
	})
}
