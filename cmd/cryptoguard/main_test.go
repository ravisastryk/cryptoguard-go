package main

import (
	"testing"

	"github.com/ravisastryk/cryptoguard-go/pkg/analyzer"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  analyzer.Severity
	}{
		{"critical", analyzer.SeverityCritical},
		{"high", analyzer.SeverityHigh},
		{"medium", analyzer.SeverityMedium},
		{"low", analyzer.SeverityLow},
		{"", analyzer.SeverityLow},
		{"unknown", analyzer.SeverityLow},
	}
	for _, tt := range tests {
		if got := parseSeverity(tt.input); got != tt.want {
			t.Errorf("parseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
