package reporter

import (
	"bytes"
	"encoding/json"
	"go/token"
	"strings"
	"testing"

	"github.com/ravisastryk/cryptoguard-go/pkg/analyzer"
)

func sample() []analyzer.Finding {
	return []analyzer.Finding{
		{RuleID: "CRYPTO001", Category: "weak-algorithm", Severity: analyzer.SeverityHigh,
			Message: "MD5 is broken", Position: token.Position{Filename: "main.go", Line: 10, Column: 5},
			CWE: "CWE-328", Fix: "Use SHA-256"},
		{RuleID: "CRYPTO010", Category: "key-management", Severity: analyzer.SeverityCritical,
			Message: "Hardcoded key", Position: token.Position{Filename: "crypto.go", Line: 42, Column: 8},
			CWE: "CWE-321", Fix: "Use env vars"},
	}
}

func TestNew(t *testing.T) {
	for _, f := range []string{"text", "json", "sarif", "xml"} {
		if r := New(f); r == nil || r.format != f {
			t.Errorf("New(%q)", f)
		}
	}
}

func TestText_Empty(t *testing.T) {
	var b bytes.Buffer
	New("text").Report(nil, &b)
	if !strings.Contains(b.String(), "No issues found") {
		t.Error("missing empty msg")
	}
}

func TestText_Content(t *testing.T) {
	var b bytes.Buffer
	New("text").Report(sample(), &b)
	for _, w := range []string{"CRYPTO001", "CWE-328", "main.go", "CRYPTO010", "2 issue(s) found"} {
		if !strings.Contains(b.String(), w) {
			t.Errorf("missing %q", w)
		}
	}
}

func TestText_Severity(t *testing.T) {
	var b bytes.Buffer
	New("text").Report(sample(), &b)
	if !strings.Contains(b.String(), "HIGH") || !strings.Contains(b.String(), "CRITICAL") {
		t.Error("missing severity")
	}
}

func TestText_Fix(t *testing.T) {
	var b bytes.Buffer
	New("text").Report(sample(), &b)
	if !strings.Contains(b.String(), "Use SHA-256") {
		t.Error("missing fix")
	}
}

func TestJSON_Empty(t *testing.T) {
	var b bytes.Buffer
	New("json").Report(nil, &b)
	s := strings.TrimSpace(b.String())
	if s != "null" && s != "[]" {
		t.Errorf("empty = %q", s)
	}
}

func TestJSON_Valid(t *testing.T) {
	var b bytes.Buffer
	New("json").Report(sample(), &b)
	if !json.Valid(b.Bytes()) {
		t.Error("invalid")
	}
}

func TestJSON_Count(t *testing.T) {
	var b bytes.Buffer
	New("json").Report(sample(), &b)
	var items []map[string]interface{}
	json.Unmarshal(b.Bytes(), &items)
	if len(items) != 2 {
		t.Errorf("got %d", len(items))
	}
}

func TestJSON_Fields(t *testing.T) {
	var b bytes.Buffer
	New("json").Report(sample(), &b)
	var items []map[string]interface{}
	json.Unmarshal(b.Bytes(), &items)
	for _, f := range []string{"rule_id", "category", "severity", "message", "cwe"} {
		if _, ok := items[0][f]; !ok {
			t.Errorf("missing %q", f)
		}
	}
}

func TestSARIF_Valid(t *testing.T) {
	var b bytes.Buffer
	New("sarif").Report(sample(), &b)
	if !json.Valid(b.Bytes()) {
		t.Error("invalid")
	}
}

func TestSARIF_Schema(t *testing.T) {
	var b bytes.Buffer
	New("sarif").Report(sample(), &b)
	if !strings.Contains(b.String(), "sarif-schema") {
		t.Error("missing schema")
	}
}

func TestSARIF_Version(t *testing.T) {
	var b bytes.Buffer
	New("sarif").Report(sample(), &b)
	if !strings.Contains(b.String(), "2.1.0") {
		t.Error("missing version")
	}
}

func TestSARIF_Tool(t *testing.T) {
	var b bytes.Buffer
	New("sarif").Report(sample(), &b)
	if !strings.Contains(b.String(), "cryptoguard-go") {
		t.Error("missing tool")
	}
}

func TestSARIF_Results(t *testing.T) {
	var b bytes.Buffer
	New("sarif").Report(sample(), &b)
	var s map[string]interface{}
	json.Unmarshal(b.Bytes(), &s)
	runs := s["runs"].([]interface{})
	results := runs[0].(map[string]interface{})["results"].([]interface{})
	if len(results) != 2 {
		t.Errorf("results = %d", len(results))
	}
}

func TestSARIF_ErrorLevel(t *testing.T) {
	var b bytes.Buffer
	New("sarif").Report(sample(), &b)
	if !strings.Contains(b.String(), `"level": "error"`) {
		t.Error("CRITICAL should be error")
	}
}

func TestUnknown_Fallback(t *testing.T) {
	var b bytes.Buffer
	New("xml").Report(sample(), &b)
	if !strings.Contains(b.String(), "CRYPTO001") {
		t.Error("should fall back to text")
	}
}
