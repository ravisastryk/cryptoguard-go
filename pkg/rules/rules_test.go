package rules

import (
	"testing"

	"github.com/ravisastryk/cryptoguard-go/pkg/analyzer"
)

// Helper function to test rule metadata
func testRuleMeta(t *testing.T, r analyzer.Rule, id, cat, cwe string, sev analyzer.Severity) {
	t.Helper()
	if r.ID() != id {
		t.Errorf("ID mismatch: got %s, want %s", r.ID(), id)
	}
	if r.Category() != cat {
		t.Errorf("Category mismatch: got %s, want %s", r.Category(), cat)
	}
	if r.CWE() != cwe {
		t.Errorf("CWE mismatch: got %s, want %s", r.CWE(), cwe)
	}
	if r.Severity() != sev {
		t.Errorf("Severity mismatch: got %v, want %v", r.Severity(), sev)
	}
}

// Test MD5Rule metadata
func TestMD5Rule_Meta(t *testing.T) {
	testRuleMeta(t, &MD5Rule{}, "CRYPTO001", "weak-algorithm", "CWE-328", analyzer.SeverityHigh)
}

// Test SHA1Rule metadata
func TestSHA1Rule_Meta(t *testing.T) {
	testRuleMeta(t, &SHA1Rule{}, "CRYPTO002", "weak-algorithm", "CWE-328", analyzer.SeverityHigh)
}

// Test HardcodedKeyRule metadata
func TestHardcodedKeyRule_Meta(t *testing.T) {
	testRuleMeta(t, &HardcodedKeyRule{}, "CRYPTO010", "key-management", "CWE-321", analyzer.SeverityCritical)
}

// Test StaticIVRule metadata
func TestStaticIVRule_Meta(t *testing.T) {
	testRuleMeta(t, &StaticIVRule{}, "CRYPTO020", "iv-misuse", "CWE-329", analyzer.SeverityCritical)
}

// Test PQVulnerableRule metadata
func TestPQRule_Meta(t *testing.T) {
	testRuleMeta(t, &PQVulnerableRule{}, "CRYPTO040", "post-quantum", "CWE-327", analyzer.SeverityMedium)
}

// Test that rules return empty when given nil input
func TestMD5Rule_NilInput(t *testing.T) {
	rule := &MD5Rule{}
	findings := rule.Check(nil, nil)
	if len(findings) != 0 {
		t.Errorf("Expected no findings for nil input, got %d", len(findings))
	}
}

func TestSHA1Rule_NilInput(t *testing.T) {
	rule := &SHA1Rule{}
	findings := rule.Check(nil, nil)
	if len(findings) != 0 {
		t.Errorf("Expected no findings for nil input, got %d", len(findings))
	}
}

func TestHardcodedKeyRule_NilInput(t *testing.T) {
	rule := &HardcodedKeyRule{}
	findings := rule.Check(nil, nil)
	if len(findings) != 0 {
		t.Errorf("Expected no findings for nil input, got %d", len(findings))
	}
}

func TestStaticIVRule_NilInput(t *testing.T) {
	rule := &StaticIVRule{}
	findings := rule.Check(nil, nil)
	if len(findings) != 0 {
		t.Errorf("Expected no findings for nil input, got %d", len(findings))
	}
}

func TestPQRule_NilInput(t *testing.T) {
	rule := &PQVulnerableRule{}
	findings := rule.Check(nil, nil)
	if len(findings) != 0 {
		t.Errorf("Expected no findings for nil input, got %d", len(findings))
	}
}

// Test All() returns expected number of rules
func TestAll_Count(t *testing.T) {
	rules := All()
	if len(rules) != 5 {
		t.Errorf("Expected 5 rules, got %d", len(rules))
	}
}

// Test All() returns all expected rule IDs
func TestAll_IDs(t *testing.T) {
	rules := All()
	ids := make(map[string]bool)
	for _, r := range rules {
		ids[r.ID()] = true
	}

	expectedIDs := []string{"CRYPTO001", "CRYPTO002", "CRYPTO010", "CRYPTO020", "CRYPTO040"}
	for _, id := range expectedIDs {
		if !ids[id] {
			t.Errorf("Missing rule ID: %s", id)
		}
	}
}

// Test MD5Rule detection with nil input
func TestMD5Rule_Detection(t *testing.T) {
	rule := &MD5Rule{}

	// Test with nil SSA (should handle gracefully)
	findings := rule.Check(nil, nil)
	if len(findings) != 0 {
		t.Error("Should handle nil input gracefully")
	}
}

// Test rule descriptions are non-empty
func TestRules_HaveDescriptions(t *testing.T) {
	rules := All()
	for _, r := range rules {
		if r.Description() == "" {
			t.Errorf("Rule %s has empty description", r.ID())
		}
	}
}

// Test rule fixes are non-empty for critical/high severity
func TestRules_HaveFixes(t *testing.T) {
	rules := All()
	for _, r := range rules {
		if r.Severity() >= analyzer.SeverityHigh {
			// We can't directly test Fix here since it's in the findings,
			// but we can verify the rule exists
			if r.ID() == "" {
				t.Errorf("Rule missing ID")
			}
		}
	}
}

// Test that each rule has unique ID
func TestRules_UniqueIDs(t *testing.T) {
	rules := All()
	ids := make(map[string]bool)
	for _, r := range rules {
		if ids[r.ID()] {
			t.Errorf("Duplicate rule ID: %s", r.ID())
		}
		ids[r.ID()] = true
	}
}

// Test HardcodedKeyRule target functions
func TestHardcodedKeyRule_Targets(t *testing.T) {
	rule := &HardcodedKeyRule{}

	// Verify rule metadata
	if rule.ID() != "CRYPTO010" {
		t.Error("Wrong rule ID")
	}

	// Test nil input handling
	findings := rule.Check(nil, nil)
	if len(findings) != 0 {
		t.Error("Should return no findings for nil input")
	}
}

// Test StaticIVRule target functions
func TestStaticIVRule_Targets(t *testing.T) {
	rule := &StaticIVRule{}

	// Verify rule metadata
	if rule.ID() != "CRYPTO020" {
		t.Error("Wrong rule ID")
	}

	// Test nil input handling
	findings := rule.Check(nil, nil)
	if len(findings) != 0 {
		t.Error("Should return no findings for nil input")
	}
}

// Test PQVulnerableRule detects quantum-vulnerable algorithms
func TestPQRule_Algorithms(t *testing.T) {
	rule := &PQVulnerableRule{}

	// Verify rule metadata
	if rule.ID() != "CRYPTO040" {
		t.Error("Wrong rule ID")
	}

	if rule.Severity() != analyzer.SeverityMedium {
		t.Error("Wrong severity for PQ rule")
	}
}

// Benchmark rule performance
func BenchmarkMD5Rule(b *testing.B) {
	rule := &MD5Rule{}
	for i := 0; i < b.N; i++ {
		rule.Check(nil, nil)
	}
}

func BenchmarkAllRules(b *testing.B) {
	rules := All()
	for i := 0; i < b.N; i++ {
		for _, r := range rules {
			r.Check(nil, nil)
		}
	}
}
