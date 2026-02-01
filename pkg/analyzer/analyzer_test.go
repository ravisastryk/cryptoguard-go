package analyzer

import "testing"

func TestSeverity_String(t *testing.T) {
	for _, tt := range []struct {
		s Severity
		w string
	}{
		{SeverityLow, "LOW"}, {SeverityMedium, "MEDIUM"}, {SeverityHigh, "HIGH"}, {SeverityCritical, "CRITICAL"},
	} {
		if got := tt.s.String(); got != tt.w {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.s, got, tt.w)
		}
	}
}

func TestSeverity_Ordering(t *testing.T) {
	if SeverityLow >= SeverityMedium || SeverityMedium >= SeverityHigh || SeverityHigh >= SeverityCritical {
		t.Error("ordering broken")
	}
}

func TestNew_Default(t *testing.T) {
	a, err := New(Config{})
	if err != nil || a == nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNew_RegistersRules(t *testing.T) {
	a, _ := New(Config{})
	// Rules are set separately via SetRules
	if a.rules == nil {
		t.Error("rules not initialized")
	}
}

func TestEnabled_All(t *testing.T) {
	a, _ := New(Config{})
	if !a.isRuleEnabled("CRYPTO001") {
		t.Error("should be enabled")
	}
}

func TestEnabled_Disabled(t *testing.T) {
	a, _ := New(Config{DisabledRules: []string{"CRYPTO001"}})
	if a.isRuleEnabled("CRYPTO001") {
		t.Error("should be disabled")
	}
}

func TestEnabled_Only(t *testing.T) {
	a, _ := New(Config{EnabledRules: []string{"CRYPTO001"}})
	if !a.isRuleEnabled("CRYPTO001") || a.isRuleEnabled("CRYPTO020") {
		t.Error("filter broken")
	}
}

func TestEnabled_DisabledPriority(t *testing.T) {
	a, _ := New(Config{EnabledRules: []string{"CRYPTO001"}, DisabledRules: []string{"CRYPTO001"}})
	if a.isRuleEnabled("CRYPTO001") {
		t.Error("disabled should win")
	}
}

func TestAnalyze_BadPackage(t *testing.T) {
	a, _ := New(Config{})
	if _, err := a.Analyze("not/real/pkg"); err == nil {
		t.Error("expected error")
	}
}

func TestFinding_Fields(t *testing.T) {
	f := Finding{RuleID: "X", Severity: SeverityHigh, CWE: "CWE-1"}
	if f.RuleID != "X" || f.Severity != SeverityHigh {
		t.Error("mismatch")
	}
}
