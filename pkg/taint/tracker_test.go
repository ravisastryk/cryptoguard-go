package taint

import "testing"

func TestNewTracker(t *testing.T) {
	tr := NewTracker()
	if tr == nil || tr.sources == nil || tr.visited == nil {
		t.Fatal("broken")
	}
}

func TestFindSource_Nil(t *testing.T) {
	if s := NewTracker().FindSource(nil); s == nil || s.Type != "unknown" {
		t.Error("nil should return unknown")
	}
}

func TestIsRandomSource(t *testing.T) {
	for _, n := range []string{"crypto/rand.Read", "crypto/rand.Int", "crypto/rand.Prime"} {
		if !isRandomSource(n) {
			t.Errorf("%q should be random", n)
		}
	}
	for _, n := range []string{"math/rand.Read", ""} {
		if isRandomSource(n) {
			t.Errorf("%q should not be random", n)
		}
	}
}

func TestIsEnvSource(t *testing.T) {
	if !isEnvSource("os.Getenv") || !isEnvSource("os.LookupEnv") {
		t.Error("env miss")
	}
	if isEnvSource("os.Open") {
		t.Error("false positive")
	}
}

func TestSource_Fields(t *testing.T) {
	s := &Source{Type: "random", Confidence: 0.95}
	if s.Type != "random" || s.Confidence != 0.95 {
		t.Error("mismatch")
	}
}
