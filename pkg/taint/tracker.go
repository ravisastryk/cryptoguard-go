// Package taint provides taint analysis capabilities for tracking data flow
// in SSA-form Go programs. It identifies the origin and propagation of values
// through the program to detect potential security issues.
package taint

import "golang.org/x/tools/go/ssa"

// Source represents the origin of a tainted value in the program.
// It tracks where a value came from and the confidence level of that determination.
type Source struct {
	// Type categorizes the source (e.g., "constant", "random", "parameter").
	Type string

	// Value is the SSA value representing this source.
	Value ssa.Value

	// Description provides human-readable context about the source.
	Description string

	// Confidence indicates how certain we are about this source (0.0-1.0).
	Confidence float64
}

// Tracker performs taint analysis by tracing values back to their sources.
// It maintains a cache of analyzed values to avoid redundant work and detect cycles.
type Tracker struct {
	// sources maps SSA values to their identified source origins.
	sources map[ssa.Value]*Source

	// visited tracks values already analyzed to prevent infinite recursion.
	visited map[ssa.Value]bool
}

// NewTracker creates a new taint tracker with initialized internal maps.
func NewTracker() *Tracker {
	return &Tracker{sources: make(map[ssa.Value]*Source), visited: make(map[ssa.Value]bool)}
}

// FindSource traces the given SSA value back to its source origin.
// It returns a Source describing where the value came from and how it was derived.
// The method handles cycles and caches results for efficiency.
func (t *Tracker) FindSource(v ssa.Value) *Source {
	if v == nil {
		return &Source{Type: "unknown", Description: "nil value"}
	}
	if t.visited[v] {
		if s, ok := t.sources[v]; ok {
			return s
		}
		return &Source{Type: "unknown", Value: v, Description: "cycle"}
	}
	t.visited[v] = true
	if s, ok := t.sources[v]; ok {
		return s
	}
	s := t.trace(v)
	t.sources[v] = s
	return s
}

// trace performs the actual tracing logic for a given SSA value.
// It examines the value's type and recursively traces its origins.
func (t *Tracker) trace(v ssa.Value) *Source {
	switch val := v.(type) {
	case *ssa.Const:
		return &Source{"constant", val, "Constant value", 1.0}
	case *ssa.Alloc:
		return t.traceAlloc(val)
	case *ssa.Call:
		return t.traceCall(val)
	case *ssa.Phi:
		for _, e := range val.Edges {
			if s := t.FindSource(e); s.Type == "constant" || s.Type == "zero-value" {
				return s
			}
		}
		return &Source{"phi", val, "Merged control flow", 0.5}
	case *ssa.Convert:
		return t.FindSource(val.X)
	case *ssa.Slice:
		return t.FindSource(val.X)
	case *ssa.Parameter:
		return &Source{"parameter", val, "Function parameter", 0.6}
	case *ssa.Global:
		return &Source{"global", val, "Global variable", 0.7}
	default:
		return &Source{"unknown", v, "Unknown source", 0.5}
	}
}

// traceAlloc traces an allocation instruction by examining its referrers.
// It looks for Store instructions to determine what value was stored into the allocation.
func (t *Tracker) traceAlloc(a *ssa.Alloc) *Source {
	if refs := a.Referrers(); refs != nil {
		for _, r := range *refs {
			if st, ok := r.(*ssa.Store); ok {
				return t.FindSource(st.Val)
			}
		}
	}
	return &Source{"zero-value", a, "Uninitialized", 0.9}
}

// traceCall traces a function call to determine its source characteristics.
// It identifies cryptographically secure random sources and environment variable reads.
func (t *Tracker) traceCall(c *ssa.Call) *Source {
	f := c.Call.StaticCallee()
	if f == nil {
		return &Source{"dynamic-call", c, "Dynamic call", 0.3}
	}
	if f.Pkg == nil {
		return &Source{"builtin", c, "Built-in", 0.5}
	}
	name := f.Pkg.Pkg.Path() + "." + f.Name()
	if isRandomSource(name) {
		return &Source{"random", c, "Cryptographically random", 1.0}
	}
	if isEnvSource(name) {
		return &Source{"env", c, "Environment variable", 0.8}
	}
	return &Source{"function-result", c, "Function return", 0.5}
}

// isRandomSource checks if the given function name is a cryptographically secure random source.
// It returns true for functions from crypto/rand package that generate random values.
func isRandomSource(n string) bool {
	switch n {
	case "crypto/rand.Read", "crypto/rand.Int", "crypto/rand.Prime":
		return true
	}
	return false
}

// isEnvSource checks if the given function name reads from environment variables.
// It returns true for os.Getenv and os.LookupEnv functions.
func isEnvSource(n string) bool { return n == "os.Getenv" || n == "os.LookupEnv" }
