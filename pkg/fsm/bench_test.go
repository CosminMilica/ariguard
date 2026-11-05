package fsm

import (
	"os"
	"path/filepath"
	"testing"
)

// fullBundle is the committed deploy bundle (all rules) the agent loads at startup.
func fullBundle(tb testing.TB) []byte {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "policy-full.bin"))
	if err != nil {
		tb.Fatalf("read bundle: %v", err)
	}
	return data
}

// BenchmarkUnmarshalBundle measures decoding the on-wire policy bundle into the in-memory FSM — the
// cost the agent pays on every control-plane hot-swap (F7). Guards it against perf regressions.
func BenchmarkUnmarshalBundle(b *testing.B) {
	data := fullBundle(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		if _, err := UnmarshalBundle(data); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGroupBindings measures grouping a bundle's bindings by hook into the AG_BINDINGS map
// values the agent writes into the kernel on apply.
func BenchmarkGroupBindings(b *testing.B) {
	bundle, err := UnmarshalBundle(fullBundle(b))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := bundle.GroupBindings(); err != nil {
			b.Fatal(err)
		}
	}
}
