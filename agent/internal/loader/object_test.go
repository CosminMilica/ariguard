package loader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/CosminMilica/ariguard/agent/internal/hooks"
	"github.com/CosminMilica/ariguard/pkg/fsm"
)

// maxInstructions caps each program's pre-verifier size. Raise it deliberately
// when a change needs more; an unexpected jump usually means unrolling or inlining.
// Phase 2 raised it from 512: the per-pod gate, AG_METRICS counters, enforcement
// re-read and bpf_send_signal path add ~78 inlined insns (programs are 571-581).
const maxInstructions = 640

func loadSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	path := os.Getenv("ARIGUARD_OBJECT")
	if path == "" {
		path = filepath.Join("..", "..", "..", "bin", "ariguard.bpf.o")
	}
	if _, err := os.Stat(path); err != nil {
		if os.Getenv("ARIGUARD_REQUIRE_OBJECT") != "" {
			t.Fatalf("BPF object: %v (build with `make build-bpf`)", err)
		}
		t.Skipf("BPF object %s not built, skipping", path)
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatalf("load collection spec: %v", err)
	}
	return spec
}

func TestObjectContract(t *testing.T) {
	spec := loadSpec(t)
	for h := uint32(0); h < fsm.NumHooks; h++ {
		name := hooks.Program(h)
		p, ok := spec.Programs[name]
		if !ok {
			t.Errorf("program %s missing", name)
			continue
		}
		if want := "tracepoint/syscalls/" + hooks.Tracepoint(h); p.SectionName != want {
			t.Errorf("%s: section %s, want %s", name, p.SectionName, want)
		}
	}
	for _, name := range MapNames {
		if _, ok := spec.Maps[name]; !ok {
			t.Errorf("map %s missing", name)
		}
	}
}

func TestInstructionBudget(t *testing.T) {
	spec := loadSpec(t)
	for name, p := range spec.Programs {
		if !strings.HasPrefix(name, ProgramPrefix) {
			continue
		}
		n := len(p.Instructions)
		t.Logf("%s: %d instructions", name, n)
		if n > maxInstructions {
			t.Errorf("%s: %d instructions, budget %d", name, n, maxInstructions)
		}
	}
}
