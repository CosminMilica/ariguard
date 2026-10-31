package loader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/CosminMilica/statewall/agent/internal/hooks"
	"github.com/CosminMilica/statewall/pkg/fsm"
)

// maxInstructions caps each program's pre-verifier size. Raise it deliberately
// when a change needs more; an unexpected jump usually means unrolling or inlining.
const maxInstructions = 512

func loadSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	path := os.Getenv("STATEWALL_OBJECT")
	if path == "" {
		path = filepath.Join("..", "..", "..", "bin", "statewall.bpf.o")
	}
	if _, err := os.Stat(path); err != nil {
		if os.Getenv("STATEWALL_REQUIRE_OBJECT") != "" {
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
	for _, name := range []string{MapState, MapTransitions, MapBindings, MapDims, MapAudit, MapScratch} {
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
