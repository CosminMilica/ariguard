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
// re-read and bpf_send_signal path add ~78 inlined insns. Phase 2b added the
// deny-token arm (bpf_get_current_pid_tgid + AG_DENY insert) inline into every sw_
// program (+~40, now 621); the lsm_* deny programs are ~164.
const maxInstructions = 680

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
	for name, section := range map[string]string{"lsm_sb_mount": "lsm/sb_mount", "lsm_move_mount": "lsm/move_mount"} {
		p, ok := spec.Programs[name]
		if !ok {
			t.Errorf("program %s missing", name)
			continue
		}
		if p.SectionName != section {
			t.Errorf("%s: section %s, want %s", name, p.SectionName, section)
		}
	}
}

func TestInstructionBudget(t *testing.T) {
	spec := loadSpec(t)
	for name, p := range spec.Programs {
		if !strings.HasPrefix(name, ProgramPrefix) && !strings.HasPrefix(name, LSMProgramPrefix) {
			continue
		}
		n := len(p.Instructions)
		t.Logf("%s: %d instructions", name, n)
		if n > maxInstructions {
			t.Errorf("%s: %d instructions, budget %d", name, n, maxInstructions)
		}
	}
}
