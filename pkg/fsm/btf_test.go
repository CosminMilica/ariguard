package fsm

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// objectPath returns the built BPF object. The test skips when it is missing,
// unless STATEWALL_REQUIRE_OBJECT is set (CI).
func objectPath(t *testing.T) string {
	t.Helper()
	path := os.Getenv("STATEWALL_OBJECT")
	if path == "" {
		path = filepath.Join("..", "..", "bin", "statewall.bpf.o")
	}
	if _, err := os.Stat(path); err != nil {
		if os.Getenv("STATEWALL_REQUIRE_OBJECT") != "" {
			t.Fatalf("BPF object: %v (build with `make build-bpf`)", err)
		}
		t.Skipf("BPF object %s not built, skipping", path)
	}
	return path
}

// TestABIMatchesObjectBTF compares the Go mirror with the layouts the Rust
// compiler emitted into the object's BTF, so drift on either side fails.
func TestABIMatchesObjectBTF(t *testing.T) {
	path := objectPath(t)
	spec, err := btf.LoadSpec(path)
	if err != nil {
		t.Fatalf("load BTF: %v", err)
	}
	for _, goType := range []any{FsmKey{}, FsmState{}, Transition{}, Binding{}, HookBindings{}, Rule{}, Policy{}, AuditRecord{}} {
		rt := reflect.TypeOf(goType)
		t.Run(rt.Name(), func(t *testing.T) {
			var st *btf.Struct
			if err := spec.TypeByName(rt.Name(), &st); err != nil {
				t.Fatalf("BTF struct %s: %v", rt.Name(), err)
			}
			compareStruct(t, rt.Name(), rt, st)
		})
	}
}

func compareStruct(t *testing.T, path string, rt reflect.Type, st *btf.Struct) {
	t.Helper()
	if uintptr(st.Size) != rt.Size() {
		t.Errorf("%s: size Go=%d BTF=%d", path, rt.Size(), st.Size)
	}
	if rt.NumField() != len(st.Members) {
		t.Fatalf("%s: fields Go=%d BTF=%d", path, rt.NumField(), len(st.Members))
	}
	for i, m := range st.Members {
		f := rt.Field(i)
		fpath := path + "." + f.Name
		if f.Name != "_" && normalize(f.Name) != normalize(m.Name) {
			t.Errorf("%s: name Go=%s BTF=%s", fpath, f.Name, m.Name)
		}
		if uintptr(m.Offset.Bytes()) != f.Offset {
			t.Errorf("%s: offset Go=%d BTF=%d", fpath, f.Offset, m.Offset.Bytes())
		}
		size, err := btf.Sizeof(m.Type)
		if err != nil {
			t.Fatalf("%s: BTF size: %v", fpath, err)
		}
		if uintptr(size) != f.Type.Size() {
			t.Errorf("%s: size Go=%d BTF=%d", fpath, f.Type.Size(), size)
		}
		if arr, ok := btf.UnderlyingType(m.Type).(*btf.Array); ok && f.Type.Kind() == reflect.Array {
			if int(arr.Nelems) != f.Type.Len() {
				t.Errorf("%s: len Go=%d BTF=%d", fpath, f.Type.Len(), arr.Nelems)
			}
			if inner, ok := btf.UnderlyingType(arr.Type).(*btf.Struct); ok {
				compareStruct(t, fpath+"[]", f.Type.Elem(), inner)
			}
		}
	}
}

func normalize(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", ""))
}

// TestMapCapacitiesMatchObject checks the contract maps against the Go constants.
func TestMapCapacitiesMatchObject(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(objectPath(t))
	if err != nil {
		t.Fatalf("load collection spec: %v", err)
	}
	cases := []struct {
		name       string
		typ        ebpf.MapType
		maxEntries uint32
		keySize    uint32
		valueSize  uint32
	}{
		{"SW_STATE", ebpf.LRUHash, MaxTrackedWorkloads, 16, 16},
		{"SW_TRANSITIONS", ebpf.Array, MaxTransitions, 4, 8},
		{"SW_BINDINGS", ebpf.Array, NumHooks, 4, 840},
		{"SW_RULES", ebpf.Array, MaxRules, 4, 32},
		{"SW_POLICY", ebpf.Array, 1, 4, 8},
		{"SW_SCRATCH", ebpf.PerCPUArray, 1, 4, PatternLen},
		{"SW_PODS", ebpf.LRUHash, MaxTrackedWorkloads, 8, 1},
		{"SW_METRICS", ebpf.PerCPUArray, NumMetrics, 4, 8},
	}
	for _, c := range cases {
		m, ok := spec.Maps[c.name]
		if !ok {
			t.Errorf("map %s missing from object", c.name)
			continue
		}
		if m.Type != c.typ || m.MaxEntries != c.maxEntries || m.KeySize != c.keySize || m.ValueSize != c.valueSize {
			t.Errorf("%s: got type=%s max=%d key=%d value=%d, want type=%s max=%d key=%d value=%d",
				c.name, m.Type, m.MaxEntries, m.KeySize, m.ValueSize,
				c.typ, c.maxEntries, c.keySize, c.valueSize)
		}
	}
	if m, ok := spec.Maps["SW_AUDIT"]; !ok || m.Type != ebpf.RingBuf {
		t.Errorf("SW_AUDIT missing or not a ring buffer")
	}
}
