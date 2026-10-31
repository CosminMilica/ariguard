package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"sync"
	"testing"
	"unsafe"

	"github.com/CosminMilica/statewall/agent/internal/podmeta"
	"github.com/CosminMilica/statewall/pkg/fsm"
)

func TestRecordSize(t *testing.T) {
	if s := unsafe.Sizeof(fsm.AuditRecord{}); s != RecordSize {
		t.Fatalf("sizeof(AuditRecord) = %d, want %d", s, RecordSize)
	}
}

func TestActionNames(t *testing.T) {
	actions := []string{"observe", "throttle", "deny", "kill"}
	for i, w := range actions {
		if got := ActionName(uint32(i)); got != w {
			t.Errorf("ActionName(%d) = %q, want %q", i, got, w)
		}
	}
	if got := ActionName(7); got != "7" {
		t.Errorf("ActionName(7) = %q", got)
	}
}

func meta() fsm.Meta {
	return fsm.Meta{Rules: []fsm.RuleMeta{{
		Name:   "container-escape",
		Scope:  "cgroup",
		States: []string{"normal", "suspicious", "escalating", "breakout_imminent", "compromised"},
		Events: []string{"runtime_socket_open", "namespace_manipulation", "host_mount", "critical_execve"},
	}}}
}

func sample() []byte {
	b := make([]byte, RecordSize)
	le := binary.LittleEndian
	le.PutUint64(b[0:], 0x1122334455667788)
	le.PutUint64(b[8:], 123456789)
	le.PutUint32(b[16:], 4242)
	le.PutUint32(b[20:], fsm.HookOpenat)
	le.PutUint32(b[24:], 0)
	le.PutUint32(b[28:], 0)
	le.PutUint32(b[32:], 0)
	le.PutUint32(b[36:], 1)
	le.PutUint32(b[40:], fsm.ActionObserve)
	le.PutUint32(b[44:], 0xdeadbeef)
	copy(b[48:], "cat")
	return b
}

func TestDecode(t *testing.T) {
	r, err := Decode(sample())
	if err != nil {
		t.Fatal(err)
	}
	want := fsm.AuditRecord{
		CgroupID: 0x1122334455667788, TsNs: 123456789, Pid: 4242,
		Hook: fsm.HookOpenat, Rule: 0, Event: 0, FromState: 0, ToState: 1, Action: fsm.ActionObserve,
	}
	copy(want.Comm[:], "cat")
	if r != want {
		t.Fatalf("Decode = %+v, want %+v", r, want)
	}
	if _, err := Decode(sample()[:RecordSize-1]); err == nil {
		t.Fatal("Decode of short sample succeeded")
	}
}

func line(t *testing.T, r fsm.AuditRecord, m *fsm.Meta, pod podmeta.Info) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteLine(&buf, NewEvent(r, m, pod)); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestWriteLine(t *testing.T) {
	r, _ := Decode(sample())
	m := meta()
	pod := podmeta.Info{Namespace: "statewall-eval", Pod: "container-escape", Container: "attacker"}
	want := `{"ts_ns":123456789,"cgroup_id":1234605616436508552,"pid":4242,"comm":"cat","hook":"openat",` +
		`"rule":"container-escape","event":"runtime_socket_open","from":"normal","to":"suspicious","action":"observe",` +
		`"namespace":"statewall-eval","pod":"container-escape","container":"attacker"}` + "\n"
	if got := line(t, r, &m, pod); got != want {
		t.Fatalf("line = %s\nwant   %s", got, want)
	}

	r.Hook, r.Event, r.ToState, r.Action = 99, 9, 11, 13
	want = `{"ts_ns":123456789,"cgroup_id":1234605616436508552,"pid":4242,"comm":"cat","hook":"99",` +
		`"rule":"container-escape","event":"9","from":"normal","to":"11","action":"13",` +
		`"namespace":"","pod":"","container":""}` + "\n"
	if got := line(t, r, &m, podmeta.Info{}); got != want {
		t.Fatalf("line = %s\nwant   %s", got, want)
	}

	r.Rule = 3
	want = `{"ts_ns":123456789,"cgroup_id":1234605616436508552,"pid":4242,"comm":"cat","hook":"99",` +
		`"rule":"3","event":"9","from":"0","to":"11","action":"13",` +
		`"namespace":"","pod":"","container":""}` + "\n"
	if got := line(t, r, &m, podmeta.Info{}); got != want {
		t.Fatalf("unknown rule: line = %s\nwant   %s", got, want)
	}
	if got := line(t, r, nil, podmeta.Info{}); got != want {
		t.Fatalf("no metadata: line = %s\nwant   %s", got, want)
	}
}

func TestComm(t *testing.T) {
	var c [fsm.CommLen]byte
	copy(c[:], "0123456789abcdef")
	if got := comm(c); got != "0123456789abcdef" {
		t.Errorf("full comm = %q", got)
	}
	c = [fsm.CommLen]byte{}
	if got := comm(c); got != "" {
		t.Errorf("empty comm = %q", got)
	}
}

func TestNamesReload(t *testing.T) {
	var n Names
	if n.Load() != nil {
		t.Fatal("Load before Store is not nil")
	}
	n.Store(meta())
	if got := n.Load().Rules[0].Name; got != "container-escape" {
		t.Errorf("Load().Rules[0].Name = %q", got)
	}

	r, _ := Decode(sample())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			n.Store(fsm.Meta{Rules: []fsm.RuleMeta{{Name: "reverse-shell", States: []string{"idle", "connected"}, Events: []string{"x"}}}})
			n.Store(meta())
		}
	}()
	for i := 0; i < 1000; i++ {
		var e Event
		if err := json.Unmarshal([]byte(line(t, r, n.Load(), podmeta.Info{})), &e); err != nil {
			t.Fatal(err)
		}
		ok := (e.Rule == "container-escape" && e.From == "normal" && e.To == "suspicious") ||
			(e.Rule == "reverse-shell" && e.From == "idle" && e.To == "connected")
		if !ok {
			t.Fatalf("torn names: %+v", e)
		}
	}
	wg.Wait()
}
