package audit

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/CosminMilica/statewall/pkg/fsm"
)

func TestRecordSize(t *testing.T) {
	if s := unsafe.Sizeof(fsm.AuditRecord{}); s != RecordSize {
		t.Fatalf("sizeof(AuditRecord) = %d, want %d", s, RecordSize)
	}
}

func TestNames(t *testing.T) {
	states := []string{"normal", "suspicious", "escalating", "breakout_imminent", "compromised"}
	for i, w := range states {
		if got := StateName(uint32(i)); got != w {
			t.Errorf("StateName(%d) = %q, want %q", i, got, w)
		}
	}
	actions := []string{"observe", "throttle", "deny", "kill"}
	for i, w := range actions {
		if got := ActionName(uint32(i)); got != w {
			t.Errorf("ActionName(%d) = %q, want %q", i, got, w)
		}
	}
	if got := StateName(42); got != "42" {
		t.Errorf("StateName(42) = %q", got)
	}
	if got := ActionName(7); got != "7" {
		t.Errorf("ActionName(7) = %q", got)
	}
}

func sample() []byte {
	b := make([]byte, RecordSize)
	le := binary.LittleEndian
	le.PutUint64(b[0:], 0x1122334455667788)
	le.PutUint64(b[8:], 123456789)
	le.PutUint32(b[16:], 4242)
	le.PutUint32(b[20:], fsm.HookOpenat)
	le.PutUint32(b[24:], 0)
	le.PutUint32(b[28:], fsm.StateNormal)
	le.PutUint32(b[32:], fsm.StateSuspicious)
	le.PutUint32(b[36:], fsm.ActionObserve)
	return b
}

func TestDecode(t *testing.T) {
	r, err := Decode(sample())
	if err != nil {
		t.Fatal(err)
	}
	want := fsm.AuditRecord{
		CgroupID: 0x1122334455667788, TsNs: 123456789, Pid: 4242,
		Hook: fsm.HookOpenat, FromState: fsm.StateNormal, ToState: fsm.StateSuspicious,
	}
	if r != want {
		t.Fatalf("Decode = %+v, want %+v", r, want)
	}
	if _, err := Decode(sample()[:RecordSize-1]); err == nil {
		t.Fatal("Decode of short sample succeeded")
	}
}

func TestWriteLine(t *testing.T) {
	r, _ := Decode(sample())
	var buf bytes.Buffer
	if err := WriteLine(&buf, r); err != nil {
		t.Fatal(err)
	}
	want := `{"ts_ns":123456789,"cgroup_id":1234605616436508552,"pid":4242,"hook":"openat","event":0,"from":"normal","to":"suspicious","action":"observe"}` + "\n"
	if buf.String() != want {
		t.Fatalf("line = %s\nwant   %s", buf.String(), want)
	}

	r.Hook, r.ToState, r.Action = 9, 11, 13
	buf.Reset()
	_ = WriteLine(&buf, r)
	want = `{"ts_ns":123456789,"cgroup_id":1234605616436508552,"pid":4242,"hook":"9","event":0,"from":"normal","to":"11","action":"13"}` + "\n"
	if buf.String() != want {
		t.Fatalf("line = %s\nwant   %s", buf.String(), want)
	}
}
