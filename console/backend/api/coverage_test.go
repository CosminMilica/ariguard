package api_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCoverage(t *testing.T) {
	srv := newServer(t)
	mustPost(t, srv, "/api/v1/register", `{"node":"n1","kernel":"6.8","enforce":true,"hooks_attached":16,"hooks_total":16,
		"bundle":{"rules":[{"name":"r1","scope":"pod","num_states":3,"window_ns":1000,"terminal_action":"kill",
		"transitions":[
		  {"from":"normal","event":"execve","to":"suspicious","action":"observe","syscalls":["openat path^=/etc/shadow"]},
		  {"from":"suspicious","event":"ptrace","to":"compromised","action":"kill","syscalls":["ptrace arg0 == 16","connect arg0"]}
		]}]}}`)
	now := time.Now().UnixNano()
	ev := func(hook string) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": now, "rule": "r1", "event": "x", "from": "normal", "to": "suspicious",
			"action": "observe", "enforced": false, "namespace": "ns", "pod": "p1", "node": "n1", "comm": "sh", "hook": hook})
		return string(b)
	}
	mustPost(t, srv, "/api/v1/audit", "["+strings.Join([]string{ev("openat"), ev("openat"), ev("execve")}, ",")+"]")

	var got struct {
		Attached, Total int
		Hooks           []struct {
			Hook       string
			Attached   bool
			Rules      []string
			Techniques []string
			Events     int
		}
	}
	mustGet(t, srv, "/api/coverage?range=1h", &got)

	if got.Total != 16 || got.Attached != 16 || len(got.Hooks) != 16 {
		t.Fatalf("coverage totals: %+v", got)
	}
	if got.Hooks[0].Hook != "openat" {
		t.Fatalf("hook order: %+v", got.Hooks[0])
	}
	byHook := map[string]struct {
		Hook       string
		Attached   bool
		Rules      []string
		Techniques []string
		Events     int
	}{}
	for _, h := range got.Hooks {
		byHook[h.Hook] = h
	}
	openat := byHook["openat"]
	if !openat.Attached || openat.Events != 2 || len(openat.Rules) != 1 || openat.Rules[0] != "r1" {
		t.Fatalf("openat: %+v", openat)
	}
	if len(openat.Techniques) != 2 || openat.Techniques[0] != "T1552 Unsecured Credentials" {
		t.Fatalf("openat techniques: %+v", openat.Techniques)
	}
	if byHook["ptrace"].Rules[0] != "r1" || byHook["connect"].Rules[0] != "r1" {
		t.Fatalf("ptrace/connect rules: %+v %+v", byHook["ptrace"], byHook["connect"])
	}
	if byHook["execve"].Events != 1 || len(byHook["execve"].Rules) != 0 {
		t.Fatalf("execve: %+v", byHook["execve"])
	}
}
