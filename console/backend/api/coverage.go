package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

// hookOrder is the fixed list of instrumented hooks, in presentation order.
var hookOrder = []string{
	"openat", "setns", "unshare", "mount", "execve", "ptrace", "connect", "dup2",
	"dup3", "memfd_create", "execveat", "fsmount", "move_mount", "init_module", "finit_module", "bpf",
}

// hookTechniques maps each hook to its static ATT&CK technique list.
var hookTechniques = map[string][]string{
	"openat":       {"T1552 Unsecured Credentials", "T1003.008 /etc/shadow"},
	"setns":        {"T1611 Escape to Host"},
	"unshare":      {"T1611 Escape to Host"},
	"mount":        {"T1611 Escape to Host"},
	"execve":       {"T1059 Command Execution"},
	"ptrace":       {"T1055.008 Ptrace Injection"},
	"connect":      {"T1071 C2", "T1041 Exfiltration"},
	"dup2":         {"T1059 Reverse Shell I/O"},
	"dup3":         {"T1059 Reverse Shell I/O"},
	"memfd_create": {"T1620 Fileless/Reflective Load"},
	"execveat":     {"T1620 Fileless", "T1059 Command Execution"},
	"fsmount":      {"T1611 Escape to Host"},
	"move_mount":   {"T1611 Escape to Host"},
	"init_module":  {"T1547.006 Kernel Module"},
	"finit_module": {"T1547.006 Kernel Module"},
	"bpf":          {"T1562 Impair Defenses", "T1014 Rootkit"},
}

type hookCoverage struct {
	Hook       string   `json:"hook"`
	Attached   bool     `json:"attached"`
	Rules      []string `json:"rules"`
	Techniques []string `json:"techniques"`
	Events     int64    `json:"events"`
}

type coverageOut struct {
	Attached int            `json:"attached"`
	Total    int            `json:"total"`
	Hooks    []hookCoverage `json:"hooks"`
}

// coverage reports per-hook ATT&CK coverage, backing rules and event volume.
func (a *API) coverage(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)

	// attached is a coarse heuristic: the per-hook attach bitmap is not stored yet,
	// so every hook is marked attached when any node has at least one hook attached.
	var maxAttached int
	if err := a.DB.QueryRow(`SELECT COALESCE(MAX(hooks_attached),0) FROM nodes`).Scan(&maxAttached); err != nil {
		fail(w, err)
		return
	}
	attached := maxAttached > 0

	rulesByHook := map[string]map[string]bool{}
	rr, err := a.DB.Query(`SELECT name, MAX(detail) FROM rules GROUP BY name`)
	if err != nil {
		fail(w, err)
		return
	}
	for rr.Next() {
		var name, detail string
		if err := rr.Scan(&name, &detail); err != nil {
			rr.Close()
			fail(w, err)
			return
		}
		if detail == "" {
			continue
		}
		var d struct {
			Transitions []struct {
				Syscalls []string `json:"syscalls"`
			} `json:"transitions"`
		}
		if err := json.Unmarshal([]byte(detail), &d); err != nil {
			rr.Close()
			fail(w, err)
			return
		}
		for _, tr := range d.Transitions {
			for _, sc := range tr.Syscalls {
				hook := strings.Fields(sc)
				if len(hook) == 0 {
					continue
				}
				if _, ok := hookTechniques[hook[0]]; !ok {
					continue
				}
				if rulesByHook[hook[0]] == nil {
					rulesByHook[hook[0]] = map[string]bool{}
				}
				rulesByHook[hook[0]][name] = true
			}
		}
	}
	rr.Close()
	if err := rr.Err(); err != nil {
		fail(w, err)
		return
	}

	eventsByHook := map[string]int64{}
	ev, err := a.DB.Query(`SELECT hook, COUNT(*) FROM audit_events WHERE ts_ns >= ? AND ts_ns <= ? GROUP BY hook`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	for ev.Next() {
		var hook string
		var n int64
		if err := ev.Scan(&hook, &n); err != nil {
			ev.Close()
			fail(w, err)
			return
		}
		eventsByHook[hook] = n
	}
	ev.Close()
	if err := ev.Err(); err != nil {
		fail(w, err)
		return
	}

	out := coverageOut{Total: len(hookOrder), Hooks: []hookCoverage{}}
	for _, h := range hookOrder {
		hc := hookCoverage{Hook: h, Attached: attached, Techniques: hookTechniques[h], Events: eventsByHook[h], Rules: []string{}}
		for name := range rulesByHook[h] {
			hc.Rules = append(hc.Rules, name)
		}
		sort.Strings(hc.Rules)
		if attached {
			out.Attached++
		}
		out.Hooks = append(out.Hooks, hc)
	}
	writeJSON(w, out)
}
