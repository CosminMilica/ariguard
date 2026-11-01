package api_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestActors(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	ev := func(ts int64, pod, ns, rule, to, action, img, imgID, comm string, enforced bool) string {
		b, _ := json.Marshal(map[string]any{
			"ts_ns": ts, "rule": rule, "event": "execve", "from": "normal", "to": to,
			"action": action, "enforced": enforced, "namespace": ns, "pod": pod, "node": "n1",
			"comm": comm, "image": img, "image_id": imgID,
		})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		// one compromised image across two pods and two namespaces = a spreading actor
		ev(now-4000, "p1", "ns-a", "r1", "compromised", "kill", "evil:1", "sha256:evil", "python3", true),
		ev(now-3000, "p2", "ns-b", "r2", "compromised", "kill", "evil:1", "sha256:evil", "sh", true),
		// a different image on a single pod
		ev(now-1000, "p3", "ns-a", "r1", "breakout_imminent", "deny", "legit:1", "sha256:legit", "mount", true),
		// a benign (observe-only) event must not create an actor
		ev(now-500, "p4", "ns-a", "r1", "normal", "observe", "benign:1", "sha256:benign", "sh", false),
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	type actor struct {
		ImageID            string   `json:"image_id"`
		Image              string   `json:"image"`
		Incidents          int      `json:"incidents"`
		Pods               int      `json:"pods"`
		Namespaces         int      `json:"namespaces"`
		Nodes              int      `json:"nodes"`
		Killed             int      `json:"killed"`
		Blocked            int      `json:"blocked"`
		Detected           int      `json:"detected"`
		Rules              []string `json:"rules"`
		Comms              []string `json:"comms"`
		AffectedNamespaces []string `json:"affected_namespaces"`
	}
	var got []actor
	mustGet(t, srv, "/api/actors?range=1h", &got)

	if len(got) != 2 {
		t.Fatalf("want 2 actors (benign excluded), got %d: %+v", len(got), got)
	}
	// widest spread first: the evil image across 2 pods.
	a := got[0]
	if a.ImageID != "sha256:evil" || a.Image != "evil:1" || a.Pods != 2 || a.Namespaces != 2 ||
		a.Incidents != 2 || a.Killed != 2 || a.Blocked != 0 || a.Nodes != 1 {
		t.Fatalf("evil actor: %+v", a)
	}
	sort.Strings(a.Rules)
	sort.Strings(a.Comms)
	if strings.Join(a.Rules, ",") != "r1,r2" || strings.Join(a.Comms, ",") != "python3,sh" {
		t.Fatalf("evil actor rules/comms: %+v", a)
	}
	sort.Strings(a.AffectedNamespaces)
	if strings.Join(a.AffectedNamespaces, ",") != "ns-a,ns-b" {
		t.Fatalf("evil actor namespaces: %+v", a)
	}
	if got[1].ImageID != "sha256:legit" || got[1].Pods != 1 || got[1].Blocked != 1 || got[1].Killed != 0 {
		t.Fatalf("legit actor: %+v", got[1])
	}
}
