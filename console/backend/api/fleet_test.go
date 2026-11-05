package api_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFleet(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	ev := func(ts int64, pod, ns, node, rule, to, action, img, imgID string) string {
		b, _ := json.Marshal(map[string]any{
			"ts_ns": ts, "rule": rule, "event": "execve", "from": "normal", "to": to,
			"action": action, "enforced": true, "namespace": ns, "pod": pod, "node": node,
			"comm": "sh", "image": img, "image_id": imgID,
		})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		// same compromised image on two nodes (n1 first, then n2) = a spreading cross-node actor
		ev(now-5000, "p1", "ns-a", "n1", "container-escape", "compromised", "kill", "evil:1", "sha256:evil"),
		ev(now-2000, "p2", "ns-b", "n2", "container-escape", "compromised", "kill", "evil:1", "sha256:evil"),
		// a single-node actor (one node only) must be excluded from the fleet view
		ev(now-1500, "p3", "ns-a", "n1", "reverse-shell", "compromised", "kill", "lonely:1", "sha256:lonely"),
		// an imageless threat (rule only) on two nodes = a cross-node rule campaign
		ev(now-1400, "p4", "ns-a", "n1", "kernel-module-load", "compromised", "kill", "", ""),
		ev(now-1300, "p5", "ns-c", "n3", "kernel-module-load", "compromised", "kill", "", ""),
		// benign observe-only must not count
		ev(now-500, "p6", "ns-a", "n2", "reverse-shell", "normal", "observe", "benign:1", "sha256:benign"),
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	type nodeHit struct {
		Node      string `json:"node"`
		Incidents int    `json:"incidents"`
	}
	type threat struct {
		Kind      string    `json:"kind"`
		Signature string    `json:"signature"`
		Image     string    `json:"image"`
		Rule      string    `json:"rule"`
		NodeCount int       `json:"node_count"`
		Incidents int       `json:"incidents"`
		Killed    int       `json:"killed"`
		Spreading bool      `json:"spreading"`
		Nodes     []nodeHit `json:"nodes"`
	}
	var got []threat
	mustGet(t, srv, "/api/fleet?range=1h", &got)

	if len(got) != 2 {
		t.Fatalf("want 2 cross-node threats (single-node + benign excluded), got %d: %+v", len(got), got)
	}
	// the evil actor across two nodes (find by kind; order among equal-rank threats is by recency)
	var actor, rule *threat
	for i := range got {
		switch got[i].Kind {
		case "actor":
			actor = &got[i]
		case "rule":
			rule = &got[i]
		}
	}
	if actor == nil || actor.Image != "evil:1" || actor.NodeCount != 2 || actor.Incidents != 2 || actor.Killed != 2 {
		t.Fatalf("evil actor: %+v", actor)
	}
	if !actor.Spreading {
		t.Error("evil actor reached n2 after n1, should be spreading")
	}
	if len(actor.Nodes) != 2 || actor.Nodes[0].Node != "n1" || actor.Nodes[1].Node != "n2" {
		t.Errorf("node breakdown (earliest first): %+v", actor.Nodes)
	}
	// the imageless rule campaign across two nodes
	if rule == nil || rule.Rule != "kernel-module-load" || rule.NodeCount != 2 {
		t.Fatalf("rule campaign: %+v", rule)
	}
	// the single-node actor must not appear
	for _, x := range got {
		if x.Image == "lonely:1" {
			t.Error("single-node actor must be excluded from the fleet view")
		}
	}
}
