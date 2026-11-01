package api_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLateral(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	ev := func(ts int64, pod, ns, rule, imgID string) string {
		b, _ := json.Marshal(map[string]any{
			"ts_ns": ts, "rule": rule, "event": "execve", "from": "normal", "to": "compromised",
			"action": "kill", "enforced": true, "namespace": ns, "pod": pod, "node": "n1",
			"comm": "python3", "image": "evil:1", "image_id": imgID,
		})
		return string(b)
	}
	// Actor "evil" moves ns-a -> ns-b -> ns-c over time. A different actor stays in ns-a (no hop).
	body := "[" + strings.Join([]string{
		ev(now-5000, "p1", "ns-a", "r1", "sha256:evil"),
		ev(now-4000, "p2", "ns-b", "r1", "sha256:evil"),
		ev(now-3000, "p3", "ns-c", "r1", "sha256:evil"),
		ev(now-2000, "p4", "ns-a", "r1", "sha256:other"),
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	type node struct {
		Namespace       string `json:"namespace"`
		Incidents, Pods int
	}
	type edge struct {
		From, To string
		Count    int
		Images   []string
	}
	var got struct {
		Nodes []node `json:"nodes"`
		Edges []edge `json:"edges"`
	}
	mustGet(t, srv, "/api/lateral?range=1h", &got)

	if len(got.Nodes) != 3 {
		t.Fatalf("want 3 namespace nodes, got %+v", got.Nodes)
	}
	// ns-a has two incidents (evil + other), the rest one each.
	byNS := map[string]node{}
	for _, n := range got.Nodes {
		byNS[n.Namespace] = n
	}
	if byNS["ns-a"].Incidents != 2 || byNS["ns-a"].Pods != 2 {
		t.Errorf("ns-a node: %+v", byNS["ns-a"])
	}

	// evil's trail gives exactly two hops: ns-a->ns-b and ns-b->ns-c; "other" (single ns) adds none.
	if len(got.Edges) != 2 {
		t.Fatalf("want 2 edges, got %+v", got.Edges)
	}
	seen := map[string]edge{}
	for _, e := range got.Edges {
		seen[e.From+"->"+e.To] = e
	}
	ab, ok1 := seen["ns-a->ns-b"]
	bc, ok2 := seen["ns-b->ns-c"]
	if !ok1 || !ok2 {
		t.Fatalf("missing expected hops: %+v", got.Edges)
	}
	if ab.Count != 1 || strings.Join(ab.Images, ",") != "sha256:evil" {
		t.Errorf("edge ns-a->ns-b: %+v", ab)
	}
	if bc.Count != 1 {
		t.Errorf("edge ns-b->ns-c: %+v", bc)
	}
}
