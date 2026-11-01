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
	// Actor "evil" moves ns-a -> ns-b -> ns-c over time. Actor "other" stays in ns-a (no movement).
	body := "[" + strings.Join([]string{
		ev(now-5000, "p1", "ns-a", "r1", "sha256:evil"),
		ev(now-4000, "p2", "ns-b", "r1", "sha256:evil"),
		ev(now-3000, "p3", "ns-c", "r1", "sha256:evil"),
		ev(now-2000, "p4", "ns-a", "r2", "sha256:other"),
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	type trail struct {
		ImageID    string   `json:"image_id"`
		Path       []string `json:"path"`
		Hops       int      `json:"hops"`
		Namespaces int      `json:"namespaces"`
		Pods       int      `json:"pods"`
		Incidents  int      `json:"incidents"`
		Killed     int      `json:"killed"`
	}
	var got struct {
		Actors     []trail  `json:"actors"`
		Namespaces []string `json:"namespaces"`
	}
	mustGet(t, srv, "/api/lateral?range=1h", &got)

	if len(got.Actors) != 2 {
		t.Fatalf("want 2 actors, got %+v", got.Actors)
	}
	// the mover sorts first
	evil := got.Actors[0]
	if evil.ImageID != "sha256:evil" || evil.Hops != 2 || evil.Namespaces != 3 || evil.Pods != 3 ||
		evil.Incidents != 3 || evil.Killed != 3 {
		t.Fatalf("evil trail: %+v", evil)
	}
	if strings.Join(evil.Path, "->") != "ns-a->ns-b->ns-c" {
		t.Fatalf("evil path: %v", evil.Path)
	}
	other := got.Actors[1]
	if other.ImageID != "sha256:other" || other.Hops != 0 || strings.Join(other.Path, "->") != "ns-a" {
		t.Fatalf("other trail: %+v", other)
	}
	if strings.Join(got.Namespaces, ",") != "ns-a,ns-b,ns-c" {
		t.Fatalf("namespaces filter list: %v", got.Namespaces)
	}
}
