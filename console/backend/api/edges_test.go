package api_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEdges(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	ev := func(ts int64, pod, ns, dstPod, dstNs string, port int64) string {
		b, _ := json.Marshal(map[string]any{
			"ts_ns": ts, "rule": "reverse-shell", "event": "connect", "from": "normal", "to": "suspicious",
			"action": "observe", "namespace": ns, "pod": pod, "node": "n1", "comm": "python3", "hook": "connect",
			"dst_ip": "10.0.0.9", "dst_port": port, "dst_pod": dstPod, "dst_ns": dstNs,
		})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		ev(now-5000, "attacker", "ns-a", "db", "ns-b", 5432),    // cross-ns pivot
		ev(now-4000, "attacker", "ns-a", "db", "ns-b", 5432),    // same edge again -> count 2
		ev(now-3000, "attacker", "ns-a", "cache", "ns-a", 6379), // same-ns pivot
		ev(now-2000, "loner", "ns-a", "", "", 80),               // no dst pod -> not an edge
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	var edges []struct {
		SrcPod  string  `json:"src_pod"`
		DstPod  string  `json:"dst_pod"`
		CrossNs bool    `json:"cross_ns"`
		Count   int64   `json:"count"`
		Ports   []int64 `json:"ports"`
	}
	mustGet(t, srv, "/api/edges?range=1h", &edges)

	if len(edges) != 2 {
		t.Fatalf("want 2 edges, got %+v", edges)
	}
	// cross-namespace pivot sorts first
	if edges[0].DstPod != "db" || !edges[0].CrossNs || edges[0].Count != 2 || len(edges[0].Ports) != 1 || edges[0].Ports[0] != 5432 {
		t.Fatalf("db edge: %+v", edges[0])
	}
	if edges[1].DstPod != "cache" || edges[1].CrossNs {
		t.Fatalf("cache edge: %+v", edges[1])
	}
}
