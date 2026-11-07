package api_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestActorsOwnerWithCommaNotSplit verifies that an attacker-influenced label containing a comma is
// kept as a single list entry by the GROUP_CONCAT / splitConcat path (unit-separator, not comma).
func TestActorsOwnerWithCommaNotSplit(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	ev := func(pod, owner string) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": now, "rule": "r1", "event": "execve",
			"from": "normal", "to": "compromised", "action": "kill", "enforced": true,
			"namespace": "ns-a", "pod": pod, "node": "n1", "comm": "sh",
			"image": "img:1", "image_id": "sha256:abc", "owner": owner, "app": "a"})
		return string(b)
	}
	// one owner label, containing a comma, seen across two pods of the same image
	mustPost(t, srv, "/api/v1/audit", "["+ev("p1", "team-a,evil")+","+ev("p2", "team-a,evil")+"]")

	var got []struct {
		ImageID string   `json:"image_id"`
		Owners  []string `json:"owners"`
	}
	mustGet(t, srv, "/api/actors?range=1h", &got)
	if len(got) != 1 {
		t.Fatalf("actors = %+v, want 1", got)
	}
	if len(got[0].Owners) != 1 || got[0].Owners[0] != "team-a,evil" {
		t.Fatalf("owners = %+v, want [\"team-a,evil\"] (comma not split)", got[0].Owners)
	}
}

// TestCampaignsNamespaceWithCommaNotSplit covers the same fix on the campaigns call site.
func TestCampaignsNamespaceWithCommaNotSplit(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	b, _ := json.Marshal(map[string]any{"ts_ns": now, "rule": "r1", "event": "execve",
		"from": "normal", "to": "compromised", "action": "kill", "enforced": true,
		"namespace": "weird,ns", "pod": "p1", "node": "n1", "comm": "sh"})
	mustPost(t, srv, "/api/v1/audit", "["+string(b)+"]")

	var got struct {
		ByRule []struct {
			AffectedNS []string `json:"affected_namespaces"`
		} `json:"by_rule"`
	}
	mustGet(t, srv, "/api/campaigns?range=1h", &got)
	if len(got.ByRule) != 1 || len(got.ByRule[0].AffectedNS) != 1 || got.ByRule[0].AffectedNS[0] != "weird,ns" {
		t.Fatalf("affected_namespaces = %+v, want [\"weird,ns\"]", got.ByRule)
	}
}

// TestEventsSearchEscapesLikeWildcards verifies LIKE metacharacters in ?q= are treated literally.
func TestEventsSearchEscapesLikeWildcards(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	ev := func(pod string) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": now, "rule": "r1", "event": "execve",
			"from": "normal", "to": "suspicious", "action": "observe",
			"namespace": "ns", "pod": pod, "node": "n1", "comm": "sh"})
		return string(b)
	}
	mustPost(t, srv, "/api/v1/audit", "["+ev("alpha")+","+ev("beta")+"]")

	// "%" (url-encoded %25) must match literally — no pod contains a literal % — not act as a wildcard.
	var got []map[string]any
	mustGet(t, srv, "/api/events?range=1h&q=%25", &got)
	if len(got) != 0 {
		t.Fatalf("q=%% matched %d events, want 0 (wildcard escaped)", len(got))
	}
	// sanity: a genuine substring still matches
	var got2 []map[string]any
	mustGet(t, srv, "/api/events?range=1h&q=alph", &got2)
	if len(got2) != 1 {
		t.Fatalf("q=alph matched %d events, want 1", len(got2))
	}
}

// TestExportSanitizesContentDisposition verifies an embedded quote in the pod param cannot break the
// Content-Disposition filename quoting.
func TestExportSanitizesContentDisposition(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	pod := `p"x`
	b, _ := json.Marshal(map[string]any{"ts_ns": now, "rule": "r1", "event": "execve",
		"from": "normal", "to": "compromised", "action": "kill", "enforced": true,
		"namespace": "ns", "pod": pod, "node": "n1", "comm": "sh"})
	mustPost(t, srv, "/api/v1/audit", "["+string(b)+"]")

	resp, err := http.Get(srv.URL + "/api/export?pod=" + url.QueryEscape(pod))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("export: %v %v", err, resp)
	}
	defer resp.Body.Close()
	cd := resp.Header.Get("Content-Disposition")
	if strings.Count(cd, `"`) != 2 || strings.Contains(cd, `"x`) {
		t.Fatalf("Content-Disposition not sanitized: %q", cd)
	}
	if !strings.Contains(cd, "ariguard-incident-p_x.json") {
		t.Fatalf("filename not sanitized as expected: %q", cd)
	}
}
