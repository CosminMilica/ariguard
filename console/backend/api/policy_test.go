package api_test

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestPolicyDistribution(t *testing.T) {
	srv := newServer(t)

	// no policy yet: agents get 204, the UI sees present=false
	resp, err := http.Get(srv.URL + "/api/v1/policy")
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("empty GET /api/v1/policy: %v %v", err, resp)
	}
	var view struct {
		Version string `json:"version"`
		Present bool   `json:"present"`
		Bytes   int    `json:"bytes"`
	}
	mustGet(t, srv, "/api/policy", &view)
	if view.Present {
		t.Fatalf("policy should be absent, got %+v", view)
	}

	// the control plane pushes a bundle
	bundle := []byte("STBT-fake-bundle-bytes-v1")
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/policy", bytes.NewReader(bundle))
	put, err := http.DefaultClient.Do(req)
	if err != nil || put.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT policy: %v %v", err, put)
	}
	version := put.Header.Get("X-Policy-Version")
	if version == "" {
		t.Fatal("PUT policy returned no X-Policy-Version")
	}

	// an agent with no version gets the bytes + version
	resp, _ = http.Get(srv.URL + "/api/v1/policy")
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Equal(got, bundle) {
		t.Fatalf("GET policy: status %d, %d bytes", resp.StatusCode, len(got))
	}
	if resp.Header.Get("X-Policy-Version") != version {
		t.Fatalf("version header %q != %q", resp.Header.Get("X-Policy-Version"), version)
	}

	// an agent that already has this version gets 304 (nothing to hot-swap)
	resp, _ = http.Get(srv.URL + "/api/v1/policy?have=" + version)
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("GET policy?have=current: want 304, got %d", resp.StatusCode)
	}

	// the UI now sees the pushed policy
	mustGet(t, srv, "/api/policy", &view)
	if !view.Present || view.Version != version || view.Bytes != len(bundle) {
		t.Fatalf("policy view: %+v", view)
	}

	// pushing a different bundle rolls the version
	req2, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/policy", bytes.NewReader([]byte("STBT-v2")))
	put2, _ := http.DefaultClient.Do(req2)
	if put2.Header.Get("X-Policy-Version") == version {
		t.Fatal("a different bundle must get a new version")
	}
}
