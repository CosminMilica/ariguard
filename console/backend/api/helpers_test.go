package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CosminMilica/ariguard/console/backend/api"
	"github.com/CosminMilica/ariguard/console/backend/ingest"
	"github.com/CosminMilica/ariguard/console/backend/store"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mux := http.NewServeMux()
	(&ingest.Handler{DB: db}).Routes(mux)
	(&api.API{DB: db}).Routes(mux)
	srv := httptest.NewServer(api.CORS(mux))
	t.Cleanup(srv.Close)
	return srv
}

func mustPost(t *testing.T, srv *httptest.Server, path, body string) {
	t.Helper()
	resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
	if err != nil || resp.StatusCode >= 300 {
		t.Fatalf("POST %s: %v %v", path, err, resp)
	}
}

func mustGet(t *testing.T, srv *httptest.Server, path string, v any) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("GET %s: %v %v", path, err, resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}
