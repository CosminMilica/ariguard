package metrics

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeReader struct {
	c   Counters
	err error
}

func (f fakeReader) Read() (Counters, error) { return f.c, f.err }

func TestFormat(t *testing.T) {
	got := Format(Counters{Events: 7, Kills: 2, AuditDropped: 1})
	for _, want := range []string{
		"# TYPE ariguard_events_total counter\nariguard_events_total 7\n",
		"# TYPE ariguard_kills_total counter\nariguard_kills_total 2\n",
		"# TYPE ariguard_audit_dropped_total counter\nariguard_audit_dropped_total 1\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler(fakeReader{c: Counters{Kills: 3}}).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "ariguard_kills_total 3\n") {
		t.Fatalf("code %d body %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	Handler(fakeReader{err: errors.New("boom")}).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 500 {
		t.Fatalf("code %d, want 500", rec.Code)
	}
}

func TestServe(t *testing.T) {
	if err := Serve(context.Background(), "127.0.0.1:99999", fakeReader{}); err == nil {
		t.Fatal("expected a listen error for an invalid port")
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- Serve(ctx, "127.0.0.1:0", fakeReader{}) }()
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

func TestServeShutsDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, ln, fakeReader{c: Counters{Events: 5}}) }()
	resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "ariguard_events_total 5") {
		t.Fatalf("body %s", body)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

func TestFormatWorkloads(t *testing.T) {
	got := FormatWorkloads([]Workload{
		{Pod: "web", Namespace: "prod", Node: "n1", Comm: "nginx", Rule: "escape", State: 2},
		{Pod: "db", Namespace: "prod", Node: "n1", Comm: "pg", State: 9},
	})
	for _, want := range []string{
		"# TYPE ariguard_workload_state gauge\n",
		`ariguard_workload_state{pod="web",namespace="prod",node="n1",comm="nginx",rule="escape"} 2` + "\n",
		`ariguard_workload_state{pod="db",namespace="prod",node="n1",comm="pg",rule=""} 4` + "\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

type workloadReader struct {
	fakeReader
	ws []Workload
}

func (f workloadReader) Workloads() ([]Workload, error) { return f.ws, nil }

func TestHandlerWorkloads(t *testing.T) {
	rec := httptest.NewRecorder()
	r := workloadReader{ws: []Workload{{Pod: "p", Namespace: "n", Node: "x", Comm: "c"}}}
	Handler(r).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `ariguard_workload_state{pod="p",namespace="n",node="x",comm="c",rule=""} 0`) {
		t.Fatalf("body %s", rec.Body)
	}
}
