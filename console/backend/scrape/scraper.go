package scrape

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// StateNames maps the ariguard_workload_state gauge value to a state name.
var StateNames = []string{"normal", "suspicious", "escalating", "breakout_imminent", "compromised"}

type Scraper struct {
	DB       *sql.DB
	Interval time.Duration
	Client   *http.Client
}

func New(db *sql.DB) *Scraper {
	return &Scraper{DB: db, Interval: 3 * time.Second, Client: &http.Client{Timeout: 2500 * time.Millisecond}}
}

// Run scrapes every node each interval until ctx is cancelled.
func (s *Scraper) Run(ctx context.Context) {
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		s.scrapeAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type target struct{ node, addr string }

func (s *Scraper) scrapeAll(ctx context.Context) {
	rows, err := s.DB.Query(`SELECT node, metrics_addr FROM nodes WHERE metrics_addr != ''`)
	if err != nil {
		log.Printf("scraper: list nodes: %v", err)
		return
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.node, &t.addr); err == nil {
			targets = append(targets, t)
		}
	}
	rows.Close()

	for _, t := range targets {
		if err := s.scrapeNode(ctx, t); err != nil {
			log.Printf("scraper: %s (%s): %v", t.node, t.addr, err)
		}
	}
	// Keep history bounded (the longest query range is 24h); this also reaps
	// terminal workloads we deliberately kept after their pod was killed.
	cutoff := time.Now().Add(-26 * time.Hour).UnixMilli()
	s.DB.Exec(`DELETE FROM metric_samples WHERE ts < ?`, cutoff)
	s.DB.Exec(`DELETE FROM workloads WHERE updated < ?`, cutoff)
}

func (s *Scraper) scrapeNode(ctx context.Context, t target) error {
	url := t.addr
	if !strings.Contains(url, "://") {
		url = "http://" + url
	}
	url = strings.TrimRight(url, "/") + "/metrics"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return s.store(t.node, ParseProm(resp.Body))
}

func (s *Scraper) store(node string, samples []Sample) error {
	var events, kills, dropped float64
	now := time.Now().UnixMilli()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	seen := 0
	for _, sm := range samples {
		switch sm.Name {
		case "ariguard_events_total":
			events += sm.Value
		case "ariguard_kills_total":
			kills += sm.Value
		case "ariguard_audit_dropped_total":
			dropped += sm.Value
		case "ariguard_workload_state":
			pod, rule := sm.Labels["pod"], sm.Labels["rule"]
			idx := int(sm.Value)
			// rule may be "" for an enrolled pod with no FSM state yet (a benign
			// workload); that is a valid row keyed by (node,pod,rule="").
			if pod == "" || idx < 0 || idx >= len(StateNames) {
				continue
			}
			n := sm.Labels["node"]
			if n == "" {
				n = node
			}
			if _, err := tx.Exec(`INSERT INTO workloads(node,pod,namespace,comm,rule,state,action,updated)
				VALUES(?,?,?,?,?,?,'',?)
				ON CONFLICT(node,pod,rule) DO UPDATE SET namespace=excluded.namespace, comm=excluded.comm,
				  state=excluded.state, updated=excluded.updated,
				  action=CASE WHEN excluded.state='normal' THEN '' ELSE workloads.action END`,
				n, pod, sm.Labels["namespace"], sm.Labels["comm"], rule, StateNames[idx], now); err != nil {
				return err
			}
			seen++
		}
	}
	// The gauge set is authoritative for live state, but keep workloads that
	// reached a terminal state: an attacker is killed within ~1s of turning
	// compromised, so it vanishes from the gauge immediately — we keep it
	// visible (as compromised) so the attack stays on screen instead of
	// flickering away. Aged-out terminal rows are pruned by the loop below.
	if seen > 0 {
		if _, err := tx.Exec(`DELETE FROM workloads WHERE node=? AND updated < ? AND state != 'compromised'`, node, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO metric_samples(ts,node,events,kills,audit_dropped) VALUES(?,?,?,?,?)`,
		now, node, int64(events), int64(kills), int64(dropped)); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE nodes SET last_seen=? WHERE node=?`, now, node); err != nil {
		return err
	}
	return tx.Commit()
}
