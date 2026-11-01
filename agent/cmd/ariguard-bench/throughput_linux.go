//go:build linux

package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// runThroughput spawns --workers tight syscall loops for --window, polling the
// agent's /metrics before and after to compute the matched-event rate and the
// audit drops over the window. CSV: events_per_sec,events_total_delta,audit_dropped_delta.
func runThroughput(args []string) error {
	fs := flag.NewFlagSet("throughput", flag.ExitOnError)
	workers := fs.Int("workers", 16, "number of tight-loop worker processes")
	window := fs.Duration("window", 10*time.Second, "measurement window")
	metricsURL := fs.String("metrics-url", "http://127.0.0.1:9102/metrics", "agent Prometheus endpoint")
	out := fs.String("out", "", `CSV output file ("" = stdout)`)
	if err := fs.Parse(args); err != nil {
		return err
	}

	start, err := scrapeMetrics(*metricsURL)
	if err != nil {
		return fmt.Errorf("scrape start metrics: %w", err)
	}

	ws := make([]*worker, 0, *workers)
	for i := 0; i < *workers; i++ {
		// Tight loop (no sleep) on the runtime socket path so every openat matches
		// the container-escape binding and is counted as an event.
		w, err := spawnWorker(runtimeSocket, 256, 0, "")
		if err != nil {
			stopWorkers(ws)
			return fmt.Errorf("spawn worker: %w", err)
		}
		ws = append(ws, w)
	}

	time.Sleep(*window)

	end, err := scrapeMetrics(*metricsURL)
	stopWorkers(ws)
	if err != nil {
		return fmt.Errorf("scrape end metrics: %w", err)
	}

	eventsDelta := end.events - start.events
	droppedDelta := end.dropped - start.dropped
	eps := float64(eventsDelta) / window.Seconds()

	rows := [][]string{
		{"events_per_sec", "events_total_delta", "audit_dropped_delta"},
		{
			strconv.FormatFloat(eps, 'f', 2, 64),
			strconv.FormatUint(eventsDelta, 10),
			strconv.FormatUint(droppedDelta, 10),
		},
	}

	w, closeOut, err := openOut(*out)
	if err != nil {
		return err
	}
	defer func() { _ = closeOut() }()
	return writeCSV(w, rows)
}

type metricsSample struct {
	events  uint64
	dropped uint64
}

// scrapeMetrics fetches the Prometheus text endpoint and extracts the two
// counters with a simple per-line scan.
func scrapeMetrics(url string) (metricsSample, error) {
	resp, err := http.Get(url)
	if err != nil {
		return metricsSample{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return metricsSample{}, fmt.Errorf("GET %s: %s", url, resp.Status)
	}

	var s metricsSample
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := parseMetricLine(line)
		if !ok {
			continue
		}
		switch name {
		case "ariguard_events_total":
			s.events = value
		case "ariguard_audit_dropped_total":
			s.dropped = value
		}
	}
	return s, sc.Err()
}

// parseMetricLine parses an unlabeled Prometheus counter line "name value".
func parseMetricLine(line string) (string, uint64, bool) {
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return "", 0, false
	}
	v, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		// Tolerate a float-formatted counter (e.g. "123.0").
		f, ferr := strconv.ParseFloat(fields[1], 64)
		if ferr != nil {
			return "", 0, false
		}
		v = uint64(f)
	}
	return fields[0], v, true
}
