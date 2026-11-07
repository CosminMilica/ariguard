package api

import (
	"fmt"
	"net/http/httptest"
	"testing"
)

// TestWindowOfClampsOverlongSpan verifies the M1 span cap: an explicit from/to whose span exceeds
// maxWindowMs is clamped to the most recent maxWindowMs (To is kept, From is pulled up).
func TestWindowOfClampsOverlongSpan(t *testing.T) {
	const to int64 = 10_000_000_000_000 // arbitrary large unix-ms "to"
	r := httptest.NewRequest("GET", fmt.Sprintf("/api/x?from=0&to=%d", to), nil)
	w := windowOf(r)
	if w.To != to {
		t.Fatalf("To = %d, want %d (unchanged)", w.To, to)
	}
	if w.From != to-maxWindowMs {
		t.Fatalf("From = %d, want %d (clamped to most recent maxWindowMs)", w.From, to-maxWindowMs)
	}
	if got := w.To - w.From; got != maxWindowMs {
		t.Fatalf("span = %d, want capped at %d", got, maxWindowMs)
	}
}

// TestWindowOfKeepsInRangeSpan verifies an explicit span within the cap passes through untouched.
func TestWindowOfKeepsInRangeSpan(t *testing.T) {
	const to int64 = 10_000_000_000_000
	from := to - maxWindowMs/2 // half the cap: well within range
	r := httptest.NewRequest("GET", fmt.Sprintf("/api/x?from=%d&to=%d", from, to), nil)
	w := windowOf(r)
	if w.From != from || w.To != to {
		t.Fatalf("window = [%d,%d], want [%d,%d] (unchanged)", w.From, w.To, from, to)
	}
}
