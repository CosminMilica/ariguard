// Package mutes holds the operator allowlist the agent pulls from the console: muted pods are
// neither killed (excluded from AG_PODS) nor quarantined (the responder skips them). Safe for
// concurrent use.
package mutes

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Set is a concurrency-safe set of muted pod names.
type Set struct {
	mu  sync.RWMutex
	pod map[string]bool
}

// New returns an empty Set.
func New() *Set { return &Set{pod: map[string]bool{}} }

// Replace swaps the muted pods for the given list. A nil Set is a no-op.
func (s *Set) Replace(pods []string) {
	if s == nil {
		return
	}
	m := make(map[string]bool, len(pods))
	for _, p := range pods {
		if p != "" {
			m[p] = true
		}
	}
	s.mu.Lock()
	s.pod = m
	s.mu.Unlock()
}

// Has reports whether pod is muted. A nil Set reports false.
func (s *Set) Has(pod string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pod[pod]
}

// Poll refreshes the set from fetch every interval until ctx is done. A failed fetch keeps the
// last known set (fail-open on transient console errors; the operator's intent is not lost).
func Poll(ctx context.Context, s *Set, interval time.Duration, fetch func(context.Context) ([]string, error), log *slog.Logger) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	refresh := func() {
		pods, err := fetch(ctx)
		if err != nil {
			if log != nil {
				log.Debug("mute list refresh failed, keeping last", "err", err)
			}
			return
		}
		s.Replace(pods)
	}
	refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			refresh()
		}
	}
}
