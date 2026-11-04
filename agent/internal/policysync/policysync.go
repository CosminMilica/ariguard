// Package policysync pulls the current policy bundle from the console (the control plane) and
// hot-swaps it into the kernel maps, so rules reach the fleet without rebuilding the agent image
// (F7). It mirrors the mute poller: a Fetch that returns a new bundle only when its version
// changed, and an Apply that installs it. A failed fetch or a bad bundle keeps the running policy
// (fail-safe: the agent never drops to no policy because the console hiccuped).
package policysync

import (
	"context"
	"log/slog"
	"time"
)

// Fetch returns the console's current bundle: changed=false (with the current version) when the
// agent's “have“ still matches or no policy is pushed, or changed=true with the new bytes.
type Fetch func(ctx context.Context, have string) (data []byte, version string, changed bool, err error)

// Apply installs a fetched bundle into the kernel maps (the existing hot-swap path). It must be
// safe to call concurrently with a SIGHUP reload; the caller serialises the two.
type Apply func(data []byte) error

// Poll fetches every interval and applies a new bundle until ctx is done. The applied version is
// remembered so the next poll is a cheap 304 until the control plane pushes a change.
func Poll(ctx context.Context, interval time.Duration, fetch Fetch, apply Apply, log *slog.Logger) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	have := ""
	refresh := func() {
		data, version, changed, err := fetch(ctx, have)
		if err != nil {
			if log != nil {
				log.Debug("policy poll failed, keeping current", "err", err)
			}
			return
		}
		if !changed {
			return
		}
		if err := apply(data); err != nil {
			if log != nil {
				log.Error("policy hot-swap failed, keeping current", "version", version, "err", err)
			}
			return
		}
		have = version
		if log != nil {
			log.Info("policy hot-swapped from control plane", "version", version, "bytes", len(data))
		}
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
