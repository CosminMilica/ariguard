// Package podsync mirrors the node's pod cgroups into AG_PODS, the set of mitigation candidates (F2).
package podsync

import (
	"context"
	"log/slog"
	"time"
)

// PodSet is the AG_PODS map.
type PodSet interface {
	Put(cgid uint64) error
	Delete(cgid uint64) error
	Keys() ([]uint64, error)
}

// Source lists the current pod cgroup ids.
type Source interface {
	PodCgroups() []uint64
}

// Sync makes set equal to ids: it writes every id and deletes the others.
func Sync(set PodSet, ids []uint64) (added, removed int, err error) {
	have, err := set.Keys()
	if err != nil {
		return 0, 0, err
	}
	present := make(map[uint64]bool, len(have))
	for _, k := range have {
		present[k] = true
	}
	want := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		want[id] = true
		if err := set.Put(id); err != nil {
			return added, removed, err
		}
		if !present[id] {
			added++
		}
	}
	for _, k := range have {
		if want[k] {
			continue
		}
		if err := set.Delete(k); err != nil {
			return added, removed, err
		}
		removed++
	}
	return added, removed, nil
}

// Run syncs once immediately, then every interval until ctx is done.
func Run(ctx context.Context, set PodSet, src Source, interval time.Duration, log *slog.Logger) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		added, removed, err := Sync(set, src.PodCgroups())
		switch {
		case err != nil:
			log.Warn("sync AG_PODS", "err", err)
		case added > 0 || removed > 0:
			log.Info("AG_PODS updated", "added", added, "removed", removed)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
