package podsync

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"testing"
	"time"
)

type fakeSet map[uint64]bool

func (f fakeSet) Put(id uint64) error    { f[id] = true; return nil }
func (f fakeSet) Delete(id uint64) error { delete(f, id); return nil }
func (f fakeSet) Keys() ([]uint64, error) {
	var ks []uint64
	for k := range f {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
	return ks, nil
}

type errSet struct{ fakeSet }

func (errSet) Keys() ([]uint64, error) { return nil, errors.New("boom") }

type fakeSource []uint64

func (f fakeSource) PodCgroups() []uint64 { return f }

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSyncAddsAndPrunes(t *testing.T) {
	set := fakeSet{}
	added, removed, err := Sync(set, []uint64{1, 2, 3})
	if err != nil || added != 3 || removed != 0 {
		t.Fatalf("first sync: %d %d %v", added, removed, err)
	}
	added, removed, err = Sync(set, []uint64{2, 3, 4})
	if err != nil || added != 1 || removed != 1 {
		t.Fatalf("second sync: %d %d %v", added, removed, err)
	}
	keys, _ := set.Keys()
	if len(keys) != 3 || keys[0] != 2 || keys[1] != 3 || keys[2] != 4 {
		t.Fatalf("keys = %v, want [2 3 4]", keys)
	}
	if _, removed, _ = Sync(set, nil); removed != 3 || len(set) != 0 {
		t.Fatalf("empty sync left %v", set)
	}
}

func TestSyncRewritesEvictedEntries(t *testing.T) {
	set := fakeSet{1: true}
	delete(set, 1)
	if _, _, err := Sync(set, []uint64{1}); err != nil || !set[1] {
		t.Fatalf("entry not restored: %v %v", set, err)
	}
}

func TestRunSyncsOnceThenStops(t *testing.T) {
	set := fakeSet{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, set, fakeSource{1, 2}, time.Hour, discardLog())
		close(done)
	}()
	cancel()
	<-done
	if !set[1] || !set[2] {
		t.Fatalf("source not synced into set: %v", set)
	}
}

func TestRunLogsSyncError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, errSet{}, fakeSource{1}, time.Hour, discardLog())
		close(done)
	}()
	cancel()
	<-done
}
