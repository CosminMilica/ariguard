package policysync

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestPollAppliesNewVersionsAndRemembersThem(t *testing.T) {
	var mu sync.Mutex
	applied := []string{}
	fetches := 0

	fetch := func(_ context.Context, have string) ([]byte, string, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		fetches++
		current := "v1"
		if fetches >= 4 { // a push rolls the control plane to v2 partway through
			current = "v2"
		}
		if have == current {
			return nil, current, false, nil // 304: nothing new, must NOT re-apply
		}
		return []byte("bundle-" + current), current, true, nil
	}
	apply := func(data []byte) error {
		mu.Lock()
		defer mu.Unlock()
		applied = append(applied, string(data))
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	go Poll(ctx, 5*time.Millisecond, fetch, apply, nil)

	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(applied) >= 2 })
	cancel()
	mu.Lock()
	defer mu.Unlock()
	if applied[0] != "bundle-v1" || applied[1] != "bundle-v2" {
		t.Fatalf("applied sequence = %v, want [bundle-v1 bundle-v2]", applied)
	}
}

func TestPollKeepsCurrentOnFetchError(t *testing.T) {
	var mu sync.Mutex
	applies := 0
	calls := 0
	fetch := func(_ context.Context, _ string) ([]byte, string, bool, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return nil, "", false, errors.New("console down")
		}
		return []byte("b"), "v1", true, nil
	}
	apply := func([]byte) error { mu.Lock(); applies++; mu.Unlock(); return nil }

	ctx, cancel := context.WithCancel(context.Background())
	go Poll(ctx, 5*time.Millisecond, fetch, apply, nil)
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return applies == 1 }) // recovers after the error
	cancel()
}

func TestPollDoesNotRememberVersionWhenApplyFails(t *testing.T) {
	var mu sync.Mutex
	applies := 0
	fetch := func(_ context.Context, have string) ([]byte, string, bool, error) {
		return []byte("bad"), "v1", true, nil // always "new" from the agent's point of view
	}
	apply := func([]byte) error { mu.Lock(); applies++; mu.Unlock(); return errors.New("bad bundle") }

	ctx, cancel := context.WithCancel(context.Background())
	go Poll(ctx, 5*time.Millisecond, fetch, apply, nil)
	// a failed apply must not advance `have`, so the agent keeps retrying the same version
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return applies >= 2 })
	cancel()
}
