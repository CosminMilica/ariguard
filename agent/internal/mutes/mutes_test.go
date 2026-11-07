package mutes

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSetReplaceHas(t *testing.T) {
	s := New()
	if s.Has("a") {
		t.Fatal("empty set should not contain a")
	}
	s.Replace([]string{"a", "b", ""})
	if !s.Has("a") || !s.Has("b") {
		t.Fatal("a and b should be muted")
	}
	if s.Has("") || s.Has("c") {
		t.Fatal("empty and c should not be muted")
	}
	s.Replace([]string{"c"})
	if s.Has("a") || !s.Has("c") {
		t.Fatal("replace should swap the whole set")
	}
}

func TestNilSafe(t *testing.T) {
	var s *Set
	if s.Has("a") {
		t.Fatal("nil set must report false")
	}
	if !s.Empty() {
		t.Fatal("nil set must report empty")
	}
	s.Replace([]string{"a"}) // must not panic
}

func TestEmpty(t *testing.T) {
	s := New()
	if !s.Empty() {
		t.Fatal("new set should be empty")
	}
	s.Replace([]string{"p1"})
	if s.Empty() {
		t.Fatal("set with an entry is not empty")
	}
	s.Replace(nil)
	if !s.Empty() {
		t.Fatal("cleared set should be empty")
	}
}

func TestPollRefreshesAndKeepsOnError(t *testing.T) {
	s := New()
	calls := 0
	fetch := func(context.Context) ([]string, error) {
		calls++
		switch calls {
		case 1:
			return []string{"p1"}, nil
		case 2:
			return nil, errors.New("console down") // keep last
		default:
			return []string{"p2"}, nil
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	go Poll(ctx, s, 10*time.Millisecond, fetch, nil)

	waitFor(t, func() bool { return s.Has("p1") }) // first refresh
	waitFor(t, func() bool { return calls >= 2 })  // error tick
	if !s.Has("p1") {
		t.Fatal("set must keep the last good value on fetch error")
	}
	waitFor(t, func() bool { return s.Has("p2") && !s.Has("p1") }) // recovery
	cancel()
}

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
