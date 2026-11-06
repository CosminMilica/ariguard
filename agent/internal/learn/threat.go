package learn

import "sync"

// ThreatSet is the set of cgroups that tripped a mitigation (a non-observe audit action). A learn
// trace for a cgroup in this set is labeled "attack" rather than "benign". It is bounded and evicts
// the oldest-marked cgroup past the cap, since cgroup ids churn with pod lifetimes.
type ThreatSet struct {
	mu    sync.RWMutex
	set   map[uint64]struct{}
	order []uint64 // insertion order, for FIFO eviction
	cap   int
}

// NewThreatSet returns a threat set holding at most capacity cgroups (<=0 picks a default).
func NewThreatSet(capacity int) *ThreatSet {
	if capacity <= 0 {
		capacity = 8192
	}
	return &ThreatSet{set: make(map[uint64]struct{}, capacity), cap: capacity}
}

// Mark records that cgroup tripped a mitigation.
func (t *ThreatSet) Mark(cgroup uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.set[cgroup]; ok {
		return
	}
	if len(t.order) >= t.cap {
		oldest := t.order[0]
		t.order = t.order[1:]
		delete(t.set, oldest)
	}
	t.set[cgroup] = struct{}{}
	t.order = append(t.order, cgroup)
}

// Has reports whether cgroup is marked as a threat.
func (t *ThreatSet) Has(cgroup uint64) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.set[cgroup]
	return ok
}
