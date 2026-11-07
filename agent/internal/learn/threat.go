package learn

import (
	"container/list"
	"sync"
)

// ThreatSet is the set of cgroups that tripped a mitigation (a non-observe audit action). A learn
// trace for a cgroup in this set is labeled "attack" rather than "benign". It is bounded and evicts
// the least-recently-marked cgroup past the cap, since cgroup ids churn with pod lifetimes.
//
// Eviction is LRU, not FIFO: re-marking an already-present cgroup refreshes its recency (moves it to
// most-recent). This keeps a still-active attacker's mark alive under host-wide churn — a flood of
// marks for other (non-learn) cgroups can no longer evict a learn cgroup that keeps tripping, and a
// long-running attacker is not dropped just because its first mark is old.
type ThreatSet struct {
	mu    sync.Mutex
	ll    *list.List               // front = least-recently-marked, back = most-recent
	elems map[uint64]*list.Element // cgroup -> its element in ll (element value is the cgroup id)
	cap   int
}

// NewThreatSet returns a threat set holding at most capacity cgroups (<=0 picks a default).
func NewThreatSet(capacity int) *ThreatSet {
	if capacity <= 0 {
		capacity = 8192
	}
	return &ThreatSet{
		ll:    list.New(),
		elems: make(map[uint64]*list.Element, capacity),
		cap:   capacity,
	}
}

// Mark records that cgroup tripped a mitigation. Re-marking an existing cgroup refreshes its
// recency rather than being a no-op, so it is never evicted while it keeps tripping.
func (t *ThreatSet) Mark(cgroup uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.elems[cgroup]; ok {
		t.ll.MoveToBack(e)
		return
	}
	if t.ll.Len() >= t.cap {
		oldest := t.ll.Front()
		if oldest != nil {
			t.ll.Remove(oldest)
			delete(t.elems, oldest.Value.(uint64))
		}
	}
	t.elems[cgroup] = t.ll.PushBack(cgroup)
}

// Has reports whether cgroup is marked as a threat.
func (t *ThreatSet) Has(cgroup uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.elems[cgroup]
	return ok
}
