package audit

import "sync"

const commCacheCap = 4096

// CommCache maps a cgroup id to its last-seen process command. It is bounded:
// once full, the oldest inserted cgroup is evicted. The zero value is ready to use.
//
// Insertion order is tracked in a fixed-size ring buffer (head = oldest, size =
// valid entries), so eviction is O(1): it overwrites the head slot instead of
// shifting the whole slice, which matters on the per-audit-event hot path.
type CommCache struct {
	mu    sync.Mutex
	m     map[uint64]string
	order []uint64 // ring buffer of inserted cgroups, oldest at head
	head  int      // index of the oldest entry
	size  int      // number of valid entries in order
}

// Set records comm for cgroup; empty comms are ignored.
func (c *CommCache) Set(cgroup uint64, comm string) {
	if comm == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[uint64]string, commCacheCap)
		c.order = make([]uint64, commCacheCap)
	}
	if _, ok := c.m[cgroup]; !ok {
		if c.size >= commCacheCap { // full: overwrite the oldest slot, no shift
			delete(c.m, c.order[c.head])
			c.order[c.head] = cgroup
			c.head = (c.head + 1) % commCacheCap
		} else {
			c.order[(c.head+c.size)%commCacheCap] = cgroup
			c.size++
		}
	}
	c.m[cgroup] = comm
}

// Get returns the last-seen comm for cgroup.
func (c *CommCache) Get(cgroup uint64) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[cgroup]
	return v, ok
}
