package audit

import "sync"

const commCacheCap = 4096

// CommCache maps a cgroup id to its last-seen process command. It is bounded:
// once full, the oldest inserted cgroup is evicted. The zero value is ready to use.
type CommCache struct {
	mu    sync.Mutex
	m     map[uint64]string
	order []uint64
}

// Set records comm for cgroup; empty comms are ignored.
func (c *CommCache) Set(cgroup uint64, comm string) {
	if comm == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[uint64]string)
	}
	if _, ok := c.m[cgroup]; !ok {
		if len(c.order) >= commCacheCap {
			delete(c.m, c.order[0])
			c.order = append(c.order[:0], c.order[1:]...)
		}
		c.order = append(c.order, cgroup)
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
