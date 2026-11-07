package audit

import "testing"

func TestCommCacheSetGet(t *testing.T) {
	var c CommCache
	if _, ok := c.Get(1); ok {
		t.Fatal("empty cache returned a value")
	}
	c.Set(1, "bash")
	c.Set(1, "curl")
	c.Set(2, "")
	if v, ok := c.Get(1); !ok || v != "curl" {
		t.Fatalf("Get(1) = %q, %v", v, ok)
	}
	if _, ok := c.Get(2); ok {
		t.Fatal("empty comm must not be stored")
	}
}

func TestNamesCommFallback(t *testing.T) {
	var n Names
	if _, ok := n.Comm(7); ok {
		t.Fatal("unexpected comm")
	}
	n.SetComm(7, "sh")
	if v, ok := n.Comm(7); !ok || v != "sh" {
		t.Fatalf("Comm(7) = %q, %v", v, ok)
	}
	var nilNames *Names
	nilNames.SetComm(1, "x")
	if _, ok := nilNames.Comm(1); ok {
		t.Fatal("nil Names returned a comm")
	}
}

func TestCommCacheBounded(t *testing.T) {
	var c CommCache
	for i := uint64(0); i < commCacheCap+10; i++ {
		c.Set(i, "x")
	}
	if len(c.m) != commCacheCap || c.size != commCacheCap {
		t.Fatalf("size = %d/%d, want %d", len(c.m), c.size, commCacheCap)
	}
	for i := uint64(0); i < 10; i++ { // the first 10 inserted were evicted
		if _, ok := c.Get(i); ok {
			t.Fatalf("entry %d should have been evicted", i)
		}
	}
	if _, ok := c.Get(commCacheCap + 9); !ok {
		t.Fatal("newest entry missing")
	}
}

// TestCommCacheRingEvictionOrder verifies the ring evicts in strict insertion
// (FIFO) order across the wrap point, and that re-setting an existing cgroup
// does not consume a ring slot or disturb the eviction order.
func TestCommCacheRingEvictionOrder(t *testing.T) {
	var c CommCache
	for i := uint64(0); i < commCacheCap; i++ {
		c.Set(i, "x")
	}
	// Re-set an existing entry: must not grow the ring nor evict anything.
	c.Set(0, "y")
	if c.size != commCacheCap {
		t.Fatalf("re-set changed size to %d, want %d", c.size, commCacheCap)
	}
	if v, ok := c.Get(0); !ok || v != "y" {
		t.Fatalf("re-set value = %q, %v", v, ok)
	}
	// Insert one new entry past the cap: the oldest (0) is evicted, 1 survives.
	c.Set(commCacheCap, "z")
	if _, ok := c.Get(0); ok {
		t.Fatal("oldest entry (0) should have been evicted")
	}
	if _, ok := c.Get(1); !ok {
		t.Fatal("second-oldest entry (1) should survive")
	}
	if _, ok := c.Get(commCacheCap); !ok {
		t.Fatal("newest entry missing after wrap")
	}
}
