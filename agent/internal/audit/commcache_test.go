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
	if len(c.m) != commCacheCap || len(c.order) != commCacheCap {
		t.Fatalf("size = %d/%d, want %d", len(c.m), len(c.order), commCacheCap)
	}
	if _, ok := c.Get(0); ok {
		t.Fatal("oldest entry not evicted")
	}
	if _, ok := c.Get(commCacheCap + 9); !ok {
		t.Fatal("newest entry missing")
	}
}
