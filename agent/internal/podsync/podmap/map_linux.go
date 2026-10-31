//go:build linux

package podmap

import (
	"errors"

	"github.com/cilium/ebpf"
)

// Map implements podsync.PodSet over AG_PODS.
type Map struct{ M *ebpf.Map }

func (m Map) Put(cgid uint64) error { return m.M.Put(cgid, uint8(1)) }

func (m Map) Delete(cgid uint64) error {
	if err := m.M.Delete(cgid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func (m Map) Keys() ([]uint64, error) {
	var keys []uint64
	var k uint64
	var v uint8
	it := m.M.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	return keys, it.Err()
}
