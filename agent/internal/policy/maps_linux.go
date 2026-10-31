//go:build linux

package policy

import (
	"github.com/cilium/ebpf"

	"github.com/CosminMilica/statewall/pkg/fsm"
)

// KernelMaps implements Maps over the loaded BPF maps.
type KernelMaps struct {
	Transitions *ebpf.Map
	Bindings    *ebpf.Map
	Dims        *ebpf.Map
}

func (k KernelMaps) PutDims(d fsm.Dims) error {
	return k.Dims.Put(uint32(0), d)
}

func (k KernelMaps) PutTransition(index uint32, t fsm.Transition) error {
	return k.Transitions.Put(index, t)
}

func (k KernelMaps) PutBindings(hook uint32, hb fsm.HookBindings) error {
	return k.Bindings.Put(hook, hb)
}
