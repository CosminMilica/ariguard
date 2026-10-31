//go:build linux

package kmap

import (
	"github.com/cilium/ebpf"

	"github.com/CosminMilica/statewall/pkg/fsm"
)

// KernelMaps implements policy.Maps over the loaded BPF maps.
type KernelMaps struct {
	Policy      *ebpf.Map
	Rules       *ebpf.Map
	Transitions *ebpf.Map
	Bindings    *ebpf.Map
}

func (k KernelMaps) PutPolicy(p fsm.Policy) error {
	return k.Policy.Put(uint32(0), p)
}

func (k KernelMaps) PutRule(index uint32, r fsm.Rule) error {
	return k.Rules.Put(index, r)
}

func (k KernelMaps) PutTransition(index uint32, t fsm.Transition) error {
	return k.Transitions.Put(index, t)
}

func (k KernelMaps) PutBindings(hook uint32, hb fsm.HookBindings) error {
	return k.Bindings.Put(hook, hb)
}
