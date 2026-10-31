// Package policy writes a compiled policy bundle into the kernel maps.
package policy

import (
	"fmt"

	"github.com/CosminMilica/statewall/pkg/fsm"
)

// Maps is the write surface of SW_POLICY, SW_RULES, SW_TRANSITIONS and SW_BINDINGS.
type Maps interface {
	PutPolicy(p fsm.Policy) error
	PutRule(index uint32, r fsm.Rule) error
	PutTransition(index uint32, t fsm.Transition) error
	PutBindings(hook uint32, hb fsm.HookBindings) error
}

// Apply loads b into the kernel maps without reloading programs.
//
// Hot-swap protocol: zero SW_POLICY first (programs stop evaluating), rewrite rules,
// table and bindings, then publish the new SW_POLICY last.
func Apply(m Maps, b *fsm.Bundle) error {
	if err := b.Validate(); err != nil {
		return fmt.Errorf("validate bundle: %w", err)
	}
	groups, err := b.GroupBindings()
	if err != nil {
		return fmt.Errorf("group bindings: %w", err)
	}
	if err := m.PutPolicy(fsm.Policy{}); err != nil {
		return fmt.Errorf("disable SW_POLICY: %w", err)
	}
	for i, r := range b.Rules {
		if err := m.PutRule(uint32(i), r); err != nil {
			return fmt.Errorf("write SW_RULES[%d]: %w", i, err)
		}
	}
	for i, t := range b.Transitions {
		if err := m.PutTransition(uint32(i), t); err != nil {
			return fmt.Errorf("write SW_TRANSITIONS[%d]: %w", i, err)
		}
	}
	for h := uint32(0); h < fsm.NumHooks; h++ {
		if err := m.PutBindings(h, groups[h]); err != nil {
			return fmt.Errorf("write SW_BINDINGS[%d]: %w", h, err)
		}
	}
	if err := m.PutPolicy(b.Policy()); err != nil {
		return fmt.Errorf("publish SW_POLICY: %w", err)
	}
	return nil
}
