// Package policy writes a compiled policy bundle into the kernel maps.
package policy

import (
	"fmt"

	"github.com/CosminMilica/ariguard/pkg/fsm"
)

// Maps is the write surface of AG_POLICY, AG_RULES, AG_TRANSITIONS and AG_BINDINGS.
type Maps interface {
	PutPolicy(p fsm.Policy) error
	PutRule(index uint32, r fsm.Rule) error
	PutTransition(index uint32, t fsm.Transition) error
	PutBindings(hook uint32, hb fsm.HookBindings) error
}

// Option tunes Apply.
type Option func(*fsm.Policy)

// WithEnforce sets Policy.Enforce: true kills on matching actions, false only records them (F3).
func WithEnforce(enforce bool) Option {
	return func(p *fsm.Policy) {
		if enforce {
			p.Enforce = 1
		}
	}
}

// Apply loads b into the kernel maps without reloading programs; enforcement is off unless WithEnforce(true).
//
// Hot-swap protocol: zero AG_POLICY first (programs stop evaluating), rewrite rules,
// table and bindings, then publish the new AG_POLICY last.
func Apply(m Maps, b *fsm.Bundle, opts ...Option) error {
	if err := b.Validate(); err != nil {
		return fmt.Errorf("validate bundle: %w", err)
	}
	groups, err := b.GroupBindings()
	if err != nil {
		return fmt.Errorf("group bindings: %w", err)
	}
	if err := m.PutPolicy(fsm.Policy{}); err != nil {
		return fmt.Errorf("disable AG_POLICY: %w", err)
	}
	for i, r := range b.Rules {
		if err := m.PutRule(uint32(i), r); err != nil {
			return fmt.Errorf("write AG_RULES[%d]: %w", i, err)
		}
	}
	for i, t := range b.Transitions {
		if err := m.PutTransition(uint32(i), t); err != nil {
			return fmt.Errorf("write AG_TRANSITIONS[%d]: %w", i, err)
		}
	}
	for h := uint32(0); h < fsm.NumHooks; h++ {
		if err := m.PutBindings(h, groups[h]); err != nil {
			return fmt.Errorf("write AG_BINDINGS[%d]: %w", h, err)
		}
	}
	pol := b.Policy()
	for _, o := range opts {
		o(&pol)
	}
	if err := m.PutPolicy(pol); err != nil {
		return fmt.Errorf("publish AG_POLICY: %w", err)
	}
	return nil
}
