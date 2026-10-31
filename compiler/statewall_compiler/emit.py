"""Serialize an FSM into the policy bundle distributed to agents.

Policy bundle format v2 (little-endian), identical to the Go pkg/fsm reader
(see docs/architecture.md):
  Header (32 bytes): magic u32 = 0x53544254, version u32 = 2,
                     num_states u32, num_events u32, num_bindings u32,
                     reserved u32 = 0, window_ns u64
  Transitions: num_states * num_events entries, row-major
               (index = state * num_events + event); 8 bytes each:
               next_state u32, action u32.
  Bindings: num_bindings entries, 80 bytes each: hook u32, event u32,
            match_kind u32, pattern_len u32, pattern [u8; 64] NUL-padded.
Unspecified (state, event) pairs default to next_state = state, action = OBSERVE.
"""

from __future__ import annotations

import struct

from .schema import MAX_TRANSITIONS, PATTERN_LEN, Fsm

MAGIC = 0x53544254  # "STBT"
VERSION = 2
ACTION_OBSERVE = 0
DEFAULT_MAX_ENTRIES = MAX_TRANSITIONS

HEADER = struct.Struct("<IIIIIIQ")
TRANSITION = struct.Struct("<II")
BINDING = struct.Struct(f"<IIII{PATTERN_LEN}s")


def emit_bundle(fsm: Fsm, max_entries: int = DEFAULT_MAX_ENTRIES) -> bytes:
    """Serialize ``fsm`` into the on-wire policy bundle."""
    num_states = fsm.num_states
    num_events = fsm.num_events
    total = num_states * num_events
    if total > max_entries:
        raise ValueError(f"transition table has {total} entries, exceeds max of {max_entries}")

    out = bytearray()
    out += HEADER.pack(MAGIC, VERSION, num_states, num_events, len(fsm.bindings), 0, fsm.window_ns)
    for state in range(num_states):
        for event in range(num_events):
            next_state, action = fsm.transitions.get((state, event), (state, ACTION_OBSERVE))
            out += TRANSITION.pack(next_state, action)
    for b in fsm.bindings:
        out += BINDING.pack(b.hook, b.event, b.match_kind, len(b.pattern), b.pattern)
    return bytes(out)
