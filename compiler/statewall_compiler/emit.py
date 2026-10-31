"""Serialize an FSM into the transition-table binary distributed to agents.

Binary format v1 (little-endian), identical to the Go pkg/fsm reader:
  Header (16 bytes): magic u32 = 0x53544254, version u32 = 1,
                     num_states u32, num_events u32
  Body: num_states * num_events entries, row-major
        (index = state * num_events + event); each entry is 8 bytes:
        next_state u32, action u32.
Unspecified (state, event) pairs default to next_state = state, action = OBSERVE.
"""

from __future__ import annotations

import struct

from .schema import Fsm

MAGIC = 0x53544254  # "STBT"
VERSION = 1
ACTION_OBSERVE = 0
DEFAULT_MAX_ENTRIES = 4096


def emit_table(fsm: Fsm, max_entries: int = DEFAULT_MAX_ENTRIES) -> bytes:
    """Serialize ``fsm`` into the on-wire transition-table binary."""
    num_states = fsm.num_states
    num_events = fsm.num_events
    total = num_states * num_events
    if total > max_entries:
        raise ValueError(
            f"transition table has {total} entries, exceeds max of {max_entries}"
        )

    out = bytearray()
    out += struct.pack("<IIII", MAGIC, VERSION, num_states, num_events)
    for state in range(num_states):
        for event in range(num_events):
            next_state, action = fsm.transitions.get((state, event), (state, ACTION_OBSERVE))
            out += struct.pack("<II", next_state, action)
    return bytes(out)
