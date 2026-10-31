"""Compile the example rule and assert the binary matches the ABI."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from statewall_compiler.emit import MAGIC, VERSION, emit_table
from statewall_compiler.schema import load_rule, parse_rule

RULE = Path(__file__).resolve().parents[1] / "rules" / "container-escape.yml"

ENTRY = struct.Struct("<II")
HEADER = struct.Struct("<IIII")


def _entry(table: bytes, num_events: int, state: int, event: int) -> tuple[int, int]:
    index = state * num_events + event
    offset = HEADER.size + index * ENTRY.size
    return ENTRY.unpack_from(table, offset)


def test_header_and_known_transition_and_defaults():
    fsm = load_rule(RULE)
    table = emit_table(fsm)

    magic, version, num_states, num_events = HEADER.unpack_from(table, 0)
    assert magic == MAGIC
    assert version == VERSION
    assert num_states == 5
    assert num_events == 4
    assert len(table) == HEADER.size + num_states * num_events * ENTRY.size

    # escalating(2) + host_mount(event 2) -> breakout_imminent(3), deny(2)
    assert _entry(table, num_events, 2, 2) == (3, 2)
    # breakout_imminent(3) + critical_execve(event 3) -> compromised(4), kill(3)
    assert _entry(table, num_events, 3, 3) == (4, 3)

    # Unspecified pair defaults to (same_state, OBSERVE=0).
    assert _entry(table, num_events, 0, 3) == (0, 0)
    assert _entry(table, num_events, 4, 0) == (4, 0)


def test_rejects_unknown_names():
    with pytest.raises(ValueError):
        parse_rule(
            {
                "states": ["normal", "bogus"],
                "events": {"e": ["open"]},
                "transitions": [{"from": "normal", "event": "e", "to": "normal"}],
            }
        )


def test_rejects_oversized_table():
    fsm = load_rule(RULE)
    with pytest.raises(ValueError):
        emit_table(fsm, max_entries=4)
