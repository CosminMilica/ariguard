"""Parse and validate YAML rule files into an FSM matching the kernel ABI.

A rule file describes one kill chain: named states, named events (each mapped to
the syscalls that raise it), and transitions (from_state + event -> to_state +
action). Symbolic names map to the numeric ABI values defined in
bpf/statewall-common/src/lib.rs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

# ABI mirror (bpf/statewall-common/src/lib.rs). Keep in sync.
STATE_VALUES = {
    "normal": 0,
    "suspicious": 1,
    "escalating": 2,
    "breakout_imminent": 3,
    "compromised": 4,
}
ACTION_VALUES = {
    "observe": 0,
    "throttle": 1,
    "deny": 2,
    "kill": 3,
}


class RuleError(ValueError):
    """Raised when a rule file is malformed or references unknown names."""


@dataclass
class Fsm:
    """A parsed, validated finite state machine ready for serialization."""

    name: str
    num_states: int
    num_events: int
    events: dict[str, list[str]]
    # (from_state, event_index) -> (to_state, action), all numeric ABI values.
    transitions: dict[tuple[int, int], tuple[int, int]] = field(default_factory=dict)


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise RuleError(msg)


def parse_rule(data: dict) -> Fsm:
    """Validate a decoded rule mapping and build an :class:`Fsm`."""
    _require(isinstance(data, dict), "rule must be a mapping")

    name = data.get("name", "unnamed")
    _require(isinstance(name, str), "name must be a string")

    states = data.get("states")
    _require(isinstance(states, list) and states, "states must be a non-empty list")
    for s in states:
        _require(s in STATE_VALUES, f"unknown state: {s!r}")
    state_values = [STATE_VALUES[s] for s in states]

    raw_events = data.get("events")
    _require(isinstance(raw_events, dict) and raw_events, "events must be a non-empty mapping")
    events: dict[str, list[str]] = {}
    event_index: dict[str, int] = {}
    for idx, (ev_name, syscalls) in enumerate(raw_events.items()):
        _require(isinstance(ev_name, str), f"event name must be a string: {ev_name!r}")
        if isinstance(syscalls, str):
            syscalls = [syscalls]
        _require(
            isinstance(syscalls, list) and all(isinstance(c, str) for c in syscalls),
            f"event {ev_name!r} must map to a syscall or list of syscalls",
        )
        events[ev_name] = syscalls
        event_index[ev_name] = idx

    raw_transitions = data.get("transitions")
    _require(isinstance(raw_transitions, list) and raw_transitions, "transitions must be a non-empty list")

    transitions: dict[tuple[int, int], tuple[int, int]] = {}
    for t in raw_transitions:
        _require(isinstance(t, dict), "each transition must be a mapping")
        frm, event, to = t.get("from"), t.get("event"), t.get("to")
        action = t.get("action", "observe")
        _require(frm in STATE_VALUES, f"unknown from_state: {frm!r}")
        _require(to in STATE_VALUES, f"unknown to_state: {to!r}")
        _require(event in event_index, f"unknown event: {event!r}")
        _require(action in ACTION_VALUES, f"unknown action: {action!r}")
        key = (STATE_VALUES[frm], event_index[event])
        _require(key not in transitions, f"duplicate transition for ({frm}, {event})")
        transitions[key] = (STATE_VALUES[to], ACTION_VALUES[action])

    num_states = max(state_values) + 1
    num_events = len(events)
    return Fsm(
        name=name,
        num_states=num_states,
        num_events=num_events,
        events=events,
        transitions=transitions,
    )


def load_rule(path: str | Path) -> Fsm:
    """Load, parse and validate a YAML rule file."""
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    return parse_rule(data)
