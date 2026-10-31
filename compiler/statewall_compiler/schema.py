"""Parse and validate YAML rule files (schema v2) into an FSM matching the kernel ABI.

A rule file describes one kill chain: named states, named events (each bound to the
hooks that raise it, optionally gated by a path prefix), transitions (from_state +
event -> to_state + action) and a time window. Symbolic names map to the numeric ABI
values defined in bpf/statewall-common/src/lib.rs.
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
HOOK_VALUES = {
    "openat": 0,
    "setns": 1,
    "unshare": 2,
    "mount": 3,
    "execve": 4,
    "ptrace": 5,
}
MATCH_ANY = 0
MATCH_PATH_PREFIX = 1
PATTERN_LEN = 64
MAX_BINDINGS_PER_HOOK = 4
MAX_TRANSITIONS = 1024
NS_PER_SECOND = 1_000_000_000


class RuleError(ValueError):
    """Raised when a rule file is malformed or references unknown names."""


@dataclass(frozen=True)
class Binding:
    """One hook -> event binding, numeric ABI values."""

    hook: int
    event: int
    match_kind: int
    pattern: bytes = b""


@dataclass
class Fsm:
    """A parsed, validated finite state machine ready for serialization."""

    name: str
    num_states: int
    num_events: int
    events: list[str]
    bindings: list[Binding] = field(default_factory=list)
    # (from_state, event_index) -> (to_state, action), all numeric ABI values.
    transitions: dict[tuple[int, int], tuple[int, int]] = field(default_factory=dict)
    window_ns: int = 0


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise RuleError(msg)


def _str_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(v, str) for v in value)


def _parse_bindings(raw_events: dict) -> tuple[list[str], list[Binding]]:
    events: list[str] = []
    bindings: list[Binding] = []
    for idx, (ev_name, spec) in enumerate(raw_events.items()):
        _require(isinstance(ev_name, str), f"event name must be a string: {ev_name!r}")
        _require(isinstance(spec, dict), f"event {ev_name!r} must be a mapping")
        unknown = set(spec) - {"hooks", "path_prefix"}
        _require(not unknown, f"event {ev_name!r} has unknown keys: {sorted(unknown)}")
        hooks = spec.get("hooks")
        _require(_str_list(hooks), f"event {ev_name!r}: hooks must be a non-empty list")
        prefixes = spec.get("path_prefix")
        if prefixes is not None:
            _require(
                _str_list(prefixes),
                f"event {ev_name!r}: path_prefix must be a non-empty list",
            )
        patterns: list[bytes] = []
        for p in prefixes or []:
            encoded = p.encode("utf-8")
            _require(
                1 <= len(encoded) <= PATTERN_LEN,
                f"event {ev_name!r}: pattern {p!r} must be 1..{PATTERN_LEN} bytes",
            )
            patterns.append(encoded)
        for hook in hooks:
            _require(hook in HOOK_VALUES, f"event {ev_name!r}: unknown hook: {hook!r}")
            hook_id = HOOK_VALUES[hook]
            if patterns:
                bindings += [Binding(hook_id, idx, MATCH_PATH_PREFIX, p) for p in patterns]
            else:
                bindings.append(Binding(hook_id, idx, MATCH_ANY))
        events.append(ev_name)

    for hook, hook_id in HOOK_VALUES.items():
        count = sum(1 for b in bindings if b.hook == hook_id)
        _require(
            count <= MAX_BINDINGS_PER_HOOK,
            f"hook {hook!r} has {count} bindings, max is {MAX_BINDINGS_PER_HOOK}",
        )
    return events, bindings


def parse_rule(data: dict) -> Fsm:
    """Validate a decoded rule mapping and build an :class:`Fsm`."""
    _require(isinstance(data, dict), "rule must be a mapping")

    name = data.get("name", "unnamed")
    _require(isinstance(name, str), "name must be a string")

    window = data.get("window_seconds", 0)
    _require(
        isinstance(window, int) and not isinstance(window, bool) and window >= 0,
        "window_seconds must be a non-negative integer",
    )

    states = data.get("states")
    _require(isinstance(states, list) and states, "states must be a non-empty list")
    for s in states:
        _require(s in STATE_VALUES, f"unknown state: {s!r}")
    state_values = [STATE_VALUES[s] for s in states]

    raw_events = data.get("events")
    _require(isinstance(raw_events, dict) and raw_events, "events must be a non-empty mapping")
    num_states = max(state_values) + 1
    num_events = len(raw_events)
    _require(
        num_states * num_events <= MAX_TRANSITIONS,
        f"transition table has {num_states * num_events} entries, max is {MAX_TRANSITIONS}",
    )
    events, bindings = _parse_bindings(raw_events)
    event_index = {ev: idx for idx, ev in enumerate(events)}

    raw_transitions = data.get("transitions")
    _require(isinstance(raw_transitions, list) and raw_transitions, "transitions must be a non-empty list")

    transitions: dict[tuple[int, int], tuple[int, int]] = {}
    for t in raw_transitions:
        _require(isinstance(t, dict), "each transition must be a mapping")
        frm, event, to = t.get("from"), t.get("event"), t.get("to")
        action = t.get("action", "observe")
        _require(frm in states, f"unknown from_state: {frm!r}")
        _require(to in states, f"unknown to_state: {to!r}")
        _require(event in event_index, f"unknown event: {event!r}")
        _require(action in ACTION_VALUES, f"unknown action: {action!r}")
        key = (STATE_VALUES[frm], event_index[event])
        _require(key not in transitions, f"duplicate transition for ({frm}, {event})")
        transitions[key] = (STATE_VALUES[to], ACTION_VALUES[action])

    return Fsm(
        name=name,
        num_states=num_states,
        num_events=num_events,
        events=events,
        bindings=bindings,
        transitions=transitions,
        window_ns=window * NS_PER_SECOND,
    )


def load_rule(path: str | Path) -> Fsm:
    """Load, parse and validate a YAML rule file."""
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    return parse_rule(data)
