"""Parse and validate YAML rule files (schema v3), one rule per file.

A rule describes one kill chain: named states, named events (each a list of hook
bindings with optional path and argument predicates), transitions (from + event ->
to + action), a scope and a time window. See docs/architecture.md ("Rule file schema v3").
Numeric values mirror bpf/statewall-common/src/lib.rs (ABI v3).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# ABI mirror (bpf/statewall-common/src/lib.rs). Keep in sync.
HOOKS = (
    "openat",
    "setns",
    "unshare",
    "mount",
    "execve",
    "ptrace",
    "connect",
    "dup2",
    "dup3",
    "memfd_create",
    "execveat",
    "fsmount",
    "move_mount",
    "init_module",
    "finit_module",
    "bpf",
)
HOOK_VALUES = {name: idx for idx, name in enumerate(HOOKS)}
ACTION_VALUES = {"observe": 0, "throttle": 1, "deny": 2, "kill": 3}
SCOPE_VALUES = {"cgroup": 0, "process": 1}
PATH_ANY = 0
PATH_PREFIX = 1
PATH_SUN_PREFIX = 2
ARG_ANY = 0
ARG_OPS = {"eq": 1, "le": 2, "mask_any": 3, "mask_none": 4}
NO_ARG = 0xFFFFFFFF
MAX_SYSCALL_ARGS = 6
PATTERN_LEN = 64
MAX_BINDINGS_PER_HOOK = 8
MAX_RULES = 16
MAX_TRANSITIONS = 1024
NS_PER_SECOND = 1_000_000_000

# Argument index holding the path, per hook and predicate kind.
PATH_ARGS = {"openat": 1, "execve": 0, "execveat": 1, "mount": 1, "memfd_create": 0}
SUN_PATH_ARGS = {"connect": 1}

NAME_RE = re.compile(r"[a-z][a-z0-9_-]*")
RULE_KEYS = {"name", "scope", "window_seconds", "states", "terminal", "events", "transitions"}
BINDING_KEYS = {"hook", "path_prefix", "sun_path_prefix", "arg"}
TRANSITION_KEYS = {"from", "event", "to", "action"}


class RuleError(ValueError):
    """Raised when a rule file is malformed or references unknown names."""


@dataclass(frozen=True)
class Binding:
    """One hook -> event binding of a rule, numeric ABI values."""

    hook: int
    event: int
    path_kind: int = PATH_ANY
    path_arg: int = NO_ARG
    pattern: bytes = b""
    arg_op: int = ARG_ANY
    arg_index: int = NO_ARG
    arg_value: int = 0


@dataclass
class Rule:
    """A parsed, validated rule ready for linking."""

    name: str
    scope: str
    states: list[str]
    events: list[str]
    terminal_from: int
    window_ns: int = 0
    bindings: list[Binding] = field(default_factory=list)
    # (from_state, event) -> (to_state, action), numeric.
    transitions: dict[tuple[int, int], tuple[int, int]] = field(default_factory=dict)

    @property
    def num_states(self) -> int:
        return len(self.states)

    @property
    def num_events(self) -> int:
        return len(self.events)


class _Loader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""


def _construct_mapping(loader: _Loader, node: yaml.MappingNode, deep: bool = False) -> dict:
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise RuleError(f"duplicate key: {key!r}")
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise RuleError(msg)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_name(value: object, what: str) -> str:
    _require(
        isinstance(value, str) and NAME_RE.fullmatch(value) is not None,
        f"{what} {value!r} must match ^[a-z][a-z0-9_-]*$",
    )
    return value


def _name_list(value: object, what: str, item: str) -> list[str]:
    _require(isinstance(value, list) and value, f"{what} must be a non-empty list")
    names = [_check_name(v, item) for v in value]
    _require(len(set(names)) == len(names), f"{what} must be unique")
    return names


def _patterns(value: object, where: str, key: str) -> list[bytes]:
    _require(isinstance(value, list) and value, f"{where}: {key} must be a non-empty list")
    out = []
    for p in value:
        _require(isinstance(p, str), f"{where}: {key} entries must be strings")
        encoded = p.encode("utf-8")
        _require(
            1 <= len(encoded) <= PATTERN_LEN - 1,
            f"{where}: pattern {p!r} must be 1..{PATTERN_LEN - 1} bytes",
        )
        _require(b"\0" not in encoded, f"{where}: pattern {p!r} must not contain NUL")
        out.append(encoded)
    return out


def _arg(value: object, where: str) -> tuple[int, int, int]:
    _require(isinstance(value, dict), f"{where}: arg must be a mapping")
    unknown = set(value) - {"index"} - set(ARG_OPS)
    _require(not unknown, f"{where}: arg has unknown keys: {sorted(unknown, key=str)}")
    index = value.get("index")
    _require(
        _is_int(index) and 0 <= index < MAX_SYSCALL_ARGS,
        f"{where}: arg index must be an integer in 0..{MAX_SYSCALL_ARGS - 1}",
    )
    ops = [op for op in ARG_OPS if op in value]
    _require(len(ops) == 1, f"{where}: arg needs exactly one of {', '.join(ARG_OPS)}")
    operand = value[ops[0]]
    _require(
        _is_int(operand) and 0 <= operand < 1 << 64,
        f"{where}: arg {ops[0]} must be an integer in 0..2^64-1",
    )
    return ARG_OPS[ops[0]], index, operand


def _parse_event(name: str, idx: int, spec: object) -> list[Binding]:
    _require(isinstance(spec, list) and spec, f"event {name!r} must be a non-empty list")
    bindings: list[Binding] = []
    for entry in spec:
        where = f"event {name!r}"
        _require(isinstance(entry, dict), f"{where}: each binding must be a mapping")
        unknown = set(entry) - BINDING_KEYS
        _require(not unknown, f"{where}: binding has unknown keys: {sorted(unknown, key=str)}")
        hook = entry.get("hook")
        _require(hook in HOOK_VALUES, f"{where}: unknown hook: {hook!r}")
        where = f"event {name!r} hook {hook!r}"
        hook_id = HOOK_VALUES[hook]

        arg_op, arg_index, arg_value = ARG_ANY, NO_ARG, 0
        if "arg" in entry:
            arg_op, arg_index, arg_value = _arg(entry["arg"], where)

        path_kind, path_arg, patterns = PATH_ANY, NO_ARG, [b""]
        if "path_prefix" in entry:
            _require(hook in PATH_ARGS, f"{where}: path_prefix needs a hook with a path argument")
            path_kind, path_arg = PATH_PREFIX, PATH_ARGS[hook]
            patterns = _patterns(entry["path_prefix"], where, "path_prefix")
        if "sun_path_prefix" in entry:
            _require(hook in SUN_PATH_ARGS, f"{where}: sun_path_prefix is only valid on connect")
            path_kind, path_arg = PATH_SUN_PREFIX, SUN_PATH_ARGS[hook]
            patterns = _patterns(entry["sun_path_prefix"], where, "sun_path_prefix")

        bindings += [
            Binding(hook_id, idx, path_kind, path_arg, p, arg_op, arg_index, arg_value)
            for p in patterns
        ]
    return bindings


def check_bindings_per_hook(bindings: list[Binding], where: str) -> None:
    """Reject more than MAX_BINDINGS_PER_HOOK bindings on any hook."""
    for hook, hook_id in HOOK_VALUES.items():
        count = sum(1 for b in bindings if b.hook == hook_id)
        _require(
            count <= MAX_BINDINGS_PER_HOOK,
            f"{where}: hook {hook!r} has {count} bindings, max is {MAX_BINDINGS_PER_HOOK}",
        )


def parse_rule(data: object) -> Rule:
    """Validate a decoded rule mapping and build a :class:`Rule`."""
    _require(isinstance(data, dict), "rule must be a mapping")
    unknown = set(data) - RULE_KEYS
    _require(not unknown, f"rule has unknown keys: {sorted(unknown, key=str)}")
    missing = {"name", "scope", "states", "events", "transitions"} - set(data)
    _require(not missing, f"rule is missing keys: {sorted(missing)}")

    name = _check_name(data["name"], "rule name")
    scope = data["scope"]
    _require(scope in SCOPE_VALUES, f"scope must be one of {', '.join(SCOPE_VALUES)}")

    window = data.get("window_seconds", 0)
    _require(_is_int(window) and window >= 0, "window_seconds must be a non-negative integer")

    states = _name_list(data["states"], "states", "state")
    terminal_from = len(states)
    if "terminal" in data:
        terminal = _name_list(data["terminal"], "terminal", "terminal state")
        _require(
            len(terminal) <= len(states) and states[len(states) - len(terminal) :] == terminal,
            "terminal must be a suffix of states",
        )
        terminal_from = len(states) - len(terminal)

    raw_events = data["events"]
    _require(isinstance(raw_events, dict) and raw_events, "events must be a non-empty mapping")
    events: list[str] = []
    bindings: list[Binding] = []
    for idx, (ev_name, spec) in enumerate(raw_events.items()):
        events.append(_check_name(ev_name, "event"))
        bindings += _parse_event(ev_name, idx, spec)
    check_bindings_per_hook(bindings, f"rule {name!r}")
    _require(
        len(states) * len(events) <= MAX_TRANSITIONS,
        f"rule {name!r} has {len(states) * len(events)} transitions, max is {MAX_TRANSITIONS}",
    )

    raw_transitions = data["transitions"]
    _require(
        isinstance(raw_transitions, list) and raw_transitions,
        "transitions must be a non-empty list",
    )
    state_index = {s: i for i, s in enumerate(states)}
    event_index = {e: i for i, e in enumerate(events)}
    transitions: dict[tuple[int, int], tuple[int, int]] = {}
    for t in raw_transitions:
        _require(isinstance(t, dict), "each transition must be a mapping")
        unknown = set(t) - TRANSITION_KEYS
        _require(not unknown, f"transition has unknown keys: {sorted(unknown, key=str)}")
        frm, event, to, action = t.get("from"), t.get("event"), t.get("to"), t.get("action")
        _require(frm in state_index, f"unknown from state: {frm!r}")
        _require(to in state_index, f"unknown to state: {to!r}")
        _require(event in event_index, f"unknown event: {event!r}")
        _require(action in ACTION_VALUES, f"unknown action: {action!r}")
        key = (state_index[frm], event_index[event])
        _require(key not in transitions, f"duplicate transition for ({frm}, {event})")
        transitions[key] = (state_index[to], ACTION_VALUES[action])

    return Rule(
        name=name,
        scope=scope,
        states=states,
        events=events,
        terminal_from=terminal_from,
        window_ns=window * NS_PER_SECOND,
        bindings=bindings,
        transitions=transitions,
    )


def load_rule(path: str | Path) -> Rule:
    """Load, parse and validate a YAML rule file."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = yaml.load(text, Loader=_Loader)
    except (yaml.YAMLError, RuleError) as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from exc
    try:
        return parse_rule(data)
    except RuleError as exc:
        raise RuleError(f"{path}: {exc}") from exc
