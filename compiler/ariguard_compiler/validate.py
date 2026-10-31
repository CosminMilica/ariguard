"""Deterministic validation every rule must pass before entering the library (A4).

``parse_rule`` already enforces the schema for YAML/Sigma inputs; these checks are the
second line of defense for rules built programmatically (e.g. by the generator). They
never raise -- each function returns a list of human-readable problems, empty when valid.

``roundtrip_ok`` additionally emits the bundle and parses the bytes back (a minimal
reader that inverts :mod:`ariguard_compiler.emit`'s layout) to prove the emitted bundle is
self-consistent: header counts, per-rule fields, the full transition grid, every binding
tuple and the metadata are all reconstructed and compared to the input rules.
"""

from __future__ import annotations

from .emit import (
    ACTION_OBSERVE,
    BINDING,
    HEADER,
    MAGIC,
    RULE,
    TRANSITION,
    VERSION,
    emit_bundle,
    metadata,
)
from .schema import (
    ACTION_VALUES,
    HOOK_VALUES,
    MAX_BINDINGS_PER_HOOK,
    MAX_RULES,
    MAX_TRANSITIONS,
    PATTERN_LEN,
    SCOPE_VALUES,
    Rule,
)

_VALID_HOOK_IDS = set(HOOK_VALUES.values())
_VALID_ACTIONS = set(ACTION_VALUES.values())


def validate_rule(rule: Rule) -> list[str]:
    """Return a list of problems with ``rule`` (empty = valid)."""
    problems: list[str] = []
    num_states, num_events = rule.num_states, rule.num_events

    if num_states < 2:
        problems.append(f"num_states must be >= 2, got {num_states}")
    if num_events < 1:
        problems.append(f"num_events must be >= 1, got {num_events}")
    if not 0 <= rule.terminal_from < num_states:
        problems.append(f"terminal_from {rule.terminal_from} must be in 0..{num_states - 1}")
    if rule.scope not in SCOPE_VALUES:
        problems.append(f"unknown scope: {rule.scope!r}")

    for (frm, event), (to, action) in rule.transitions.items():
        if not 0 <= frm < num_states:
            problems.append(f"transition from-state {frm} out of range 0..{num_states - 1}")
        if not 0 <= to < num_states:
            problems.append(f"transition to-state {to} out of range 0..{num_states - 1}")
        if not 0 <= event < num_events:
            problems.append(f"transition event {event} out of range 0..{num_events - 1}")
        if action not in _VALID_ACTIONS:
            problems.append(f"transition ({frm}, {event}) has invalid action {action}")

    cells = num_states * num_events
    if cells > MAX_TRANSITIONS:
        problems.append(f"{cells} transitions exceed MAX_TRANSITIONS ({MAX_TRANSITIONS})")

    # Per-hook binding budget (same count as schema.check_bindings_per_hook).
    for hook_name, hook_id in HOOK_VALUES.items():
        count = sum(1 for b in rule.bindings if b.hook == hook_id)
        if count > MAX_BINDINGS_PER_HOOK:
            problems.append(
                f"hook {hook_name!r} has {count} bindings, max is {MAX_BINDINGS_PER_HOOK}"
            )

    for b in rule.bindings:
        if b.hook not in _VALID_HOOK_IDS:
            problems.append(f"binding has unknown hook id {b.hook}")
        if not 0 <= b.event < num_events:
            problems.append(
                f"binding references event index {b.event} out of range 0..{num_events - 1}"
            )
        if len(b.pattern) > PATTERN_LEN - 1:
            problems.append(
                f"binding pattern {b.pattern!r} is {len(b.pattern)} bytes, max is {PATTERN_LEN - 1}"
            )
        if b"\0" in b.pattern:
            problems.append(f"binding pattern {b.pattern!r} contains a NUL byte")

    return problems


def validate_bundle(rules: list[Rule]) -> list[str]:
    """Return a list of problems with the bundle ``rules`` (empty = valid)."""
    problems: list[str] = []

    if not rules:
        problems.append("bundle has no rules")
    if len(rules) > MAX_RULES:
        problems.append(f"bundle has {len(rules)} rules, max is {MAX_RULES}")

    names = [r.name for r in rules]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        problems.append(f"duplicate rule names: {dup}")

    total = sum(r.num_states * r.num_events for r in rules)
    if total > MAX_TRANSITIONS:
        problems.append(f"bundle has {total} transitions, max is {MAX_TRANSITIONS}")

    for r in rules:
        problems += [f"rule {r.name!r}: {p}" for p in validate_rule(r)]

    return problems


def roundtrip_ok(rules: list[Rule]) -> list[str]:
    """Emit ``rules``, parse the bytes back, and report any mismatch (empty = ok)."""
    problems: list[str] = []
    try:
        data = emit_bundle(rules)
    except Exception as exc:  # noqa: BLE001 - report, never raise
        return [f"emit_bundle failed: {exc}"]

    try:
        magic, version, num_rules, num_trans, num_bindings, meta_len, reserved = HEADER.unpack_from(
            data, 0
        )
    except Exception as exc:  # noqa: BLE001
        return [f"header unpack failed: {exc}"]

    if magic != MAGIC:
        problems.append(f"magic {magic:#x} != {MAGIC:#x}")
    if version != VERSION:
        problems.append(f"version {version} != {VERSION}")
    if reserved != 0:
        problems.append(f"header reserved {reserved} != 0")
    if num_rules != len(rules):
        problems.append(f"num_rules {num_rules} != {len(rules)}")
    expected_trans = sum(r.num_states * r.num_events for r in rules)
    if num_trans != expected_trans:
        problems.append(f"num_transitions {num_trans} != {expected_trans}")
    expected_bindings = sum(len(r.bindings) for r in rules)
    if num_bindings != expected_bindings:
        problems.append(f"num_bindings {num_bindings} != {expected_bindings}")

    trans_start = HEADER.size + num_rules * RULE.size
    bind_start = trans_start + num_trans * TRANSITION.size
    meta_start = bind_start + num_bindings * BINDING.size

    if len(data) != meta_start + meta_len:
        problems.append(f"bundle length {len(data)} != expected {meta_start + meta_len}")

    # Per-rule header fields and the full transition grid.
    for i, r in enumerate(rules[:num_rules]):
        (
            num_states,
            num_events,
            trans_base,
            scope_val,
            terminal_from,
            rule_reserved,
            window_ns,
        ) = RULE.unpack_from(data, HEADER.size + i * RULE.size)
        name = r.name
        if num_states != r.num_states:
            problems.append(f"rule {name!r}: num_states {num_states} != {r.num_states}")
        if num_events != r.num_events:
            problems.append(f"rule {name!r}: num_events {num_events} != {r.num_events}")
        if scope_val != SCOPE_VALUES[r.scope]:
            problems.append(f"rule {name!r}: scope {scope_val} != {SCOPE_VALUES[r.scope]}")
        if terminal_from != r.terminal_from:
            problems.append(f"rule {name!r}: terminal_from {terminal_from} != {r.terminal_from}")
        if window_ns != r.window_ns:
            problems.append(f"rule {name!r}: window_ns {window_ns} != {r.window_ns}")
        if rule_reserved != 0:
            problems.append(f"rule {name!r}: reserved {rule_reserved} != 0")

        for state in range(num_states):
            for event in range(num_events):
                idx = trans_base + state * num_events + event
                cell = TRANSITION.unpack_from(data, trans_start + idx * TRANSITION.size)
                expected = r.transitions.get((state, event), (state, ACTION_OBSERVE))
                if cell != expected:
                    problems.append(f"rule {name!r}: cell ({state}, {event}) {cell} != {expected}")

    # Every binding tuple, in emit order (rule by rule).
    expected_tuples: list[tuple] = []
    for i, r in enumerate(rules):
        for b in r.bindings:
            expected_tuples.append(
                (
                    b.hook,
                    i,
                    b.event,
                    b.path_arg,
                    b.path_kind,
                    len(b.pattern),
                    b.arg_index,
                    b.arg_op,
                    b.arg_value,
                    b.pattern.ljust(PATTERN_LEN, b"\0"),
                )
            )
    for j, want in enumerate(expected_tuples[:num_bindings]):
        got = BINDING.unpack_from(data, bind_start + j * BINDING.size)
        if got != want:
            problems.append(f"binding {j} {got} != {want}")

    # Metadata (deterministic compact JSON of names).
    meta = data[meta_start : meta_start + meta_len]
    if meta != metadata(rules):
        problems.append("metadata bytes do not match metadata(rules)")

    return problems
