"""CMP-3.1: Sigma correlations compile to the same FSM the hand-written rules produce.

The examples in ``rules/sigma/*.yml`` must be *structurally* equivalent to the
hand-written ``rules/*.yml`` (event/state names differ; structure must not). We compare
by position in the chain, never by name: same scope, window, state/event counts, terminal
boundary, the set of binding tuples per event index, and the transition chain step for
step. See rules/sigma/README.md.
"""

from __future__ import annotations

import collections
from pathlib import Path

import pytest

from ariguard_compiler.emit import HEADER, MAGIC, VERSION, emit_bundle
from ariguard_compiler.schema import (
    HOOK_VALUES,
    MAX_BINDINGS_PER_HOOK,
    MAX_RULES,
    MAX_TRANSITIONS,
    Rule,
    RuleError,
    load_rule,
)
from ariguard_compiler.sigma import compile_sigma, load_sigma_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
SIGMA = RULES / "sigma"

PAIRS = {
    "reverse-shell": (SIGMA / "reverse-shell.yml", RULES / "reverse-shell.yml"),
    "fileless-exec": (SIGMA / "fileless-exec.yml", RULES / "fileless-exec.yml"),
    "container-escape": (SIGMA / "container-escape.yml", RULES / "container-escape.yml"),
}


# --- structural comparison helpers (compare by position, never by name) ------------


def _bindings_by_event(rule: Rule) -> dict[int, frozenset[tuple]]:
    """Map event index -> the set of its binding tuples (name-independent)."""
    per: dict[int, set[tuple]] = collections.defaultdict(set)
    for b in rule.bindings:
        per[b.event].add((b.hook, b.path_kind, b.pattern, b.arg_op, b.arg_index, b.arg_value))
    return {idx: frozenset(tuples) for idx, tuples in per.items()}


def _transition_chain(rule: Rule) -> list[int]:
    """A linear chain's actions in order; asserts step i advances state i -> i+1 on event i."""
    assert len(rule.transitions) == rule.num_events, "expected one transition per step"
    chain: list[int] = []
    for i in range(rule.num_events):
        assert (i, i) in rule.transitions, f"missing linear transition from state {i} on event {i}"
        to_state, action = rule.transitions[(i, i)]
        assert to_state == i + 1, f"step {i} must advance to state {i + 1}, got {to_state}"
        chain.append(action)
    return chain


def assert_rules_equivalent(got: Rule, want: Rule) -> None:
    """Assert two Rules are structurally equivalent (ignoring event/state names)."""
    assert got.scope == want.scope
    assert got.window_ns == want.window_ns
    assert got.num_states == want.num_states
    assert got.num_events == want.num_events
    assert got.terminal_from == want.terminal_from
    assert _transition_chain(got) == _transition_chain(want)
    g, w = _bindings_by_event(got), _bindings_by_event(want)
    assert set(g) == set(w), "different set of events"
    for idx in w:
        assert g[idx] == w[idx], f"event index {idx} bindings differ"


# --- equivalence with the hand-written rules ---------------------------------------


def test_reverse_shell_equivalent() -> None:
    sigma_file, hand_file = PAIRS["reverse-shell"]
    assert_rules_equivalent(compile_sigma(sigma_file), load_rule(hand_file))


def test_fileless_exec_equivalent() -> None:
    """Full structural equivalence: multi-selection OR expresses memfd_exec exactly.

    memfd_exec is an OR over two predicate shapes (execveat+AT_EMPTY_PATH OR
    execve+/proc/self/fd|/dev/fd). `condition: fexecve_sel or procfd_sel` encodes both, so
    the compiled rule is now fully structurally equal to the hand-written one.
    """
    sigma_file, hand_file = PAIRS["fileless-exec"]
    assert_rules_equivalent(compile_sigma(sigma_file), load_rule(hand_file))


def test_container_escape_equivalent() -> None:
    """Full structural equivalence: every event is a multi-selection OR over different
    predicate shapes (openat-path OR connect-sun_path; setns OR unshare; mount OR fsmount
    OR move_mount; execve OR execveat), with per-step actions observe/throttle/deny/kill.
    """
    sigma_file, hand_file = PAIRS["container-escape"]
    assert_rules_equivalent(compile_sigma(sigma_file), load_rule(hand_file))


# --- emit / limits smoke test ------------------------------------------------------


def test_sigma_bundle_within_limits() -> None:
    rules = load_sigma_rules([SIGMA / "reverse-shell.yml", SIGMA / "fileless-exec.yml"])
    bundle = emit_bundle(rules)

    magic, version, num_rules, num_transitions, num_bindings, meta_len, reserved = (
        HEADER.unpack_from(bundle, 0)
    )
    assert magic == MAGIC
    assert version == VERSION
    assert num_rules == len(rules)
    assert reserved == 0
    expected_len = (
        HEADER.size + num_rules * 32 + num_transitions * 8 + num_bindings * 104 + meta_len
    )
    assert len(bundle) == expected_len

    assert 1 <= num_rules <= MAX_RULES
    total_transitions = sum(r.num_states * r.num_events for r in rules)
    assert num_transitions == total_transitions <= MAX_TRANSITIONS
    for hook_id in HOOK_VALUES.values():
        count = sum(1 for r in rules for b in r.bindings if b.hook == hook_id)
        assert count <= MAX_BINDINGS_PER_HOOK


# --- validation: malformed Sigma files raise RuleError -----------------------------


_GOOD_CORRELATION = """
title: t
name: step
logsource: {product: linux, category: syscall}
detection:
  sel: {syscall: %s}
  condition: sel
---
title: c
name: chain
correlation:
  type: temporal_ordered
  rules: [step]
  timespan: %s
  scope: process
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "rule.yml"
    path.write_text(text, encoding="utf-8")
    return path


def test_rejects_unknown_syscall(tmp_path: Path) -> None:
    path = _write(tmp_path, _GOOD_CORRELATION % ("not_a_syscall", "30s"))
    with pytest.raises(RuleError, match="unknown hook"):
        compile_sigma(path)


def test_rejects_missing_correlation(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "title: t\nname: step\nlogsource: {product: linux, category: syscall}\n"
        "detection:\n  sel: {syscall: execve}\n  condition: sel\n",
    )
    with pytest.raises(RuleError, match="no temporal_ordered correlation"):
        compile_sigma(path)


def test_rejects_bad_timespan(tmp_path: Path) -> None:
    path = _write(tmp_path, _GOOD_CORRELATION % ("execve", "30x"))
    with pytest.raises(RuleError, match="timespan"):
        compile_sigma(path)


_MULTI_SEL_CORRELATION = """
title: t
name: step
logsource: {product: linux, category: syscall}
detection:
  sel1: {syscall: execve}
  sel2: {syscall: execveat}
  condition: %s
---
title: c
name: chain
correlation:
  type: temporal_ordered
  rules: [step]
  timespan: 30s
  scope: process
"""


@pytest.mark.parametrize("condition", ["sel1 and sel2", "not sel1", "sel1 and not sel2"])
def test_rejects_unsupported_condition(tmp_path: Path, condition: str) -> None:
    path = _write(tmp_path, _MULTI_SEL_CORRELATION % condition)
    with pytest.raises(RuleError, match="joined by 'or'"):
        compile_sigma(path)
