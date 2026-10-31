"""A4: deterministic validation and bundle round-trip."""

from __future__ import annotations

from pathlib import Path

import pytest

from ariguard_compiler.schema import (
    HOOK_VALUES,
    Binding,
    Rule,
    RuleError,
    load_rule,
)
from ariguard_compiler.sigma import compile_sigma
from ariguard_compiler.validate import roundtrip_ok, validate_bundle, validate_rule

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
SIGMA = RULES / "sigma"

HAND_RULES = [
    RULES / "container-escape.yml",
    RULES / "fileless-exec.yml",
    RULES / "reverse-shell.yml",
]
SIGMA_RULES = [
    SIGMA / "container-escape.yml",
    SIGMA / "fileless-exec.yml",
    SIGMA / "reverse-shell.yml",
]


def _rule(name: str = "r", *, states=2, bindings=None, transitions=None) -> Rule:
    """A minimal, valid Rule built programmatically (bypasses parse_rule)."""
    state_names = [f"s{i}" for i in range(states)]
    return Rule(
        name=name,
        scope="process",
        states=state_names,
        events=["e"],
        terminal_from=states - 1,
        window_ns=0,
        bindings=[Binding(HOOK_VALUES["execve"], 0)] if bindings is None else bindings,
        transitions={(0, 0): (states - 1, 3)} if transitions is None else transitions,
    )


# --- valid passes ------------------------------------------------------------------


def test_valid_rule_passes():
    assert validate_rule(_rule()) == []


def test_valid_bundle_passes():
    assert validate_bundle([_rule("a"), _rule("b")]) == []


# --- invalid rules / bundles -------------------------------------------------------


def test_too_many_bindings_per_hook():
    rule = _rule(bindings=[Binding(HOOK_VALUES["execve"], 0) for _ in range(9)])
    problems = validate_rule(rule)
    assert any("execve" in p and "max is 8" in p for p in problems)


def test_bundle_exceeds_max_rules():
    rules = [_rule(f"r{i}") for i in range(17)]
    problems = validate_bundle(rules)
    assert any("17 rules" in p and "max is 16" in p for p in problems)


def test_bad_transition_index():
    # event index 5 does not exist (num_events == 1); to-state 7 is out of range.
    rule = _rule(transitions={(0, 5): (7, 3)})
    problems = validate_rule(rule)
    assert any("event 5 out of range" in p for p in problems)
    assert any("to-state 7 out of range" in p for p in problems)


def test_invalid_action():
    rule = _rule(transitions={(0, 0): (1, 99)})
    assert any("invalid action 99" in p for p in validate_rule(rule))


def test_oversized_pattern():
    big = b"/" + b"a" * 64  # 65 bytes > PATTERN_LEN - 1 (63)
    rule = _rule(bindings=[Binding(HOOK_VALUES["openat"], 0, pattern=big)])
    assert any("65 bytes" in p and "max is 63" in p for p in validate_rule(rule))


def test_nul_in_pattern():
    rule = _rule(bindings=[Binding(HOOK_VALUES["openat"], 0, pattern=b"/a\0b")])
    assert any("NUL" in p for p in validate_rule(rule))


def test_too_few_states():
    assert any("num_states" in p for p in validate_rule(_rule(states=1, transitions={})))


def test_duplicate_names_in_bundle():
    assert any("duplicate rule names" in p for p in validate_bundle([_rule("a"), _rule("a")]))


def test_validate_bundle_aggregates_rule_problems():
    bad = _rule("bad", transitions={(0, 5): (1, 3)})
    assert any(p.startswith("rule 'bad':") for p in validate_bundle([_rule("ok"), bad]))


# --- round-trip --------------------------------------------------------------------


def test_roundtrip_handwritten():
    rules = [load_rule(p) for p in HAND_RULES]
    assert roundtrip_ok(rules) == []


def test_roundtrip_sigma():
    rules = [compile_sigma(p) for p in SIGMA_RULES]
    assert roundtrip_ok(rules) == []


# --- wiring: compile rejects an invalid generated set ------------------------------


def test_compile_rejects_invalid_bundle(tmp_path, monkeypatch):
    from ariguard_compiler import emit

    rules = [_rule(f"r{i}") for i in range(17)]  # exceeds MAX_RULES
    monkeypatch.setattr(emit, "load_rule", lambda _p: rules.pop(0))
    with pytest.raises(RuleError, match="invalid rule bundle"):
        emit.compile_files([Path(f"x{i}.yml") for i in range(17)])
