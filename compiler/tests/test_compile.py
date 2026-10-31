"""Compile the example rule and assert the bundle matches the ABI."""

from __future__ import annotations

from pathlib import Path

import pytest

from statewall_compiler.emit import BINDING, HEADER, MAGIC, TRANSITION, VERSION, emit_bundle
from statewall_compiler.schema import RuleError, load_rule, parse_rule

RULE = Path(__file__).resolve().parents[1] / "rules" / "container-escape.yml"

TRANSITIONS = [{"from": "normal", "event": "e", "to": "suspicious"}]


def _transition(bundle: bytes, num_events: int, state: int, event: int) -> tuple[int, int]:
    offset = HEADER.size + (state * num_events + event) * TRANSITION.size
    return TRANSITION.unpack_from(bundle, offset)


def _binding(bundle: bytes, num_transitions: int, index: int) -> tuple[int, int, int, int, bytes]:
    offset = HEADER.size + num_transitions * TRANSITION.size + index * BINDING.size
    return BINDING.unpack_from(bundle, offset)


def _rule(events: dict, **extra) -> dict:
    return {
        "states": ["normal", "suspicious"],
        "events": events,
        "transitions": TRANSITIONS,
        **extra,
    }


def test_header_bytes():
    bundle = emit_bundle(load_rule(RULE))
    assert bundle[:32] == bytes.fromhex(
        "54425453"  # magic "STBT" LE
        "02000000"  # version 2
        "05000000"  # num_states 5
        "04000000"  # num_events 4
        "07000000"  # num_bindings 7
        "00000000"  # reserved
        "00ac23fc06000000"  # window_ns 30e9
    )
    magic, version, num_states, num_events, num_bindings, reserved, window_ns = HEADER.unpack_from(
        bundle, 0
    )
    assert (magic, version, reserved) == (MAGIC, VERSION, 0)
    assert window_ns == 30 * 1_000_000_000
    assert len(bundle) == HEADER.size + num_states * num_events * TRANSITION.size + (
        num_bindings * BINDING.size
    )


def test_transitions_and_default():
    bundle = emit_bundle(load_rule(RULE))
    # escalating(2) + host_mount(2) -> breakout_imminent(3), deny(2)
    assert _transition(bundle, 4, 2, 2) == (3, 2)
    # Unspecified pair defaults to (same_state, OBSERVE=0).
    assert _transition(bundle, 4, 4, 0) == (4, 0)


def test_bindings_expansion_order():
    fsm = load_rule(RULE)
    bundle = emit_bundle(fsm)
    prefixes = [b"/run/containerd/containerd.sock", b"/var/run/docker.sock", b"/run/docker.sock"]
    for i, prefix in enumerate(prefixes):
        hook, event, kind, plen, pattern = _binding(bundle, 20, i)
        assert (hook, event, kind, plen) == (0, 0, 1, len(prefix))
        assert pattern == prefix.ljust(64, b"\0")
    expected_any = [(1, 1), (2, 1), (3, 2), (4, 3)]
    for i, (hook, event) in enumerate(expected_any, start=3):
        assert _binding(bundle, 20, i) == (hook, event, 0, 0, b"\0" * 64)


def test_window_absent_is_zero():
    fsm = parse_rule(_rule({"e": {"hooks": ["execve"]}}))
    assert fsm.window_ns == 0


@pytest.mark.parametrize(
    "rule",
    [
        _rule({"e": {"hooks": ["open"]}}),
        _rule({"e": ["openat"]}),
        _rule({"e": {"hooks": ["openat"], "path_prefix": [""]}}),
        _rule({"e": {"hooks": ["openat"], "path_prefix": ["/" + "a" * 64]}}),
        _rule({"e": {"hooks": ["openat"], "path_prefix": ["/a", "/b", "/c", "/d", "/e"]}}),
        _rule(
            {
                "e": {"hooks": ["openat"], "path_prefix": ["/a", "/b", "/c"]},
                "f": {"hooks": ["openat", "setns"], "path_prefix": ["/d", "/e"]},
            }
        ),
        _rule({"e": {"hooks": ["execve"]}}, window_seconds=-1),
        _rule({"e": {"hooks": ["execve"]}}, window_seconds=1.5),
        _rule({"e": {"hooks": ["execve"]}}, window_seconds=True),
        {**_rule({"e": {"hooks": ["execve"]}}), "states": ["normal", "bogus"]},
    ],
)
def test_rejects_invalid_rules(rule):
    with pytest.raises(RuleError):
        parse_rule(rule)


def test_rejects_too_many_transitions():
    events = {f"e{i}": {"hooks": ["execve"]} for i in range(205)}
    rule = {
        "states": ["normal", "suspicious", "escalating", "breakout_imminent", "compromised"],
        "events": events,
        "transitions": [{"from": "normal", "event": "e0", "to": "suspicious"}],
    }
    with pytest.raises(RuleError, match="max is 1024"):
        parse_rule(rule)


def test_rejects_oversized_table():
    fsm = load_rule(RULE)
    with pytest.raises(ValueError):
        emit_bundle(fsm, max_entries=4)
