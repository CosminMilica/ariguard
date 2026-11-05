"""Untrusted-input robustness: the parsers that consume data the operator did not author — honeypot
traces pulled from the console, and community Sigma feeds — must reject malformed input cleanly
(raise the typed error or skip), never crash with an unexpected exception."""

from __future__ import annotations

import pytest

from ariguard_compiler import feeds, strace, trace
from ariguard_compiler.schema import RuleError


@pytest.mark.parametrize(
    "obj",
    [
        {},  # no events
        {"events": []},  # empty events
        {"events": "nope"},  # events not a list
        {"label": "attack", "events": [{"hook": "not-a-syscall"}]},  # unknown hook
        {"label": "bogus", "events": [{"hook": "execve"}]},  # bad label
        {"events": [{"hook": "openat", "ts_ns": -1}]},  # negative ts
        {"events": [{"hook": "connect", "inet": "yes"}]},  # inet not bool
        {"events": [42]},  # event not an object
        "a string",  # not an object at all
        [1, 2, 3],  # a bare list of non-events
    ],
)
def test_from_records_rejects_malformed_cleanly(obj):
    # A hostile/garbled trace from the console must raise TraceError, not an arbitrary exception.
    with pytest.raises(trace.TraceError):
        trace.from_records([obj], default_label=trace.ATTACK)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\x00\x00\x00garbage\xff",
        "execve(\nunterminated",
        "1234    openat(",  # truncated args
        "not a syscall line at all",
        "+++ exited with 0 +++\n--- SIGKILL ---",
        "openat(" * 10000,  # pathological repetition
    ],
)
def test_strace_parser_never_crashes(text):
    # strace output is machine-generated but from an attacked honeypot; parsing must be total.
    t = strace.parse_text(text, source="fuzz")
    assert isinstance(t, trace.Trace)  # returns a (possibly empty) trace, never raises


def test_feed_ingest_skips_bad_rules(tmp_path):
    # a community feed directory with junk files: expressible rules compile, the rest are skipped,
    # never fatal.
    (tmp_path / "garbage.yml").write_text(": not valid yaml : [")
    (tmp_path / "empty.yml").write_text("")
    (tmp_path / "wrong.yml").write_text("title: x\ndetection: {sel: {syscall: nope}}\ncondition: sel\n")
    result = feeds.ingest_dir(tmp_path)
    assert result.expressible == 0
    assert len(result.skipped) >= 1  # recorded, not raised


def test_compile_sigma_raises_ruleerror_on_malformed(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: broken\ndetection: {}\n")
    from ariguard_compiler.sigma import compile_sigma

    with pytest.raises(RuleError):
        compile_sigma(bad)
