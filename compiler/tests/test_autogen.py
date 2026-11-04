"""Autonomous rule generation: learned baseline, novelty mining, shadow->enforce promotion, and
the end-to-end pass that proposes a shadow rule from fleet + honeypot traces."""

from __future__ import annotations

from pathlib import Path

from ariguard_compiler import autogen, mine, trace
from ariguard_compiler.schema import parse_rule
from ariguard_compiler.validate import roundtrip_ok, validate_rule

ROOT = Path(__file__).resolve().parents[2]
FLEET = ROOT / "testdata" / "traces" / "fleet"


def _t(label, *hooks, paths=None):
    paths = paths or {}
    events = tuple(trace.Event(hook=h, ts_ns=i, path=paths.get(i)) for i, h in enumerate(hooks))
    return trace.Trace(label=label, events=events, source="|".join(hooks))


# --- baseline ---------------------------------------------------------------------------------


def test_learn_baseline_captures_normal_subsequences():
    traces = [
        _t("benign", "openat", "connect", "execve"),
        _t("benign", "openat", "execve"),
        _t("attack", "unshare", "mount", "execve"),  # ignored for the baseline
    ]
    base = autogen.learn_baseline(traces)
    assert base.runs == 2
    assert base.support(("openat", "execve")) == 1.0  # in both benign runs
    assert base.support(("connect",)) == 0.5
    assert base.support(("unshare", "mount")) == 0.0  # never seen -> fully novel


# --- novelty mining ---------------------------------------------------------------------------


def test_mine_novel_finds_the_novel_chain_and_ignores_normal():
    traces = [
        _t("benign", "openat", "mount", "execve"),  # mount+execve is NORMAL here
        _t("benign", "openat", "connect", "execve"),
        _t("attack", "unshare", "mount", "execve"),
        _t("attack", "unshare", "mount", "execve"),
    ]
    base = autogen.learn_baseline(traces)
    cands = autogen.mine_novel(traces, base)
    best = cands[0]
    assert best.hooks == ("unshare", "mount", "execve")
    # mount -> execve is in the baseline, so it must not surface as a novel candidate on its own
    assert all(c.hooks != ("mount", "execve") for c in cands)


# --- promotion policy -------------------------------------------------------------------------


def test_decide_mode_shadow_enforce_retire():
    assert autogen.decide_mode(autogen.ShadowMetrics(0, 0, 0.0)) == autogen.SHADOW  # too fresh
    assert autogen.decide_mode(autogen.ShadowMetrics(3, 0, 2.0)) == autogen.SHADOW  # window too short
    assert autogen.decide_mode(autogen.ShadowMetrics(5, 0, 9.0)) == autogen.ENFORCE  # caught, clean
    assert autogen.decide_mode(autogen.ShadowMetrics(5, 1, 9.0)) == autogen.RETIRE  # a false positive
    assert autogen.decide_mode(autogen.ShadowMetrics(0, 0, 30.0)) == autogen.SHADOW  # never caught


# --- end to end on the fleet fixtures ---------------------------------------------------------


def test_autogenerate_proposes_a_shadow_rule_from_fleet_traces():
    traces = trace.load(FLEET)
    rules = autogen.autogenerate(traces)
    accepted = [r for r in rules if r.accepted]
    assert accepted, "no shadow rule proposed"
    top = accepted[0]
    assert top.candidate.hooks == ("unshare", "mount", "execve")
    assert top.mode == autogen.SHADOW  # never born enforcing
    assert top.source == "baseline-novel"
    # it is a first-class, valid rule and its last step kills
    rule = parse_rule(top.rule)
    assert validate_rule(rule) == [] and roundtrip_ok([rule]) == []
    assert top.rule["transitions"][-1]["action"] == "kill"
    # the gate held: fires on the honeypot traces, silent on the whole benign baseline
    assert mine.gate(top.rule, traces) == []


def test_autogenerate_skips_chains_already_in_the_library():
    traces = trace.load(FLEET)
    known = {("unshare", "mount", "execve")}
    rules = autogen.autogenerate(traces, known_chains=known)
    assert all(r.candidate.hooks != ("unshare", "mount", "execve") for r in rules)


# --- CLI --------------------------------------------------------------------------------------


def test_cli_writes_shadow_rule(tmp_path, capsys):
    out = tmp_path / "shadow"
    code = autogen.main([str(FLEET), "--out-dir", str(out), "--name-prefix", "auto"])
    assert code == 0
    written = list(out.glob("*.yml"))
    assert written
    rule = parse_rule(__import__("yaml").safe_load(written[0].read_text()))
    assert validate_rule(rule) == []
    assert "SHADOW" in capsys.readouterr().out


def test_cli_bad_path_exits_2(tmp_path):
    assert autogen.main([str(tmp_path / "nope")]) == 2
