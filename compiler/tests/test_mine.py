"""Data-driven rule mining (A1/A2): the algorithm on synthetic traces, then re-discovery of the
library's chains and discovery of a new one from the committed fixtures."""

from __future__ import annotations

from pathlib import Path

from ariguard_compiler import mine, trace
from ariguard_compiler.schema import parse_rule
from ariguard_compiler.validate import roundtrip_ok, validate_rule

ROOT = Path(__file__).resolve().parents[2]
TRACES = ROOT / "testdata" / "traces"


def _trace(label, *hooks, paths=None, inet=None):
    paths = paths or {}
    inet = inet or set()
    events = tuple(
        trace.Event(hook=h, ts_ns=i, path=paths.get(i), inet=(i in inet)) for i, h in enumerate(hooks)
    )
    return trace.Trace(label=label, events=events, source="|".join(hooks))


# --- PrefixSpan + support ---------------------------------------------------------------------


def test_prefixspan_finds_frequent_ordered_subsequences():
    seqs = [["a", "b", "c"], ["a", "x", "b", "c"], ["a", "b", "d"]]
    freq = mine._prefixspan(seqs, min_count=3, max_len=4)
    assert freq[("a",)] == 3
    assert freq[("a", "b")] == 3  # ordered, gap allowed (second seq has x between a and b)
    assert ("a", "b", "c") not in freq or freq[("a", "b", "c")] == 2  # only 2 of 3 reach c
    freq2 = mine._prefixspan(seqs, min_count=2, max_len=4)
    assert freq2[("a", "b", "c")] == 2


def test_contains_is_ordered_subsequence():
    assert mine._contains(["a", "x", "b", "c"], ("a", "b", "c"))
    assert not mine._contains(["a", "c", "b"], ("a", "b", "c"))  # wrong order


# --- contrast mining --------------------------------------------------------------------------


def test_contrast_keeps_discriminative_drops_common():
    traces = [
        _trace("attack", "openat", "setns", "mount", "execve"),
        _trace("attack", "openat", "setns", "mount", "execve"),
        _trace("benign", "openat", "execve"),
        _trace("benign", "openat", "mount", "execve"),  # has mount+execve but no setns
    ]
    cands = mine.mine_candidates(traces)
    best = cands[0]
    assert best.hooks == ("openat", "setns", "mount", "execve")
    assert best.attack_support == 1.0 and best.benign_support == 0.0
    # a subsequence present in both labels (openat -> execve) must not be a standalone candidate
    assert not any(c.hooks == ("openat", "execve") for c in cands)


def test_subsumed_shorter_chains_are_dropped():
    traces = [
        _trace("attack", "setns", "mount", "execve"),
        _trace("attack", "setns", "mount", "execve"),
        _trace("benign", "execve"),
    ]
    cands = mine.mine_candidates(traces)
    hooks = [c.hooks for c in cands]
    assert ("setns", "mount", "execve") in hooks
    assert ("setns", "mount") not in hooks  # contained in the kept longer chain


# --- predicate inference ----------------------------------------------------------------------


def test_predicate_inference_path_and_inet():
    traces = [
        _trace("attack", "connect", "mount", paths={1: "/mnt/a"}, inet={0}),
        _trace("attack", "connect", "mount", paths={1: "/mnt/b"}, inet={0}),
        _trace("benign", "execve"),
    ]
    cand = mine.mine_candidates(traces)[0]
    assert cand.hooks == ("connect", "mount")
    assert cand.predicates[0] == {"inet": True}
    assert cand.predicates[1] == {"path_prefix": ["/mnt"]}


# --- candidate -> rule is a first-class, valid rule -------------------------------------------


def test_candidate_to_rule_passes_the_schema_and_a4():
    cand = mine.Candidate(("openat", "setns", "mount", "execve"), 1.0, 0.0, (None, None, {"path_prefix": ["/mnt"]}, None))
    rule_dict = mine.candidate_to_rule(cand, "mined-escape")
    rule = parse_rule(rule_dict)  # schema accepts it
    assert rule.num_states == 5 and rule.terminal_from == 4
    assert validate_rule(rule) == []
    assert roundtrip_ok([rule]) == []


# --- behavioral replay ------------------------------------------------------------------------


def test_simulate_fires_on_attack_silent_on_benign():
    cand = mine.Candidate(("openat", "setns", "mount", "execve"), 1.0, 0.0)
    rule = parse_rule(mine.candidate_to_rule(cand, "mined-escape"))
    attack = (trace.Event("openat"), trace.Event("setns"), trace.Event("mount"), trace.Event("execve"))
    benign = (trace.Event("openat"), trace.Event("execve"))  # no setns/mount
    assert mine.simulate(rule, attack) is True
    assert mine.simulate(rule, benign) is False


def test_simulate_respects_the_window():
    cand = mine.Candidate(("setns", "execve"), 1.0, 0.0)
    rule = parse_rule(mine.candidate_to_rule(cand, "mined-x", window_seconds=1))
    within = (trace.Event("setns", ts_ns=0), trace.Event("execve", ts_ns=500_000_000))
    elapsed = (trace.Event("setns", ts_ns=0), trace.Event("execve", ts_ns=2_000_000_000))
    assert mine.simulate(rule, within) is True
    assert mine.simulate(rule, elapsed) is False  # chain reset: second step outside the window


# --- the gate ---------------------------------------------------------------------------------


def test_gate_accepts_a_discriminative_rule():
    traces = [
        _trace("attack", "setns", "mount", "execve"),
        _trace("benign", "openat", "execve"),
    ]
    cand = mine.mine_candidates(traces)[0]
    rule = mine.candidate_to_rule(cand, "mined-ok")
    assert mine.gate(rule, traces) == []


def test_gate_rejects_a_rule_that_fires_on_benign():
    # a hand-built over-broad rule (just execve) fires on the benign trace -> rejected
    bad = mine.candidate_to_rule(mine.Candidate(("openat", "execve"), 1.0, 1.0), "mined-bad")
    traces = [_trace("attack", "openat", "execve"), _trace("benign", "openat", "execve")]
    problems = mine.gate(bad, traces)
    assert any("benign" in p for p in problems)


# --- end to end on the committed fixtures -----------------------------------------------------


def test_rediscovers_container_escape_chain():
    traces = trace.load(TRACES / "container-escape")
    mined = [m for m in mine.mine_rules(traces) if m.accepted]
    assert mined, "no rule mined from the container-escape traces"
    top = mined[0]
    assert top.candidate.hooks == ("openat", "setns", "mount", "execve")
    assert top.rule["transitions"][-1]["action"] == "kill"
    assert mine.gate(top.rule, traces) == []


def test_rediscovers_reverse_shell_chain():
    traces = trace.load(TRACES / "reverse-shell")
    mined = [m for m in mine.mine_rules(traces) if m.accepted]
    chains = [m.candidate.hooks for m in mined]
    assert ("connect", "dup2", "execve") in chains
    # connect -> execve is benign-common and must not survive as a rule
    assert ("connect", "execve") not in chains


def test_discovers_a_new_chain_not_in_the_library():
    # module-tampering (finit_module -> bpf) is none of the three shipped rules: a rule the
    # system learns from data rather than being given.
    library = {
        ("openat", "setns", "mount", "execve"),
        ("connect", "dup2", "execve"),
        ("memfd_create", "execveat"),
    }
    traces = trace.load(TRACES / "module-tampering")
    mined = [m for m in mine.mine_rules(traces, known_chains=library) if m.accepted]
    assert ("finit_module", "bpf") in [m.candidate.hooks for m in mined]
    # bpf alone is benign (CNI, monitoring) -> no standalone bpf rule
    assert all(m.candidate.hooks != ("bpf",) for m in mined)


def test_known_chains_are_skipped():
    traces = trace.load(TRACES / "container-escape")
    known = {("openat", "setns", "mount", "execve")}
    mined = mine.mine_rules(traces, known_chains=known)
    assert all(m.candidate.hooks != ("openat", "setns", "mount", "execve") for m in mined)


def test_mine_sequences_backcompat_returns_accepted_rule_dicts():
    rules = mine.mine_sequences(str(TRACES / "reverse-shell"))
    assert isinstance(rules, list) and rules
    for r in rules:
        assert parse_rule(r)  # every returned mapping is a valid rule


def test_cli_writes_accepted_rule_files(tmp_path, capsys):
    out = tmp_path / "rules"
    code = mine.main([str(TRACES / "module-tampering"), "--out-dir", str(out), "--name-prefix", "learned"])
    assert code == 0
    written = list(out.glob("*.yml"))
    assert written, "the CLI wrote no rule file"
    rule = parse_rule(__import__("yaml").safe_load(written[0].read_text()))
    assert validate_rule(rule) == [] and roundtrip_ok([rule]) == []
    assert "ACCEPT" in capsys.readouterr().out


def test_cli_bad_path_exits_2(tmp_path):
    assert mine.main([str(tmp_path / "missing.jsonl")]) == 2
