"""Mine kill-chain rules from labeled syscall-hook traces (the data-driven path, A1/A2).

Instead of hand-writing a rule, learn it from the *difference* between attack and benign runs:

1. **Frequent ordered subsequences** of hooks in the attack traces (a gap-allowed PrefixSpan).
2. **Contrast filter**: keep only subsequences frequent in attack and (near-)absent in benign,
   scored ``attack_support - benign_support``. A subsequence every workload performs (e.g.
   ``connect -> execve``) scores ~0 and is dropped -- the benign twin is the automatic
   false-positive killer.
3. **Candidate -> rule**: the winning subsequence becomes an FSM ``temporal_ordered`` rule
   (one state per step, the last step ``kill``), with a path/``inet`` predicate inferred when
   the attack traces agree on one.
4. **Gate**: every candidate must pass the same bar as a hand-written rule -- the schema
   (:func:`ariguard_compiler.schema.parse_rule`), the A4 checks
   (:mod:`ariguard_compiler.validate`) and a behavioral replay (fire on every attack trace,
   stay silent on every benign one). Mining proposes; the gate disposes.

Everything here is pure and deterministic: given the same traces it yields the same rules, with
no model to train and no network. The output is explainable -- each rule carries the exact
subsequence it was learned from and its contrast score.
"""

from __future__ import annotations

import argparse
import math
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import trace
from .schema import HOOK_VALUES, PATH_ARGS, PATH_INET, PATH_PREFIX, RuleError, parse_rule
from .validate import roundtrip_ok, validate_rule

# Defaults: a chain must appear in every attack trace and in no benign trace, be at least two
# steps long, and fit a small state budget.
MIN_SUPPORT = 1.0
MAX_BENIGN_SUPPORT = 0.0
MIN_LEN = 2
MAX_LEN = 6
DEFAULT_WINDOW_SECONDS = 10


@dataclass(frozen=True)
class Candidate:
    """A mined ordered hook subsequence and how well it separates attack from benign."""

    hooks: tuple[str, ...]
    attack_support: float
    benign_support: float
    predicates: tuple[dict | None, ...] = ()

    @property
    def score(self) -> float:
        return self.attack_support - self.benign_support


# --- frequent ordered subsequences (gap-allowed PrefixSpan) ------------------------------------


def _prefixspan(seqs: list[list[str]], min_count: int, max_len: int) -> dict[tuple[str, ...], int]:
    """Frequent ordered subsequences (items may be non-contiguous) with per-sequence support
    >= ``min_count``. Returns pattern -> number of distinct sequences containing it."""
    results: dict[tuple[str, ...], int] = {}

    def project(prefix: tuple[str, ...], projected: list[tuple[int, int]]) -> None:
        # projected: (sequence id, index to resume from). Each sequence appears at most once.
        firsts: dict[str, list[tuple[int, int]]] = {}
        for sid, start in projected:
            seq = seqs[sid]
            seen: set[str] = set()
            for j in range(start, len(seq)):
                item = seq[j]
                if item in seen:
                    continue
                seen.add(item)
                firsts.setdefault(item, []).append((sid, j + 1))
        for item, newproj in firsts.items():
            if len(newproj) < min_count:
                continue
            pattern = prefix + (item,)
            results[pattern] = len(newproj)
            if len(pattern) < max_len:
                project(pattern, newproj)

    project((), [(sid, 0) for sid in range(len(seqs))])
    return results


def _contains(seq: list[str], pattern: tuple[str, ...]) -> bool:
    it = iter(seq)
    return all(any(x == p for x in it) for p in pattern)


def _support_fraction(seqs: list[list[str]], pattern: tuple[str, ...]) -> float:
    if not seqs:
        return 0.0
    return sum(1 for s in seqs if _contains(s, pattern)) / len(seqs)


# --- predicate inference ----------------------------------------------------------------------


def _common_prefix(paths: list[str]) -> str | None:
    """A path prefix shared by every occurrence: the full path when identical, else the common
    leading text cut back to the last ``/`` boundary. None when there is no useful prefix."""
    if not paths or any(p is None for p in paths):
        return None
    if len(set(paths)) == 1:
        return paths[0]
    common = os.path.commonprefix(paths)
    cut = common.rfind("/")
    common = common[:cut] if cut > 0 else common
    return common if len(common) > 1 else None


def _infer_predicate(hook: str, occurrences: list[trace.Event]) -> dict | None:
    """A predicate shared by every attack occurrence of ``hook`` at this chain position."""
    if hook == "connect":
        if occurrences and all(e.inet for e in occurrences):
            return {"inet": True}
        return None
    if hook in PATH_ARGS:
        paths = [e.path for e in occurrences]
        if paths and all(p for p in paths):
            prefix = _common_prefix([p for p in paths if p])
            if prefix and len(prefix) > 1:
                return {"path_prefix": [prefix]}
    return None


def _occurrences(
    attack_traces: list[trace.Trace], hooks: tuple[str, ...]
) -> list[list[trace.Event]]:
    """For each chain position, the attack events that realise it (first matching occurrence per
    trace), used to infer predicates."""
    per_pos: list[list[trace.Event]] = [[] for _ in hooks]
    for t in attack_traces:
        i = 0
        for ev in t.events:
            if i < len(hooks) and ev.hook == hooks[i]:
                per_pos[i].append(ev)
                i += 1
        # a trace that does not fully realise the chain contributes only the positions it reached
    return per_pos


# --- mining -----------------------------------------------------------------------------------


def mine_candidates(
    traces: list[trace.Trace],
    *,
    min_support: float = MIN_SUPPORT,
    max_benign_support: float = MAX_BENIGN_SUPPORT,
    min_len: int = MIN_LEN,
    max_len: int = MAX_LEN,
    infer_predicates: bool = True,
) -> list[Candidate]:
    """Discriminative subsequences separating attack from benign, best contrast first."""
    attack = [t for t in traces if t.label == trace.ATTACK]
    benign = [t for t in traces if t.label == trace.BENIGN]
    if not attack:
        return []
    attack_hooks = [list(t.hooks) for t in attack]
    benign_hooks = [list(t.hooks) for t in benign]

    min_count = max(1, math.ceil(min_support * len(attack)))
    frequent = _prefixspan(attack_hooks, min_count, max_len)

    cands: list[Candidate] = []
    for pattern, count in frequent.items():
        if len(pattern) < min_len:
            continue
        a_sup = count / len(attack)
        b_sup = _support_fraction(benign_hooks, pattern)
        if a_sup < min_support or b_sup > max_benign_support:
            continue
        preds: tuple[dict | None, ...] = tuple(None for _ in pattern)
        if infer_predicates:
            occ = _occurrences([t for t in attack if _contains(list(t.hooks), pattern)], pattern)
            preds = tuple(_infer_predicate(h, occ[i]) for i, h in enumerate(pattern))
        cands.append(Candidate(pattern, a_sup, b_sup, preds))

    cands.sort(key=lambda c: (-round(c.score, 6), -len(c.hooks), c.hooks))
    return _drop_subsumed(cands)


def _drop_subsumed(cands: list[Candidate]) -> list[Candidate]:
    """Drop a candidate whose hook subsequence is contained in a kept, higher-ranked one."""
    kept: list[Candidate] = []
    for c in cands:
        if not any(_contains(list(k.hooks), c.hooks) for k in kept):
            kept.append(c)
    return kept


# --- candidate -> rule ------------------------------------------------------------------------


def candidate_to_rule(
    cand: Candidate,
    name: str,
    *,
    scope: str = "process",
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> dict:
    """Render a candidate as a kill-chain rule mapping (schema v3), ready for parse_rule."""
    hooks = cand.hooks
    intermediate = [f"s{i}" for i in range(1, len(hooks))]
    states = ["normal", *intermediate, "compromised"]
    events: dict[str, list[dict]] = {}
    transitions: list[dict] = []
    for i, hook in enumerate(hooks):
        ev = f"e{i}"
        binding: dict = {"hook": hook}
        pred = cand.predicates[i] if i < len(cand.predicates) else None
        if pred:
            binding.update(pred)
        events[ev] = [binding]
        transitions.append(
            {
                "from": states[i],
                "event": ev,
                "to": states[i + 1],
                "action": "kill" if i == len(hooks) - 1 else "observe",
            }
        )
    return {
        "name": name,
        "scope": scope,
        "window_seconds": window_seconds,
        "states": states,
        "terminal": ["compromised"],
        "events": events,
        "transitions": transitions,
    }


# --- behavioral replay (the data-driven half of the gate) -------------------------------------


def _event_indices(rule, ev: trace.Event) -> set[int]:
    """Rule-event indices raised by a trace event: hook matches and the predicate (if any) holds."""
    raised: set[int] = set()
    for b in rule.bindings:
        if b.hook != HOOK_VALUES[ev.hook]:
            continue
        if b.path_kind == PATH_PREFIX:
            pat = b.pattern.decode("utf-8", "replace")
            if ev.path is None or not ev.path.startswith(pat):
                continue
        elif b.path_kind == PATH_INET:
            if not ev.inet:
                continue
        raised.add(b.event)
    return raised


def simulate(rule, events: tuple[trace.Event, ...]) -> bool:
    """Replay a trace through ``rule``'s FSM; True when it reaches a terminal state.

    Mirrors the kernel engine's ordered semantics: a transition fires only from the current
    state on a raised event, and the whole chain must land within ``window_ns`` of its first
    non-``normal`` step (0 = no limit).
    """
    state = 0
    started_ns: int | None = None
    for ev in events:
        if rule.window_ns and started_ns is not None and ev.ts_ns - started_ns > rule.window_ns:
            state, started_ns = 0, None  # window elapsed: the partial chain resets
        for idx in sorted(_event_indices(rule, ev)):
            nxt = rule.transitions.get((state, idx))
            if nxt is None:
                continue
            state = nxt[0]
            if started_ns is None and state != 0:
                started_ns = ev.ts_ns
            if state >= rule.terminal_from:
                return True
    return False


def gate(rule_dict: dict, traces: list[trace.Trace]) -> list[str]:
    """Problems that keep a mined rule out of the library (empty = accepted)."""
    try:
        rule = parse_rule(rule_dict)
    except RuleError as exc:
        return [f"schema: {exc}"]
    problems = validate_rule(rule)
    problems += roundtrip_ok([rule])
    for t in traces:
        fired = simulate(rule, t.events)
        if t.label == trace.ATTACK and not fired:
            problems.append(f"does not fire on attack trace {t.source!r}")
        if t.label == trace.BENIGN and fired:
            problems.append(f"fires on benign trace {t.source!r}")
    return problems


# --- end to end -------------------------------------------------------------------------------


@dataclass
class Mined:
    """An accepted mined rule and its provenance."""

    name: str
    candidate: Candidate
    rule: dict
    problems: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return not self.problems


def mine_rules(
    traces: list[trace.Trace],
    *,
    name_prefix: str = "mined",
    scope: str = "process",
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    known_chains: set[tuple[str, ...]] = frozenset(),
    **mine_kwargs,
) -> list[Mined]:
    """Mine candidates, skip chains already in the library, build and gate each rule."""
    out: list[Mined] = []
    n = 0
    for cand in mine_candidates(traces, **mine_kwargs):
        if cand.hooks in known_chains:
            continue
        n += 1
        name = f"{name_prefix}-{'-'.join(cand.hooks)}"[:60].rstrip("-")
        rule = candidate_to_rule(cand, name, scope=scope, window_seconds=window_seconds)
        out.append(Mined(name=name, candidate=cand, rule=rule, problems=gate(rule, traces)))
    return out


def mine_sequences(traces: str) -> list:
    """Back-compat entry (CMP-3.2): accepted mined rule mappings from a trace file or directory."""
    loaded = trace.load(traces)
    return [m.rule for m in mine_rules(loaded) if m.accepted]


# --- CLI --------------------------------------------------------------------------------------


def _dump_rule(rule: dict) -> str:
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=100)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ariguard-mine",
        description="Learn kill-chain rules from labeled attack/benign syscall traces.",
    )
    parser.add_argument("traces", help="a scenario directory or a JSONL trace file")
    parser.add_argument("--out-dir", help="write each accepted rule as <name>.yml here")
    parser.add_argument("--name-prefix", default="mined")
    parser.add_argument("--scope", default="process", choices=["process", "cgroup"])
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--min-support", type=float, default=MIN_SUPPORT)
    parser.add_argument("--max-benign-support", type=float, default=MAX_BENIGN_SUPPORT)
    parser.add_argument("--min-len", type=int, default=MIN_LEN)
    parser.add_argument("--max-len", type=int, default=MAX_LEN)
    args = parser.parse_args(argv)

    try:
        traces = trace.load(args.traces)
    except (trace.TraceError, OSError) as exc:
        print(f"ariguard-mine: {exc}", file=sys.stderr)
        return 2

    mined = mine_rules(
        traces,
        name_prefix=args.name_prefix,
        scope=args.scope,
        window_seconds=args.window_seconds,
        min_support=args.min_support,
        max_benign_support=args.max_benign_support,
        min_len=args.min_len,
        max_len=args.max_len,
    )
    accepted = [m for m in mined if m.accepted]
    for m in mined:
        chain = " -> ".join(m.candidate.hooks)
        verdict = "ACCEPT" if m.accepted else "reject: " + "; ".join(m.problems)
        print(f"[{m.candidate.score:.2f}] {chain}  ({m.name}) {verdict}")
        if m.accepted and args.out_dir:
            path = Path(args.out_dir) / f"{m.name}.yml"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_dump_rule(m.rule), encoding="utf-8")
    print(f"\n{len(accepted)}/{len(mined)} candidate(s) accepted from {args.traces}")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
