"""Autonomous rule generation: keep the library current from data, no LLM, CPU-only.

The LLM co-author (A3) turned MITRE prose into rules at a per-call cost. This path needs neither.
It stays current from three cheap sources that all feed the existing miner + gate:

* **community feeds** (:mod:`ariguard_compiler.feeds`) -- the security community writes and updates
  detections for free; we ingest the ones our hooks can express;
* **honeypot / canary workloads** -- every trace they produce is attack-labeled by definition, a
  free stream of real, current attack behavior;
* **the fleet's own baseline** -- each workload's *normal* syscall subsequences, learned from
  benign runs; a subsequence that is novel against that baseline is a candidate.

This module is the engine for the last two. It learns a baseline, mines subsequences that are
frequent in the observed (honeypot/attack) traces yet novel against the baseline, runs the same
gate as a hand-written rule, and classifies each survivor as **shadow** (detect-only) until
measured hits with no false positives promote it to **enforce**. No model, no network, no API key
-- only frequency statistics and the deterministic gate. Autonomy without recklessness: nothing
kills a process from a rule that has not first proven itself in shadow on real traffic.
"""

from __future__ import annotations

import argparse
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import mine, trace
from .mine import Candidate, _contains, _drop_subsumed, _infer_predicate, _occurrences, _prefixspan

SHADOW = "shadow"
ENFORCE = "enforce"
RETIRE = "retire"


# --- the fleet baseline (self-supervised "normal") --------------------------------------------


@dataclass
class Baseline:
    """A workload's learned-normal profile: the ordered hook subsequences seen in benign runs and
    how many runs contained each. The autonomous analogue of a hand-written benign twin."""

    subsequences: dict[tuple[str, ...], int]
    runs: int

    def support(self, pattern: tuple[str, ...]) -> float:
        """Fraction of baseline runs that contain ``pattern`` (0.0 = never seen = fully novel)."""
        if self.runs == 0:
            return 0.0
        return self.subsequences.get(pattern, 0) / self.runs


def learn_baseline(traces: list[trace.Trace], *, max_len: int = mine.MAX_LEN) -> Baseline:
    """Learn the normal profile from the benign traces in ``traces``."""
    benign = [list(t.hooks) for t in traces if t.label == trace.BENIGN]
    if not benign:
        return Baseline({}, 0)
    freq = _prefixspan(benign, min_count=1, max_len=max_len)
    return Baseline(freq, runs=len(benign))


# --- novelty mining (frequent in attack, novel vs the baseline) -------------------------------


def mine_novel(
    traces: list[trace.Trace],
    baseline: Baseline,
    *,
    min_support: float = mine.MIN_SUPPORT,
    max_baseline_support: float = mine.MAX_BENIGN_SUPPORT,
    min_len: int = mine.MIN_LEN,
    max_len: int = mine.MAX_LEN,
    infer_predicates: bool = True,
) -> list[Candidate]:
    """Subsequences frequent in the attack traces but novel against the learned baseline."""
    attack = [t for t in traces if t.label == trace.ATTACK]
    if not attack:
        return []
    if baseline.runs == 0:
        mine.warn_no_baseline("mine_novel")
        return []
    attack_hooks = [list(t.hooks) for t in attack]
    min_count = max(1, math.ceil(min_support * len(attack)))
    frequent = _prefixspan(attack_hooks, min_count, max_len)

    cands: list[Candidate] = []
    for pattern, count in frequent.items():
        if len(pattern) < min_len:
            continue
        a_sup = count / len(attack)
        b_sup = baseline.support(pattern)
        if a_sup < min_support or b_sup > max_baseline_support:
            continue
        preds: tuple[dict | None, ...] = tuple(None for _ in pattern)
        if infer_predicates:
            occ = _occurrences([t for t in attack if _contains(list(t.hooks), pattern)], pattern)
            preds = tuple(_infer_predicate(h, occ[i]) for i, h in enumerate(pattern))
        cands.append(Candidate(pattern, a_sup, b_sup, preds))

    cands.sort(key=lambda c: (-round(c.score, 6), -len(c.hooks), c.hooks))
    return _drop_subsumed(cands)


# --- shadow -> enforce promotion (measured, not hoped) ----------------------------------------


@dataclass(frozen=True)
class ShadowMetrics:
    """What a shadow (detect-only) rule did on real traffic over an observation window."""

    attack_hits: int
    benign_fires: int
    days_observed: float


def decide_mode(
    m: ShadowMetrics, *, min_days: float = 7.0, min_hits: int = 1, max_benign_fires: int = 0
) -> str:
    """Promote, hold or retire a shadow rule from its measured behavior.

    A single false positive retires it (a killing rule must not fire on benign traffic); otherwise
    it is promoted to enforce once it has caught real attacks over a long enough window. Until then
    it stays in shadow, firing audits but never killing.
    """
    if m.benign_fires > max_benign_fires:
        return RETIRE
    if m.days_observed >= min_days and m.attack_hits >= min_hits:
        return ENFORCE
    return SHADOW


# --- the orchestrator -------------------------------------------------------------------------


@dataclass
class AutoRule:
    """A rule the system generated for itself, with its provenance and deploy mode."""

    name: str
    source: str  # "baseline-novel" | "honeypot" | "feed:<name>"
    candidate: Candidate
    rule: dict
    problems: list[str] = field(default_factory=list)
    mode: str = SHADOW  # newly minted rules always start in shadow

    @property
    def accepted(self) -> bool:
        return not self.problems


def autogenerate(
    traces: list[trace.Trace],
    *,
    source: str = "baseline-novel",
    name_prefix: str = "auto",
    scope: str = "process",
    window_seconds: int = mine.DEFAULT_WINDOW_SECONDS,
    known_chains: set[tuple[str, ...]] = frozenset(),
    **novel_kwargs,
) -> list[AutoRule]:
    """One autonomous pass over a trace corpus (fleet baseline + honeypot/attack).

    Learns the baseline from the benign traces, mines novel attack subsequences against it, builds
    a kill-chain rule for each, gates it (schema + A4 + behavioral replay on the same corpus) and
    returns the survivors in shadow mode. Chains already in the library are skipped.
    """
    baseline = learn_baseline(traces, max_len=novel_kwargs.get("max_len", mine.MAX_LEN))
    out: list[AutoRule] = []
    for cand in mine_novel(traces, baseline, **novel_kwargs):
        if cand.hooks in known_chains:
            continue
        name = mine.chain_name(name_prefix, cand.hooks)
        # Shadow by default: a freshly minted rule only audits (observe terminal), never kills,
        # until measured hits with no false positives promote it (see loop.decide_mode).
        rule = mine.candidate_to_rule(
            cand, name, scope=scope, window_seconds=window_seconds, enforce=False
        )
        out.append(
            AutoRule(
                name=name,
                source=source,
                candidate=cand,
                rule=rule,
                problems=mine.gate(rule, traces),
                mode=SHADOW,
            )
        )
    return out


# --- per-trace candidates (single-shot discovery from a honeypot) -----------------------------

# Rare, high-signal syscalls: they almost never occur in benign workloads, so a single attack that
# uses them is itself strong evidence — no frequency support across many runs needed. (Common hooks
# like openat/execve are excluded; they are everywhere and would overfit a one-off trace.)
RARE_HOOKS = frozenset(
    {
        "setns",
        "unshare",
        "mount",
        "fsmount",
        "move_mount",
        "ptrace",
        "memfd_create",
        "init_module",
        "finit_module",
        "bpf",
    }
)
# dup2/dup3 are deliberately excluded: shell redirections (2>/dev/null) use them constantly, so they
# add noise to a one-off backbone. An inet connect still anchors reverse-shell-style sessions.


def _backbone(t: trace.Trace) -> list[trace.Event]:
    """The rare-hook backbone of a trace: its high-signal syscalls (plus an inet connect), with
    consecutive duplicates collapsed and capped at MAX_LEN — the climax of the attack."""
    kept = [e for e in t.events if e.hook in RARE_HOOKS or (e.hook == "connect" and e.inet)]
    out: list[trace.Event] = []
    for e in kept:
        if out and out[-1].hook == e.hook:
            continue
        out.append(e)
    return out[: mine.MAX_LEN]


def backbone_rules(
    attack_traces: list[trace.Trace],
    baseline: list[trace.Trace],
    *,
    known_chains: set[tuple[str, ...]] = frozenset(),
    name_prefix: str = "auto",
    scope: str = "process",
    window_seconds: int = mine.DEFAULT_WINDOW_SECONDS,
) -> list[AutoRule]:
    """Propose one shadow rule per distinct attack *backbone* — single-shot discovery from a honeypot.

    Unlike contrast mining (which needs a pattern frequent across many runs), this turns each real
    attack's rare-hook backbone into a candidate directly, then gates it the same way (fires on the
    attack, silent on the benign baseline). Right for sparse, diverse honeypot traffic.
    """
    if attack_traces and not any(t.label == trace.BENIGN for t in baseline):
        mine.warn_no_baseline("backbone_rules")
        return []
    out: list[AutoRule] = []
    seen: set[tuple[str, ...]] = set()
    for t in attack_traces:
        bb = _backbone(t)
        hooks = tuple(e.hook for e in bb)
        if len(hooks) < mine.MIN_LEN or hooks in known_chains or hooks in seen:
            continue
        seen.add(hooks)
        preds = tuple({"inet": True} if (e.hook == "connect" and e.inet) else None for e in bb)
        cand = mine.Candidate(hooks, attack_support=1.0, benign_support=0.0, predicates=preds)
        name = mine.chain_name(name_prefix, hooks)
        rule = mine.candidate_to_rule(
            cand, name, scope=scope, window_seconds=window_seconds, enforce=False
        )
        out.append(
            AutoRule(
                name=name,
                source="honeypot",
                candidate=cand,
                rule=rule,
                problems=mine.gate(rule, [t, *baseline]),
                mode=SHADOW,
            )
        )
    return out


# --- CLI --------------------------------------------------------------------------------------


def _dump_rule(rule: dict) -> str:
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=100)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ariguard-autogen",
        description="Autonomously propose shadow rules from fleet/honeypot traces (no LLM).",
    )
    parser.add_argument("traces", help="a corpus directory (benign baseline + attack/honeypot)")
    parser.add_argument("--out-dir", help="write each accepted shadow rule as <name>.yml here")
    parser.add_argument("--name-prefix", default="auto")
    parser.add_argument("--scope", default="process", choices=["process", "cgroup"])
    parser.add_argument("--window-seconds", type=int, default=mine.DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--min-support", type=float, default=mine.MIN_SUPPORT)
    parser.add_argument("--max-baseline-support", type=float, default=mine.MAX_BENIGN_SUPPORT)
    parser.add_argument("--max-len", type=int, default=mine.MAX_LEN)
    args = parser.parse_args(argv)

    try:
        traces = trace.load(args.traces)
    except (trace.TraceError, OSError) as exc:
        print(f"ariguard-autogen: {exc}", file=sys.stderr)
        return 2

    rules = autogenerate(
        traces,
        name_prefix=args.name_prefix,
        scope=args.scope,
        window_seconds=args.window_seconds,
        min_support=args.min_support,
        max_baseline_support=args.max_baseline_support,
        max_len=args.max_len,
    )
    accepted = [r for r in rules if r.accepted]
    for r in rules:
        chain = " -> ".join(r.candidate.hooks)
        verdict = f"{r.mode.upper()}" if r.accepted else "reject: " + "; ".join(r.problems)
        print(f"[{r.candidate.score:.2f}] {chain}  ({r.name}) {verdict}")
        if r.accepted and args.out_dir:
            path = Path(args.out_dir) / f"{r.name}.yml"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_dump_rule(r.rule), encoding="utf-8")
    print(f"\n{len(accepted)} shadow rule(s) proposed from {args.traces}")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
