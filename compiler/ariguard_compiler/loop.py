"""The autonomous rule-generation loop (F11): keep the fleet's policy current, cheaply, no LLM.

This is the orchestrator that wires the already-built pieces into one closed loop:

* **learn** -- load a labeled trace corpus (fleet baseline + honeypot/attack) and mine novel
  kill-chains with :mod:`ariguard_compiler.autogen` (frequency statistics + the deterministic gate);
* **ingest** -- compile the community detection feeds we can express
  (:mod:`ariguard_compiler.feeds`), so the library tracks the market for free;
* **build** -- link the hand-written rules, the generated Sigma rules, the feed rules and the mined
  rules into one bundle, with every self-proposed rule in **shadow** (observe terminal, never kills);
* **promote** -- read each rule's measured behavior from the console (hits, false positives, days
  observed) and let :func:`decide_mode` promote a proven shadow rule to enforce, hold it, or retire
  one that fired on benign traffic;
* **distribute** -- ``PUT`` the compiled bundle to the console (F7); agents poll and hot-swap it
  with no image rebuild.

Everything here is stdlib-only and offline except the two console calls (plain ``urllib``): no
model, no API key, deterministic for a given corpus + telemetry.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import autogen, feeds, mine, trace
from .autogen import ENFORCE, RETIRE, SHADOW, AutoRule, ShadowMetrics, decide_mode
from .emit import _validate, emit_bundle, rule_files
from .schema import MAX_BINDINGS_PER_HOOK, MAX_RULES, Rule, RuleError, load_rule, parse_rule

NS_PER_DAY = 86_400 * 1_000_000_000


# --- console I/O (F7) -------------------------------------------------------------------------


def pull_audit(
    console: str, *, since: int = 0, limit: int = 20_000, timeout: float = 30.0
) -> list[dict]:
    """Pull raw audit events (JSONL) from the console for a mining pass.

    Returns the parsed rows with ``id > since``, oldest first, so the caller can page by the last
    id. An empty/204 response yields ``[]``.
    """
    url = f"{console.rstrip('/')}/api/v1/audit/export?since={int(since)}&limit={int(limit)}"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    return [json.loads(line) for line in body.splitlines() if line.strip()]


def fetch_telemetry(console: str, *, timeout: float = 30.0) -> dict[str, ShadowMetrics]:
    """Read per-rule observed behavior from the console and map it to :class:`ShadowMetrics`."""
    url = f"{console.rstrip('/')}/api/v1/rules/telemetry"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        rows = json.loads(resp.read().decode("utf-8") or "[]")
    return {r["rule"]: _metrics(r) for r in rows}


def _metrics(row: dict) -> ShadowMetrics:
    first, last = int(row.get("first_seen_ns", 0)), int(row.get("last_seen_ns", 0))
    days = (last - first) / NS_PER_DAY if last > first else 0.0
    return ShadowMetrics(
        attack_hits=int(row.get("hits", 0)),
        benign_fires=int(row.get("benign_fires", 0)),
        days_observed=days,
    )


def push_bundle(console: str, bundle: bytes, *, timeout: float = 30.0) -> str:
    """PUT the compiled bundle to the control plane (F7); returns the stored version."""
    url = f"{console.rstrip('/')}/api/v1/policy"
    req = urllib.request.Request(url, data=bundle, method="PUT")
    req.add_header("Content-Type", "application/octet-stream")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.headers.get("X-Policy-Version", "")


# --- the build ---------------------------------------------------------------------------------


@dataclass
class BuildResult:
    """The outcome of one loop pass, before (or instead of) distribution."""

    rules: list[Rule]
    bundle: bytes
    auto: list[AutoRule]
    decisions: dict[str, str] = field(
        default_factory=dict
    )  # auto-rule name -> shadow|enforce|retire
    skipped_feeds: list[tuple[str, str]] = field(default_factory=list)
    skipped_budget: list[str] = field(default_factory=list)  # proposals dropped: rule/binding cap

    @property
    def summary(self) -> str:
        promoted = [n for n, m in self.decisions.items() if m == ENFORCE]
        retired = [n for n, m in self.decisions.items() if m == RETIRE]
        shadow = [n for n, m in self.decisions.items() if m == SHADOW]
        return (
            f"{len(self.rules)} rules in bundle ({len(self.bundle)} bytes); "
            f"auto: {len(shadow)} shadow, {len(promoted)} promoted, {len(retired)} retired; "
            f"feeds skipped: {len(self.skipped_feeds)}; budget skipped: {len(self.skipped_budget)}"
        )


def _base_rules(rules_dir: str | None, sigma_dir: str | None) -> list[Rule]:
    """The curated library: hand-written YAML rules plus the generated Sigma rules."""
    rules = [load_rule(f) for f in rule_files(rules_dir)]
    if sigma_dir:
        from . import sigma

        rules += [sigma.compile_sigma(f) for f in rule_files(sigma_dir)]
    return rules


def build_bundle(
    *,
    rules_dir: str | None = None,
    sigma_dir: str | None = None,
    corpus: str | None = None,
    feeds_dir: str | None = None,
    telemetry: dict[str, ShadowMetrics] | None = None,
    name_prefix: str = "auto",
    **autogen_kwargs,
) -> BuildResult:
    """One deterministic loop pass: learn + ingest + build (+ promote), returning the linked bundle.

    The curated library is always enforced. Community-feed and mined rules are *proposals*: they
    enter in shadow and are only switched to enforce by :func:`decide_mode` on their measured
    ``telemetry``. A rule that fired on benign (muted) traffic is retired. The result is capped at
    ``MAX_RULES`` -- the curated library first, then the highest-scoring survivors.
    """
    telemetry = telemetry or {}
    base = _base_rules(rules_dir, sigma_dir)

    feed_result = feeds.ingest_dir(feeds_dir) if feeds_dir else feeds.FeedResult()

    auto: list[AutoRule] = []
    if corpus:
        traces = trace.load(corpus)
        auto = [
            r
            for r in autogen.autogenerate(traces, name_prefix=name_prefix, **autogen_kwargs)
            if r.accepted
        ]

    # Decide each proposal's mode from its measured behavior, newest rule = shadow by default.
    proposals: list[tuple[Rule, str, str]] = []  # (rule, name, mode), highest score first
    decisions: dict[str, str] = {}
    for fr in feed_result.rules:
        mode = _decide(fr.name, telemetry)
        if mode == RETIRE:
            decisions[fr.name] = RETIRE
            continue
        decisions[fr.name] = mode
        proposals.append((fr, fr.name, mode))  # feed rules keep their authored actions
    for ar in sorted(auto, key=lambda r: -r.candidate.score):
        mode = _decide(ar.name, telemetry)
        decisions[ar.name] = mode
        if mode == RETIRE:
            continue
        rule_dict = mine.candidate_to_rule(
            ar.candidate,
            ar.name,
            scope=autogen_kwargs.get("scope", "process"),
            window_seconds=autogen_kwargs.get("window_seconds", mine.DEFAULT_WINDOW_SECONDS),
            enforce=(mode == ENFORCE),
        )
        proposals.append((parse_rule(rule_dict), ar.name, mode))

    if len(base) > MAX_RULES:
        raise RuleError(f"curated library alone has {len(base)} rules, over the {MAX_RULES} cap")

    # Admit proposals that fit both the rule-count cap and the per-hook binding budget. The curated
    # library has priority, so a busy hook (e.g. execve at capacity) can leave no room for a mined
    # rule; that proposal is skipped this pass rather than failing the whole build.
    tally: dict[int, int] = {}
    for ru in base:
        for b in ru.bindings:
            tally[b.hook] = tally.get(b.hook, 0) + 1
    chosen: list[Rule] = []
    skipped_budget: list[str] = []
    for rule, name, _ in proposals:
        add: dict[int, int] = {}
        for b in rule.bindings:
            add[b.hook] = add.get(b.hook, 0) + 1
        over_rules = len(base) + len(chosen) >= MAX_RULES
        over_bindings = any(tally.get(h, 0) + n > MAX_BINDINGS_PER_HOOK for h, n in add.items())
        if over_rules or over_bindings:
            skipped_budget.append(name)
            continue
        for h, n in add.items():
            tally[h] = tally.get(h, 0) + n
        chosen.append(rule)
    rules = base + chosen

    _validate(rules)
    bundle = emit_bundle(rules)
    kept = {r.name for r in chosen}
    decisions = {n: m for n, m in decisions.items() if m == RETIRE or n in kept}
    return BuildResult(rules, bundle, auto, decisions, feed_result.skipped, skipped_budget)


def _decide(name: str, telemetry: dict[str, ShadowMetrics]) -> str:
    """A proposed rule's mode: shadow until the console's telemetry promotes or retires it."""
    m = telemetry.get(name)
    return decide_mode(m) if m else SHADOW


# --- CLI ---------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ariguard-rulegen-loop",
        description="Autonomous rule-generation loop: learn + ingest feeds + build + promote + "
        "distribute, no LLM.",
    )
    parser.add_argument("--rules-dir", help="curated hand-written rules (always enforced)")
    parser.add_argument("--sigma-dir", help="generated Sigma correlation rules")
    parser.add_argument("--corpus", help="labeled trace corpus to mine (fleet baseline + honeypot)")
    parser.add_argument("--feeds", help="directory of community Sigma rules to ingest")
    parser.add_argument("--console", help="console base URL; pull telemetry, push the bundle (F7)")
    parser.add_argument("--out", help="also write the compiled bundle here")
    parser.add_argument("--name-prefix", default="auto")
    parser.add_argument("--scope", default="process", choices=["process", "cgroup"])
    parser.add_argument("--window-seconds", type=int, default=mine.DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--dry-run", action="store_true", help="build and report, never push")
    args = parser.parse_args(argv)

    if not args.rules_dir and not args.sigma_dir:
        parser.error("need at least --rules-dir or --sigma-dir for the curated library")

    telemetry: dict[str, ShadowMetrics] = {}
    if args.console and not args.dry_run:
        try:
            telemetry = fetch_telemetry(args.console)
        except (urllib.error.URLError, OSError) as exc:
            print(
                f"ariguard-rulegen-loop: telemetry fetch failed, treating all as shadow: {exc}",
                file=sys.stderr,
            )

    try:
        result = build_bundle(
            rules_dir=args.rules_dir,
            sigma_dir=args.sigma_dir,
            corpus=args.corpus,
            feeds_dir=args.feeds,
            telemetry=telemetry,
            name_prefix=args.name_prefix,
            scope=args.scope,
            window_seconds=args.window_seconds,
        )
    except (RuleError, trace.TraceError, OSError) as exc:
        print(f"ariguard-rulegen-loop: {exc}", file=sys.stderr)
        return 2

    for name, modeval in sorted(result.decisions.items()):
        print(f"  {modeval.upper():8} {name}")
    print(result.summary)

    if args.out:
        Path(args.out).write_bytes(result.bundle)
        print(f"wrote bundle -> {args.out}")

    if args.console and not args.dry_run:
        try:
            version = push_bundle(args.console, result.bundle)
        except (urllib.error.URLError, OSError) as exc:
            print(f"ariguard-rulegen-loop: push failed: {exc}", file=sys.stderr)
            return 1
        print(f"pushed bundle -> {args.console} (version {version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
