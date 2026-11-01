#!/usr/bin/env python3
"""Assert the Phase 1.5 / Phase 2 exit criteria on a AriGuard v3 JSONL audit stream."""

import argparse
import itertools
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EXPECTATIONS = ROOT / "expectations.json"
FIXTURES = ROOT / "fixtures"
# The self-test fixtures cover a fixed three-rule set; they use their own expectations so the
# deployed expectations.json can grow (more rules) without breaking the checker's self-test.
FIXTURE_EXPECTATIONS = FIXTURES / "expectations.json"
REQUIRED = ("ts_ns", "rule", "from", "to", "action", "namespace", "pod")

# (enforce, deny) mode markers.
DRY, ENF, DENY = (False, False), (True, False), (True, True)
SELF_TESTS = [
    ("pass.jsonl", DRY, set()),
    ("pass.jsonl", ENF, {("A4", "unenforced")}),
    ("fail-a1-missing-attacker.jsonl", DRY, {("A1", "missing")}),
    ("fail-a1-out-of-order.jsonl", DRY, {("A1", "order")}),
    ("fail-a2-benign-terminal.jsonl", DRY, {("A2", "pod")}),
    ("fail-a2-host-terminal.jsonl", DRY, {("A2", "host")}),
    ("fail-a3-benign-action.jsonl", DRY, {("A3", "action")}),
    ("pass-v2-dryrun.jsonl", DRY, set()),
    ("pass-v2-dryrun.jsonl", ENF, {("A4", "unenforced")}),
    ("pass-v2-enforce.jsonl", ENF, set()),
    ("pass-v2-enforce.jsonl", DRY, {("A4", "dryrun")}),
    ("fail-a4-benign-enforced.jsonl", ENF, {("A4", "pod")}),
    ("fail-a4-benign-enforced.jsonl", DRY, {("A4", "pod"), ("A4", "dryrun")}),
    ("fail-a4-host-enforced.jsonl", ENF, {("A4", "host")}),
    ("fail-a4-host-enforced.jsonl", DRY, {("A4", "host"), ("A4", "dryrun")}),
    ("fail-a4-action-not-kill.jsonl", ENF, {("A4", "action")}),
    ("fail-a4-action-not-kill.jsonl", DRY, {("A4", "action"), ("A4", "dryrun")}),
    ("fail-a4-enforce-missing.jsonl", ENF, {("A4", "unenforced")}),
    ("fail-a4-enforce-missing.jsonl", DRY, {("A4", "dryrun")}),
    # Phase 2b deny-mode (LSM -EPERM deny): container-escape is mitigated at
    # breakout_imminent; reverse-shell / fileless-exec still kill at compromised.
    ("pass-v3-deny.jsonl", DENY, set()),
    ("pass-v3-deny.jsonl", ENF, {("A1", "order"), ("A4", "action")}),
    ("fail-deny-reached-terminal.jsonl", DENY, {("A4", "reached-terminal")}),
    ("fail-deny-not-enforced.jsonl", DENY, {("A4", "deny-missing")}),
    ("fail-deny-benign-enforced.jsonl", DENY, {("A3", "action"), ("A4", "pod")}),
    (
        "pass-v2-enforce.jsonl",
        DENY,
        {("A4", "deny-missing"), ("A4", "reached-terminal"), ("A4", "action")},
    ),
]


class BadInput(Exception):
    pass


def pod_matches(pod, base):
    """A pod is an instance of attacker `base` when it equals it or is a generateName
    instance of it (`<base>-<suffix>`), so concurrent/soak instances are recognized."""
    return pod == base or pod.startswith(base + "-")


def load_expectations(path):
    try:
        with open(path, encoding="utf-8") as f:
            exp = json.load(f)
        exp["namespace"]
        for rule in exp["rules"].values():
            rule["terminal"], rule["chain"], rule["attackers"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
        raise BadInput(f"bad expectations {path}: {e}") from e
    return exp


def load(path):
    records = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                print(
                    f"warning: {path}:{lineno}: skipping non-JSON line", file=sys.stderr
                )
                continue
            if not isinstance(rec, dict) or any(k not in rec for k in REQUIRED):
                raise BadInput(f"{path}:{lineno}: not a v3 audit record")
            if not isinstance(rec.get("enforced", False), bool):
                raise BadInput(f"{path}:{lineno}: enforced must be a boolean")
            records.append(rec)
    if not records:
        raise BadInput(f"{path}: no audit records")
    return records


def pod_id(rec):
    return (rec["namespace"], rec["pod"])


def pod_label(pid):
    return f"{pid[0]}/{pid[1]}" if pid[1] else "(host)"


def follows_chain(recs, chain):
    steps = list(itertools.pairwise(chain))
    i = 0
    for r in recs:
        if i < len(steps) and (r["from"], r["to"]) == steps[i]:
            i += 1
    return i == len(steps)


def is_enforced(rec):
    return rec.get("enforced", False) is True


def check(records, exp, enforce=False, deny=False, soak=False):
    ns = exp["namespace"]
    rules = exp["rules"]
    groups = defaultdict(list)
    for r in records:
        groups[(r["rule"], pod_id(r))].append(r)
    for recs in groups.values():
        recs.sort(key=lambda r: r["ts_ns"])

    def deny_spec(spec):
        # Only honoured in deny-mode; a rule without one stays kill-at-terminal.
        return spec.get("deny") if deny else None

    def rule_chain(spec):
        d = deny_spec(spec)
        if d:
            chain = spec["chain"]
            return chain[: chain.index(d["terminal"]) + 1]
        return spec["chain"]

    def enforced_action(spec):
        d = deny_spec(spec)
        return d["action"] if d else "kill"

    failures = []
    for rule, spec in rules.items():
        chain = rule_chain(spec)
        for base in spec["attackers"]:
            instances = [
                (pid, recs)
                for (r, pid), recs in groups.items()
                if r == rule and pid[0] == ns and pod_matches(pid[1], base)
            ]
            if not instances:
                failures.append(
                    ("A1", "missing", f"{rule}: attacker {base} has no records")
                )
                continue
            if soak:
                # Under sustained load with pruning, individual instances may be cut short;
                # require that at least one instance completed the chain (and was enforced in
                # enforce mode). The false-positive guarantees (A2/A3/A4 below) stay strict.
                completed = [
                    recs for _, recs in instances if follows_chain(recs, chain)
                ]
                if not completed:
                    failures.append(
                        (
                            "A1",
                            "soak-none",
                            f"{rule}: no {base} instance completed {' -> '.join(chain)} under load",
                        )
                    )
                elif enforce and not any(
                    is_enforced(r)
                    for recs in completed
                    for r in recs
                    if r["to"] == spec["terminal"]
                ):
                    failures.append(
                        (
                            "A4",
                            "soak-unenforced",
                            f"{rule}: no {base} instance was enforced at {spec['terminal']} under load",
                        )
                    )
                continue
            for pid, recs in instances:
                if not follows_chain(recs, chain):
                    failures.append(
                        (
                            "A1",
                            "order",
                            f"{rule}: {pid[1]} did not follow {' -> '.join(chain)} in order",
                        )
                    )
    for (rule, pid), recs in groups.items():
        spec = rules.get(rule)
        attacker = (
            bool(spec)
            and pid[0] == ns
            and any(pod_matches(pid[1], b) for b in spec["attackers"])
        )
        if spec and not attacker and any(r["to"] == spec["terminal"] for r in recs):
            failures.append(
                (
                    "A2",
                    "pod" if pid[1] else "host",
                    f"{rule}: {pod_label(pid)} reached {spec['terminal']}",
                )
            )
        if not attacker:
            bad = next((r for r in recs if r["action"] != "observe"), None)
            if bad:
                failures.append(
                    (
                        "A3",
                        "action",
                        f"{rule}: {pod_label(pid)} got action {bad['action']}",
                    )
                )
        for r in recs:
            if not is_enforced(r):
                continue
            if not attacker:
                failures.append(
                    (
                        "A4",
                        "pod" if pid[1] else "host",
                        f"{rule}: {pod_label(pid)} has enforced=true but is not an attacker",
                    )
                )
            elif r["action"] != enforced_action(spec):
                failures.append(
                    (
                        "A4",
                        "action",
                        f"{rule}: {pod_label(pid)} has enforced=true with action {r['action']}",
                    )
                )
            if not enforce:
                failures.append(
                    (
                        "A4",
                        "dryrun",
                        f"{rule}: {pod_label(pid)} has enforced=true in dry-run",
                    )
                )
        if enforce and attacker:
            d = deny_spec(spec)
            if d:
                if not any(
                    r["to"] == d["terminal"]
                    and r["action"] == d["action"]
                    and is_enforced(r)
                    for r in recs
                ):
                    failures.append(
                        (
                            "A4",
                            "deny-missing",
                            f"{rule}: {pod_label(pid)} has no enforced {d['action']} at {d['terminal']}",
                        )
                    )
                if any(r["to"] == spec["terminal"] for r in recs):
                    failures.append(
                        (
                            "A4",
                            "reached-terminal",
                            f"{rule}: {pod_label(pid)} reached {spec['terminal']} despite deny",
                        )
                    )
            elif not soak:
                for r in recs:
                    if r["to"] == spec["terminal"] and not is_enforced(r):
                        failures.append(
                            (
                                "A4",
                                "unenforced",
                                f"{rule}: {pod_label(pid)} terminal record has no enforced=true",
                            )
                        )
    return groups, failures


def summary(groups, rules):
    rows = [("rule", "pod", "max_state", "actions", "enforced")]
    for (rule, pid), recs in sorted(
        groups.items(), key=lambda kv: (kv[0][0], pod_label(kv[0][1]))
    ):
        chain = rules.get(rule, {}).get("chain", [])
        rank = {s: i for i, s in enumerate(chain)}
        top = max((r["to"] for r in recs), key=lambda s: rank.get(s, -1))
        actions = ",".join(sorted({r["action"] for r in recs}))
        enforced = f"{sum(is_enforced(r) for r in recs)}/{len(recs)}"
        rows.append((rule, pod_label(pid), top, actions, enforced))
    widths = [max(len(row[i]) for row in rows) for i in range(5)]
    return "\n".join(
        "  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in rows
    )


def mode_label(enforce, deny):
    return "deny" if deny else "enforce" if enforce else "dry-run"


def run(path, exp_path, enforce, deny=False, soak=False):
    exp = load_expectations(exp_path)
    records = load(path)
    groups, failures = check(records, exp, enforce, deny, soak)
    print(summary(groups, exp["rules"]))
    if failures:
        for a, _, msg in failures:
            print(f"FAIL ({a}): {msg}")
        return 1
    tail = (
        "every rule had >=1 attacker complete + be enforced under load; nothing else reached a terminal state, got a non-observe action, or was enforced"
        if soak
        else "every rule's attackers followed their chain; nothing else reached a terminal state, got a non-observe action; enforcement only hit attackers"
    )
    print(f"PASS ({mode_label(enforce, deny)}{', soak' if soak else ''}): {tail}")
    return 0


def self_test(_exp_path):
    exp = load_expectations(FIXTURE_EXPECTATIONS)
    failed = 0
    for name, (enforce, deny), expected in SELF_TESTS:
        _, failures = check(load(FIXTURES / name), exp, enforce, deny)
        got = {(a, t) for a, t, _ in failures}
        ok = got == expected
        failed += not ok
        print(
            f"{'ok  ' if ok else 'FAIL'} {name} [{mode_label(enforce, deny)}]: expected {sorted(expected) or 'pass'}, got {sorted(got) or 'pass'}"
        )
    print("self-test passed" if not failed else f"self-test failed: {failed} case(s)")
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit", nargs="?", help="JSONL audit file from ariguard-agent")
    parser.add_argument(
        "--expectations", default=str(DEFAULT_EXPECTATIONS), help="expectations JSON"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run against testdata/fixtures in both modes",
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="enforce-mode run: attackers' terminal records must have enforced=true; default requires enforced=false everywhere",
    )
    parser.add_argument(
        "--deny",
        action="store_true",
        help="deny-mode run (implies --enforce): deny-spec rules must be mitigated with an enforced deny at their deny terminal and must not reach the rule terminal; other rules still require an enforced kill",
    )
    parser.add_argument(
        "--soak",
        action="store_true",
        help="soak/load run: tolerate instances cut short under load (require >=1 completed + enforced per rule), keep the false-positive guarantees strict",
    )
    args = parser.parse_args()
    if not args.self_test and not args.audit:
        parser.error("audit file or --self-test required")
    enforce = args.enforce or args.deny
    try:
        if args.self_test:
            return self_test(args.expectations)
        return run(args.audit, args.expectations, enforce, args.deny, args.soak)
    except (OSError, BadInput) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
