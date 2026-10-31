#!/usr/bin/env python3
"""Assert the Phase 1.5 / Phase 2 exit criteria on a Statewall v3 JSONL audit stream."""

import argparse
import itertools
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EXPECTATIONS = ROOT / "expectations.json"
FIXTURES = ROOT / "fixtures"
REQUIRED = ("ts_ns", "rule", "from", "to", "action", "namespace", "pod")

DRY, ENF = False, True
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
]


class BadInput(Exception):
    pass


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
                print(f"warning: {path}:{lineno}: skipping non-JSON line", file=sys.stderr)
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


def check(records, exp, enforce=False):
    ns = exp["namespace"]
    rules = exp["rules"]
    groups = defaultdict(list)
    for r in records:
        groups[(r["rule"], pod_id(r))].append(r)
    for recs in groups.values():
        recs.sort(key=lambda r: r["ts_ns"])

    failures = []
    for rule, spec in rules.items():
        for pod in spec["attackers"]:
            recs = groups.get((rule, (ns, pod)), [])
            if not recs:
                failures.append(("A1", "missing", f"{rule}: attacker {pod} has no records"))
            elif not follows_chain(recs, spec["chain"]):
                failures.append(
                    (
                        "A1",
                        "order",
                        f"{rule}: {pod} did not follow {' -> '.join(spec['chain'])} in order",
                    )
                )
    for (rule, pid), recs in groups.items():
        spec = rules.get(rule)
        attacker = bool(spec) and pid[0] == ns and pid[1] in spec["attackers"]
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
                    ("A3", "action", f"{rule}: {pod_label(pid)} got action {bad['action']}")
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
            elif r["action"] != "kill":
                failures.append(
                    (
                        "A4",
                        "action",
                        f"{rule}: {pod_label(pid)} has enforced=true with action {r['action']}",
                    )
                )
            if not enforce:
                failures.append(
                    ("A4", "dryrun", f"{rule}: {pod_label(pid)} has enforced=true in dry-run")
                )
        if enforce and attacker:
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
    for (rule, pid), recs in sorted(groups.items(), key=lambda kv: (kv[0][0], pod_label(kv[0][1]))):
        chain = rules.get(rule, {}).get("chain", [])
        rank = {s: i for i, s in enumerate(chain)}
        top = max((r["to"] for r in recs), key=lambda s: rank.get(s, -1))
        actions = ",".join(sorted({r["action"] for r in recs}))
        enforced = f"{sum(is_enforced(r) for r in recs)}/{len(recs)}"
        rows.append((rule, pod_label(pid), top, actions, enforced))
    widths = [max(len(row[i]) for row in rows) for i in range(5)]
    return "\n".join("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in rows)


def run(path, exp_path, enforce):
    exp = load_expectations(exp_path)
    records = load(path)
    groups, failures = check(records, exp, enforce)
    print(summary(groups, exp["rules"]))
    if failures:
        for a, _, msg in failures:
            print(f"FAIL ({a}): {msg}")
        return 1
    mode = "enforce" if enforce else "dry-run"
    print(
        f"PASS ({mode}): every rule's attackers followed their chain; nothing else reached a terminal state, got a non-observe action; enforcement only hit attackers"
    )
    return 0


def self_test(exp_path):
    exp = load_expectations(exp_path)
    failed = 0
    for name, enforce, expected in SELF_TESTS:
        _, failures = check(load(FIXTURES / name), exp, enforce)
        got = {(a, t) for a, t, _ in failures}
        ok = got == expected
        failed += not ok
        print(
            f"{'ok  ' if ok else 'FAIL'} {name} [{'enforce' if enforce else 'dry-run'}]: expected {sorted(expected) or 'pass'}, got {sorted(got) or 'pass'}"
        )
    print("self-test passed" if not failed else f"self-test failed: {failed} case(s)")
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit", nargs="?", help="JSONL audit file from statewall-agent")
    parser.add_argument(
        "--expectations", default=str(DEFAULT_EXPECTATIONS), help="expectations JSON"
    )
    parser.add_argument(
        "--self-test", action="store_true", help="run against testdata/fixtures in both modes"
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="enforce-mode run: attackers' terminal records must have enforced=true; default requires enforced=false everywhere",
    )
    args = parser.parse_args()
    if not args.self_test and not args.audit:
        parser.error("audit file or --self-test required")
    try:
        if args.self_test:
            return self_test(args.expectations)
        return run(args.audit, args.expectations, args.enforce)
    except (OSError, BadInput) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
