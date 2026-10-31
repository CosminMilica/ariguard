#!/usr/bin/env python3
"""Assert the Phase 1.5 exit criteria on a Statewall v3 JSONL audit stream."""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EXPECTATIONS = ROOT / "expectations.json"
FIXTURES = ROOT / "fixtures"
REQUIRED = ("ts_ns", "rule", "from", "to", "action", "namespace", "pod")

SELF_TESTS = [
    ("pass.jsonl", set()),
    ("fail-a1-missing-attacker.jsonl", {("A1", "missing")}),
    ("fail-a1-out-of-order.jsonl", {("A1", "order")}),
    ("fail-a2-benign-terminal.jsonl", {("A2", "pod")}),
    ("fail-a2-host-terminal.jsonl", {("A2", "host")}),
    ("fail-a3-benign-action.jsonl", {("A3", "action")}),
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
            records.append(rec)
    if not records:
        raise BadInput(f"{path}: no audit records")
    return records


def pod_id(rec):
    return (rec["namespace"], rec["pod"])


def pod_label(pid):
    return f"{pid[0]}/{pid[1]}" if pid[1] else "(host)"


def follows_chain(recs, chain):
    steps = list(zip(chain, chain[1:]))
    i = 0
    for r in recs:
        if i < len(steps) and (r["from"], r["to"]) == steps[i]:
            i += 1
    return i == len(steps)


def check(records, exp):
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
                    ("A1", "order", f"{rule}: {pod} did not follow {' -> '.join(spec['chain'])} in order")
                )
    for (rule, pid), recs in groups.items():
        spec = rules.get(rule)
        attacker = bool(spec) and pid[0] == ns and pid[1] in spec["attackers"]
        if spec and not attacker and any(r["to"] == spec["terminal"] for r in recs):
            failures.append(
                ("A2", "pod" if pid[1] else "host", f"{rule}: {pod_label(pid)} reached {spec['terminal']}")
            )
        if not attacker:
            bad = next((r for r in recs if r["action"] != "observe"), None)
            if bad:
                failures.append(
                    ("A3", "action", f"{rule}: {pod_label(pid)} got action {bad['action']}")
                )
    return groups, failures


def summary(groups, rules):
    rows = [("rule", "pod", "max_state", "actions")]
    for (rule, pid), recs in sorted(groups.items(), key=lambda kv: (kv[0][0], pod_label(kv[0][1]))):
        chain = rules.get(rule, {}).get("chain", [])
        rank = {s: i for i, s in enumerate(chain)}
        top = max((r["to"] for r in recs), key=lambda s: rank.get(s, -1))
        actions = ",".join(sorted({r["action"] for r in recs}))
        rows.append((rule, pod_label(pid), top, actions))
    widths = [max(len(row[i]) for row in rows) for i in range(4)]
    return "\n".join("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in rows)


def run(path, exp_path):
    exp = load_expectations(exp_path)
    records = load(path)
    groups, failures = check(records, exp)
    print(summary(groups, exp["rules"]))
    if failures:
        for a, _, msg in failures:
            print(f"FAIL ({a}): {msg}")
        return 1
    print("PASS: every rule's attackers followed their chain; nothing else reached a terminal state or got a non-observe action")
    return 0


def self_test(exp_path):
    exp = load_expectations(exp_path)
    failed = 0
    for name, expected in SELF_TESTS:
        _, failures = check(load(FIXTURES / name), exp)
        got = {(a, t) for a, t, _ in failures}
        ok = got == expected
        failed += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: expected {sorted(expected) or 'pass'}, got {sorted(got) or 'pass'}")
    print("self-test passed" if not failed else f"self-test failed: {failed} case(s)")
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit", nargs="?", help="JSONL audit file from statewall-agent")
    parser.add_argument("--expectations", default=str(DEFAULT_EXPECTATIONS), help="expectations JSON")
    parser.add_argument("--self-test", action="store_true", help="run against testdata/fixtures")
    args = parser.parse_args()
    if not args.self_test and not args.audit:
        parser.error("audit file or --self-test required")
    try:
        if args.self_test:
            return self_test(args.expectations)
        return run(args.audit, args.expectations)
    except (OSError, BadInput) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
