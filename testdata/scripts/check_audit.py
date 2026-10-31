#!/usr/bin/env python3
"""Assert the Phase 1 exit criteria on a Statewall JSONL audit stream."""

import argparse
import itertools
import json
import sys
from collections import defaultdict
from pathlib import Path

STATES = ["normal", "suspicious", "escalating", "breakout_imminent", "compromised"]
RANK = {s: i for i, s in enumerate(STATES)}
CHAIN = list(itertools.pairwise(STATES))
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

SELF_TESTS = [
    ("pass.jsonl", None),
    ("fail-no-compromised.jsonl", 1),
    ("fail-two-compromised.jsonl", 1),
    ("fail-chain-order.jsonl", 2),
    ("fail-benign-escalating.jsonl", 3),
]


class CheckFailure(Exception):
    def __init__(self, assertion, reason):
        super().__init__(reason)
        self.assertion = assertion
        self.reason = reason


def load(path):
    records = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                rec["cgroup_id"], rec["ts_ns"], rec["from"], rec["to"]
            except (json.JSONDecodeError, KeyError, TypeError):
                print(f"warning: {path}:{lineno}: skipping non-audit line", file=sys.stderr)
                continue
            records.append(rec)
    return records


def by_cgroup(records):
    groups = defaultdict(list)
    for rec in records:
        groups[rec["cgroup_id"]].append(rec)
    for recs in groups.values():
        recs.sort(key=lambda r: r["ts_ns"])
    return groups


def max_state(recs):
    return max((r["to"] for r in recs), key=lambda s: RANK.get(s, -1))


def summary(groups):
    rows = [("cgroup_id", "records", "max_state", "final_state", "actions")]
    for cg, recs in sorted(groups.items(), key=lambda kv: (-RANK.get(max_state(kv[1]), -1), kv[0])):
        actions = ",".join(sorted({r.get("action", "?") for r in recs}))
        rows.append((str(cg), str(len(recs)), max_state(recs), recs[-1]["to"], actions))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in rows)


def has_chain(recs):
    step = 0
    for r in recs:
        if (r["from"], r["to"]) == CHAIN[step]:
            step += 1
            if step == len(CHAIN):
                return True
    return False


def check(records):
    groups = by_cgroup(records)
    compromised = sorted(
        cg for cg, recs in groups.items() if any(r["to"] == "compromised" for r in recs)
    )
    if len(compromised) != 1:
        raise CheckFailure(
            1,
            f"expected exactly one cgroup to reach compromised, got {len(compromised)}: {compromised}",
        )
    attack = compromised[0]
    if not has_chain(groups[attack]):
        path = " -> ".join(STATES)
        raise CheckFailure(
            2, f"cgroup {attack} reached compromised without the ordered chain {path}"
        )
    leaked = sorted(
        cg
        for cg, recs in groups.items()
        if cg != attack and RANK.get(max_state(recs), -1) >= RANK["escalating"]
    )
    if leaked:
        raise CheckFailure(3, f"non-attack cgroups went past suspicious: {leaked}")
    return groups, attack


def run(path):
    records = load(path)
    groups = by_cgroup(records)
    if groups:
        print(summary(groups))
    else:
        print("no audit records")
    try:
        _, attack = check(records)
    except CheckFailure as e:
        print(f"FAIL (assertion {e.assertion}): {e.reason}")
        return 1
    print(f"PASS: cgroup {attack} followed the full chain; no other cgroup went past suspicious")
    return 0


def self_test():
    failed = 0
    for name, expected in SELF_TESTS:
        try:
            check(load(FIXTURES / name))
            got = None
        except CheckFailure as e:
            got = e.assertion
        ok = got == expected
        failed += not ok
        want = "pass" if expected is None else f"fail assertion {expected}"
        have = "pass" if got is None else f"fail assertion {got}"
        print(f"{'ok  ' if ok else 'FAIL'} {name}: expected {want}, got {have}")
    print("self-test passed" if not failed else f"self-test failed: {failed} case(s)")
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("audit", nargs="?", help="JSONL audit file from statewall-agent")
    group.add_argument("--self-test", action="store_true", help="run against testdata/fixtures")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        return run(args.audit)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
