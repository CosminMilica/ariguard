"""Command-line entry point for the AriGuard rule compiler."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .emit import compile_sources, rule_files
from .schema import RuleError


def main() -> None:
    """Link YAML rule files into one policy bundle."""
    parser = argparse.ArgumentParser(
        prog="ariguard-compile",
        description="Link kill-chain rule files into one FSM policy bundle (v3).",
    )
    parser.add_argument("--rules-dir", help="directory of *.yml rule files")
    parser.add_argument("--input", action="append", default=[], help="rule file (repeatable)")
    parser.add_argument("--sigma", action="append", default=[], help="Sigma correlation file (repeatable)")
    parser.add_argument("--sigma-dir", help="directory of *.yml Sigma correlation files")
    parser.add_argument("--out", required=True, help="path to write the policy bundle")
    args = parser.parse_args()

    yaml_files = rule_files(args.rules_dir, args.input)
    sigma_files = rule_files(args.sigma_dir, args.sigma)
    if not yaml_files and not sigma_files:
        parser.error("no rule files: pass --rules-dir, --input, --sigma and/or --sigma-dir")
    try:
        rules, bundle = compile_sources(yaml_files, sigma_files)
    except RuleError as exc:
        sys.exit(f"ariguard-compile: {exc}")
    Path(args.out).write_bytes(bundle)
    transitions = sum(r.num_states * r.num_events for r in rules)
    bindings = sum(len(r.bindings) for r in rules)
    print(
        f"compiled {len(rules)} rules ({', '.join(r.name for r in rules)}): "
        f"{transitions} transitions, {bindings} bindings -> {args.out} ({len(bundle)} bytes)"
    )


if __name__ == "__main__":
    main()
