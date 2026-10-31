"""Command-line entry point for the Statewall rule compiler."""

from __future__ import annotations

import argparse
from pathlib import Path

from .emit import DEFAULT_MAX_ENTRIES, emit_table
from .schema import load_rule


def main() -> None:
    """Compile a YAML rule file into a transition-table binary."""
    parser = argparse.ArgumentParser(
        prog="statewall-compile",
        description="Compile a kill-chain rule file into an FSM transition table.",
    )
    parser.add_argument("--input", required=True, help="path to the YAML rule file")
    parser.add_argument("--out", required=True, help="path to write the table binary")
    parser.add_argument(
        "--max-entries",
        type=int,
        default=DEFAULT_MAX_ENTRIES,
        help=f"reject tables larger than this many entries (default {DEFAULT_MAX_ENTRIES})",
    )
    args = parser.parse_args()

    fsm = load_rule(args.input)
    table = emit_table(fsm, max_entries=args.max_entries)
    Path(args.out).write_bytes(table)
    print(
        f"compiled {fsm.name}: {fsm.num_states} states x {fsm.num_events} events "
        f"-> {args.out} ({len(table)} bytes)"
    )


if __name__ == "__main__":
    main()
