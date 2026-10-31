"""Link rules into one policy bundle v3 distributed to agents.

Policy bundle format v3 (little-endian), identical to the Go pkg/fsm reader
(see docs/architecture.md, "Policy bundle format v3"):
  Header (32 B): magic, version = 3, num_rules, num_transitions, num_bindings,
                 meta_len (u32 each), reserved u64 = 0
  Rules: num_rules x 32 B; Transitions: num_transitions x 8 B, rule r owns
  [trans_base, trans_base + num_states * num_events), row-major;
  Bindings: num_bindings x 104 B; Metadata: meta_len bytes of compact sorted JSON.
Unspecified (state, event) cells default to (same state, observe).
"""

from __future__ import annotations

import json
import struct
from collections.abc import Iterable
from pathlib import Path

from .schema import (
    MAX_RULES,
    MAX_TRANSITIONS,
    PATTERN_LEN,
    SCOPE_VALUES,
    Rule,
    RuleError,
    check_bindings_per_hook,
    load_rule,
)

MAGIC = 0x53544254  # "STBT"
VERSION = 3
ACTION_OBSERVE = 0

HEADER = struct.Struct("<IIIIIIQ")
RULE = struct.Struct("<IIIIIIQ")
TRANSITION = struct.Struct("<II")
BINDING = struct.Struct(f"<IIIIIIIIQ{PATTERN_LEN}s")


def metadata(rules: list[Rule]) -> bytes:
    """Encode the names the kernel does not need, as compact sorted JSON."""
    doc = {
        "rules": [
            {"events": r.events, "name": r.name, "scope": r.scope, "states": r.states}
            for r in rules
        ]
    }
    return json.dumps(doc, separators=(",", ":"), sort_keys=True).encode("utf-8")


def emit_bundle(rules: list[Rule]) -> bytes:
    """Link ``rules`` (already in bundle order) into the on-wire policy bundle."""
    if not 1 <= len(rules) <= MAX_RULES:
        raise RuleError(f"bundle has {len(rules)} rules, expected 1..{MAX_RULES}")
    names = [r.name for r in rules]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        raise RuleError(f"duplicate rule names: {dup}")
    total = sum(r.num_states * r.num_events for r in rules)
    if total > MAX_TRANSITIONS:
        raise RuleError(f"bundle has {total} transitions, max is {MAX_TRANSITIONS}")
    check_bindings_per_hook([b for r in rules for b in r.bindings], "bundle")

    rule_bytes = bytearray()
    cells = bytearray()
    bindings = bytearray()
    num_bindings = 0
    trans_base = 0
    for idx, r in enumerate(rules):
        rule_bytes += RULE.pack(
            r.num_states,
            r.num_events,
            trans_base,
            SCOPE_VALUES[r.scope],
            r.terminal_from,
            0,
            r.window_ns,
        )
        trans_base += r.num_states * r.num_events
        for state in range(r.num_states):
            for event in range(r.num_events):
                cells += TRANSITION.pack(
                    *r.transitions.get((state, event), (state, ACTION_OBSERVE))
                )
        for b in r.bindings:
            bindings += BINDING.pack(
                b.hook,
                idx,
                b.event,
                b.path_arg,
                b.path_kind,
                len(b.pattern),
                b.arg_index,
                b.arg_op,
                b.arg_value,
                b.pattern,
            )
            num_bindings += 1

    meta = metadata(rules)
    header = HEADER.pack(MAGIC, VERSION, len(rules), trans_base, num_bindings, len(meta), 0)
    return header + bytes(rule_bytes) + bytes(cells) + bytes(bindings) + meta


def rule_files(rules_dir: str | Path | None, inputs: Iterable[str | Path] = ()) -> list[Path]:
    """Collect rule files, sorted by file name (the bundle's rule order)."""
    files = {Path(p) for p in inputs}
    if rules_dir is not None:
        d = Path(rules_dir)
        files |= set(d.glob("*.yml")) | set(d.glob("*.yaml"))
    return sorted(files, key=lambda p: (p.name, str(p)))


def compile_files(files: list[Path]) -> tuple[list[Rule], bytes]:
    """Load ``files`` in the given order and link them into a bundle."""
    rules = [load_rule(f) for f in files]
    return rules, emit_bundle(rules)
