"""Golden test: the linked policy from compiler/rules/ must match the committed golden
bytes that the Go reader also validates (cross-language ABI check).

Regenerate the golden with: make golden
"""

from __future__ import annotations

from pathlib import Path

from statewall_compiler.emit import compile_files, rule_files

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "compiler" / "rules"
GOLDEN = ROOT / "testdata" / "golden" / "policy.bin"


def test_emit_matches_golden() -> None:
    _, produced = compile_files(rule_files(RULES))
    expected = GOLDEN.read_bytes()
    assert produced == expected, "compiled bundle drifted from the golden; run `make golden`"
