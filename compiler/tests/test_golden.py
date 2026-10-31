"""Golden test: the compiled container-escape bundle must match the committed
golden bytes that the Go reader also validates (cross-language ABI check).

Regenerate the golden with: make golden
"""

from __future__ import annotations

from pathlib import Path

from statewall_compiler.emit import emit_bundle
from statewall_compiler.schema import load_rule

ROOT = Path(__file__).resolve().parents[2]
RULE = ROOT / "compiler" / "rules" / "container-escape.yml"
GOLDEN = ROOT / "testdata" / "golden" / "container-escape.bin"


def test_emit_matches_golden() -> None:
    produced = emit_bundle(load_rule(RULE))
    expected = GOLDEN.read_bytes()
    assert produced == expected, "compiled bundle drifted from the golden; run `make golden`"
