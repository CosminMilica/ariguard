"""Deploy bundle test: the full rule library (native rules + generated Sigma rules) that the
agent image ships must match the committed testdata/golden/policy-full.bin. This guards against
shipping a partial rule set (e.g. only the golden's native rules) in the agent image.

Regenerate the bundle with: make bundle
"""

from __future__ import annotations

from pathlib import Path

from ariguard_compiler.emit import compile_sources, rule_files

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "compiler" / "rules"
GENERATED = ROOT / "compiler" / "rules" / "sigma" / "generated"
FULL = ROOT / "testdata" / "golden" / "policy-full.bin"


def test_full_bundle_matches_committed() -> None:
    _, produced = compile_sources(rule_files(RULES), rule_files(GENERATED))
    expected = FULL.read_bytes()
    assert produced == expected, "deploy bundle drifted from the rule library; run `make bundle`"
