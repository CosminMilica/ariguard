"""Ingest free community detection feeds into FSM rules -- the cheap way to stay current with
the market, with no LLM.

The security community already writes and updates detections continuously (SigmaHQ, Atomic Red
Team, Falco). We don't regenerate that knowledge; we *ingest* it: point at a directory of Sigma
correlation rules (a vendored snapshot or a periodic pull), compile every one our 16 syscall hooks
can express via :func:`ariguard_compiler.sigma.compile_sigma`, and keep the rest out. Rules that
reference data sources we don't trace (Windows registry, DNS payloads, ...) simply don't compile
and are reported as skipped -- no network, no model, deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .schema import Rule, RuleError
from .sigma import compile_sigma


@dataclass
class FeedResult:
    """What an ingest produced: the rules we can enforce and why the others were skipped."""

    rules: list[Rule] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (file, reason)

    @property
    def expressible(self) -> int:
        return len(self.rules)


def ingest_dir(path: str | Path, *, pattern: str = "*.yml") -> FeedResult:
    """Compile every Sigma rule under ``path`` that our hooks can express; skip the rest.

    Deterministic and offline: it reads committed files in sorted order. A rule that references
    syscalls/data we do not trace raises ``RuleError`` in the compiler and is recorded as skipped,
    never fatal -- a feed is a stream of candidates, not a bundle that must all load.
    """
    result = FeedResult()
    for f in sorted(Path(path).rglob(pattern)):
        try:
            result.rules.append(compile_sigma(f))
        except RuleError as exc:
            result.skipped.append((str(f), str(exc).splitlines()[0]))
    return result
