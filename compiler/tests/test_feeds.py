"""Ingesting community detection feeds: keep the expressible rules, skip the rest, never raise."""

from __future__ import annotations

from pathlib import Path

from ariguard_compiler import feeds

ROOT = Path(__file__).resolve().parents[2]
SIGMA = ROOT / "compiler" / "rules" / "sigma"


def test_ingest_committed_sigma_rules():
    result = feeds.ingest_dir(SIGMA / "generated")
    assert result.expressible >= 1
    assert all(r.name for r in result.rules)
    # every compiled rule is usable (named, non-trivial)
    assert all(r.num_states >= 2 for r in result.rules)


def test_non_expressible_sigma_is_skipped_not_fatal(tmp_path):
    good = SIGMA / "reverse-shell.yml"
    (tmp_path / "ok.yml").write_text(good.read_text(), encoding="utf-8")
    # a rule that is not a valid Sigma correlation for our hooks: compiled away, recorded as skipped
    (tmp_path / "bad.yml").write_text(
        "title: not a correlation\nlogsource: {category: foo}\n", encoding="utf-8"
    )
    result = feeds.ingest_dir(tmp_path)
    assert result.expressible == 1
    assert len(result.skipped) == 1
    assert result.skipped[0][0].endswith("bad.yml")


def test_empty_feed_is_empty_result(tmp_path):
    result = feeds.ingest_dir(tmp_path)
    assert result.expressible == 0 and result.skipped == []
