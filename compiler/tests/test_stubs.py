"""Phase-3 stubs fail loudly until implemented."""

import pytest

from ariguard_compiler import mine, sigma


def test_sigma_not_implemented():
    with pytest.raises(NotImplementedError):
        sigma.compile_rules("rule.yml")


def test_mine_not_implemented():
    with pytest.raises(NotImplementedError):
        mine.mine_sequences("traces")
