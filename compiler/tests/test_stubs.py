"""Phase-3 stubs fail loudly until implemented.

CMP-3.1 (sigma.py) is implemented; see tests/test_sigma.py. mine.py (CMP-3.2) is still a
stub.
"""

import pytest

from ariguard_compiler import mine


def test_mine_not_implemented():
    with pytest.raises(NotImplementedError):
        mine.mine_sequences("traces")
