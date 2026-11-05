"""The autonomous loop (F11): build a bundle from the library + mined shadow rules, promote/retire
from measured telemetry, and talk to the console over HTTP (stub server)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from ariguard_compiler import loop
from ariguard_compiler.autogen import ENFORCE, RETIRE, SHADOW, ShadowMetrics

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "compiler" / "rules"
SIGMA_GEN = ROOT / "compiler" / "rules" / "sigma" / "generated"
FLEET = ROOT / "testdata" / "traces" / "fleet"
NS_PER_DAY = loop.NS_PER_DAY


def _has_kill(rule) -> bool:
    """A rule enforces iff one of its transitions carries the kill action (3)."""
    return any(action == 3 for _, action in rule.transitions.values())


def _auto_name(result) -> str:
    names = [n for n, m in result.decisions.items() if n.startswith("auto-")]
    assert names, f"no auto rule proposed; decisions={result.decisions}"
    return names[0]


# --- build ------------------------------------------------------------------------------------


def test_build_proposes_mined_rules_in_shadow():
    result = loop.build_bundle(rules_dir=str(RULES), corpus=str(FLEET))
    assert len(result.bundle) > 0
    # the curated library is present and enforcing
    names = {r.name for r in result.rules}
    assert {"container-escape", "fileless-exec", "reverse-shell"} <= names
    # a mined rule was proposed, and it is SHADOW -- no kill action anywhere in it
    auto = _auto_name(result)
    assert result.decisions[auto] == SHADOW
    rule = next(r for r in result.rules if r.name == auto)
    assert not _has_kill(rule), "a shadow rule must never carry a kill action"


def test_skips_a_proposal_when_the_hook_budget_is_full():
    # The full curated library (hand + generated) fills execve to the per-hook cap, so a mined
    # execve-ending rule cannot be admitted this pass — it is skipped, not a build failure.
    result = loop.build_bundle(rules_dir=str(RULES), sigma_dir=str(SIGMA_GEN), corpus=str(FLEET))
    assert len(result.bundle) > 0
    assert result.skipped_budget, "expected the mined rule to be skipped on a full binding budget"
    assert all(not r.name.startswith("auto-") for r in result.rules), (
        "no mined rule should be added"
    )


def test_promotes_on_clean_telemetry():
    base = loop.build_bundle(rules_dir=str(RULES), corpus=str(FLEET))
    auto = _auto_name(base)
    telem = {auto: ShadowMetrics(attack_hits=5, benign_fires=0, days_observed=10.0)}

    result = loop.build_bundle(rules_dir=str(RULES), corpus=str(FLEET), telemetry=telem)
    assert result.decisions[auto] == ENFORCE
    rule = next(r for r in result.rules if r.name == auto)
    assert _has_kill(rule), "a promoted rule must enforce (kill terminal)"


def test_retires_on_a_single_benign_fire():
    base = loop.build_bundle(rules_dir=str(RULES), corpus=str(FLEET))
    auto = _auto_name(base)
    telem = {auto: ShadowMetrics(attack_hits=99, benign_fires=1, days_observed=30.0)}

    result = loop.build_bundle(rules_dir=str(RULES), corpus=str(FLEET), telemetry=telem)
    assert result.decisions[auto] == RETIRE
    assert auto not in {r.name for r in result.rules}, "a retired rule must leave the bundle"


def test_held_in_shadow_when_window_too_short():
    base = loop.build_bundle(rules_dir=str(RULES), corpus=str(FLEET))
    auto = _auto_name(base)
    telem = {auto: ShadowMetrics(attack_hits=5, benign_fires=0, days_observed=1.0)}  # < min_days

    result = loop.build_bundle(rules_dir=str(RULES), corpus=str(FLEET), telemetry=telem)
    assert result.decisions[auto] == SHADOW
    rule = next(r for r in result.rules if r.name == auto)
    assert not _has_kill(rule)


# --- console I/O over HTTP --------------------------------------------------------------------


class _StubConsole(BaseHTTPRequestHandler):
    put_bodies: ClassVar[list[bytes]] = []

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path.startswith("/api/v1/audit/export"):
            body = b'{"id":1,"cgroup_id":42,"pid":7,"ts_ns":100,"hook":"execve","dst_ip":""}\n'
            self._send(200, "application/x-ndjson", body)
        elif self.path == "/api/v1/rules/telemetry":
            rows = [
                {
                    "rule": "auto-x",
                    "hits": 5,
                    "benign_fires": 0,
                    "first_seen_ns": 0,
                    "last_seen_ns": 10 * NS_PER_DAY,
                }
            ]
            self._send(200, "application/json", json.dumps(rows).encode())
        else:
            self._send(404, "text/plain", b"nope")

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        _StubConsole.put_bodies.append(self.rfile.read(n))
        self.send_response(204)
        self.send_header("X-Policy-Version", "deadbeefcafe0001")
        self.end_headers()

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def stub_console():
    _StubConsole.put_bodies = []
    srv = HTTPServer(("127.0.0.1", 0), _StubConsole)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_console_roundtrip(stub_console):
    rows = loop.pull_audit(stub_console)
    assert rows == [
        {"id": 1, "cgroup_id": 42, "pid": 7, "ts_ns": 100, "hook": "execve", "dst_ip": ""}
    ]

    telem = loop.fetch_telemetry(stub_console)
    assert telem["auto-x"].attack_hits == 5
    assert telem["auto-x"].days_observed == pytest.approx(10.0)

    version = loop.push_bundle(stub_console, b"BUNDLE-BYTES")
    assert version == "deadbeefcafe0001"
    assert _StubConsole.put_bodies == [b"BUNDLE-BYTES"]


def test_cli_dry_run_writes_a_bundle(tmp_path):
    out = tmp_path / "policy.bin"
    rc = loop.main(
        ["--rules-dir", str(RULES), "--corpus", str(FLEET), "--out", str(out), "--dry-run"]
    )
    assert rc == 0
    assert out.read_bytes()[:4]  # a non-empty bundle was written
