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


def test_admits_mined_rule_into_the_full_library():
    # The full curated library (hand + generated) has one free execve slot, so the fleet-mined
    # rule is admitted as a shadow proposal — 12 rules, nothing skipped.
    result = loop.build_bundle(rules_dir=str(RULES), sigma_dir=str(SIGMA_GEN), corpus=str(FLEET))
    autos = [r.name for r in result.rules if r.name.startswith("auto-")]
    assert autos, "expected the mined rule to be admitted"
    assert result.decisions[autos[0]] == SHADOW
    assert not result.skipped_budget


def _fill_execve_rule(path):
    """A hand rule whose chain is MAX_BINDINGS_PER_HOOK execve steps — it alone fills the hook."""
    import yaml

    from ariguard_compiler.schema import MAX_BINDINGS_PER_HOOK

    n = MAX_BINDINGS_PER_HOOK
    states = [f"s{i}" for i in range(n + 1)]
    rule = {
        "name": "fill-execve",
        "scope": "process",
        "window_seconds": 10,
        "states": states,
        "terminal": [states[-1]],
        "events": {f"e{i}": [{"hook": "execve"}] for i in range(n)},
        "transitions": [
            {
                "from": states[i],
                "event": f"e{i}",
                "to": states[i + 1],
                "action": "kill" if i == n - 1 else "observe",
            }
            for i in range(n)
        ],
    }
    path.write_text(yaml.safe_dump(rule))


def test_skips_a_proposal_when_a_hook_is_full(tmp_path):
    # A base library that already fills execve leaves no room; the mined execve-ending rule is
    # skipped this pass (recorded in skipped_budget), not a build failure.
    _fill_execve_rule(tmp_path / "fill.yml")
    result = loop.build_bundle(rules_dir=str(tmp_path), corpus=str(FLEET))
    assert len(result.bundle) > 0
    assert result.skipped_budget, "expected the mined execve rule to be skipped on a full budget"
    assert all(not r.name.startswith("auto-") for r in result.rules)


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
        elif self.path.startswith("/api/v1/traces/export"):
            body = (
                b'{"label":"attack","source":"honeypot","events":'
                b'[{"hook":"ptrace"},{"hook":"ptrace"},{"hook":"bpf"}]}\n'
            )
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


def test_pull_traces(stub_console):
    traces = loop.pull_traces(stub_console)
    assert len(traces) == 1
    assert traces[0].label == "attack"
    assert traces[0].hooks == ("ptrace", "ptrace", "bpf")


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


def test_build_mines_a_backbone_rule_from_honeypot_traces():
    # a honeypot attack (rare-hook backbone) passed as extra_traces becomes a shadow rule, even
    # though contrast mining alone would not (a single sparse trace has no frequency support).
    import ariguard_compiler.trace as T

    hp = T.Trace(
        label="attack",
        source="hp",
        events=(
            T.Event("execve", path="/usr/bin/unshare"),
            T.Event("unshare"),
            T.Event("execve", path="/usr/bin/setns"),
            T.Event("setns"),
        ),
    )
    result = loop.build_bundle(rules_dir=str(RULES), corpus=str(FLEET), extra_traces=[hp])
    autos = [r.name for r in result.rules if r.name.startswith("auto-")]
    assert any("unshare" in n and "setns" in n for n in autos), f"backbone rule missing: {autos}"


def _unshare_setns(label):
    import ariguard_compiler.trace as T

    return T.Trace(
        label=label,
        source="hp",
        events=(
            T.Event("execve", path="/usr/bin/unshare"),
            T.Event("unshare"),
            T.Event("execve", path="/usr/bin/setns"),
            T.Event("setns"),
        ),
    )


def test_benign_honeypot_baseline_suppresses_a_backbone():
    # the same unshare+setns backbone, but now a benign honeypot trace exhibits it too. It must flow
    # into the baseline (not be mined as an attack), so the backbone fires on benign and is gated out.
    attack = _unshare_setns("attack")
    benign = _unshare_setns("benign")
    result = loop.build_bundle(
        rules_dir=str(RULES), corpus=str(FLEET), extra_traces=[attack, benign]
    )
    autos = [r.name for r in result.rules if r.name.startswith("auto-")]
    assert not any("unshare" in n and "setns" in n for n in autos), (
        f"backbone should be suppressed by the benign baseline: {autos}"
    )


def test_thresholds_propagate_to_promotion():
    # a window too short for the default (7d/1hit) still promotes once --min-days/--min-hits relax it.
    base = loop.build_bundle(rules_dir=str(RULES), corpus=str(FLEET))
    auto = _auto_name(base)
    telem = {auto: ShadowMetrics(attack_hits=1, benign_fires=0, days_observed=1.0)}

    held = loop.build_bundle(rules_dir=str(RULES), corpus=str(FLEET), telemetry=telem)
    assert held.decisions[auto] == SHADOW

    promoted = loop.build_bundle(
        rules_dir=str(RULES), corpus=str(FLEET), telemetry=telem, min_days=1.0, min_hits=1
    )
    assert promoted.decisions[auto] == ENFORCE
