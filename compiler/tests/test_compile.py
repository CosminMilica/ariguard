"""Compile the rules in compiler/rules/ and assert the bundle matches ABI v3."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

from statewall_compiler import cli
from statewall_compiler.emit import (
    BINDING,
    HEADER,
    MAGIC,
    RULE,
    TRANSITION,
    VERSION,
    compile_files,
    emit_bundle,
    rule_files,
)
from statewall_compiler.schema import (
    ARG_ANY,
    HOOK_VALUES,
    HOOKS,
    NO_ARG,
    PATH_ANY,
    PATH_PREFIX,
    PATH_SUN_PREFIX,
    RuleError,
    load_rule,
    parse_rule,
)

RULES = Path(__file__).resolve().parents[1] / "rules"
SOCKETS = [b"/run/containerd/containerd.sock", b"/var/run/docker.sock", b"/run/docker.sock"]


def _bundle() -> bytes:
    return compile_files(rule_files(RULES))[1]


def _header(bundle: bytes) -> tuple[int, ...]:
    return HEADER.unpack_from(bundle, 0)


def _rules(bundle: bytes) -> list[tuple[int, ...]]:
    n = _header(bundle)[2]
    return [RULE.unpack_from(bundle, HEADER.size + i * RULE.size) for i in range(n)]


def _cell(bundle: bytes, rule: int, state: int, event: int) -> tuple[int, int]:
    num_states, num_events, base, *_ = _rules(bundle)[rule]
    assert state < num_states and event < num_events
    num_rules = _header(bundle)[2]
    offset = HEADER.size + num_rules * RULE.size + (base + state * num_events + event) * 8
    return TRANSITION.unpack_from(bundle, offset)


def _bindings(bundle: bytes) -> list[tuple]:
    _, _, num_rules, num_trans, num_bindings, _, _ = _header(bundle)
    start = HEADER.size + num_rules * RULE.size + num_trans * TRANSITION.size
    return [BINDING.unpack_from(bundle, start + i * BINDING.size) for i in range(num_bindings)]


def _meta(bundle: bytes) -> bytes:
    return bundle[len(bundle) - _header(bundle)[5] :]


def test_header_bytes():
    bundle = _bundle()
    assert bundle[:32] == bytes.fromhex(
        "54425453"  # magic "STBT" LE
        "03000000"  # version 3
        "03000000"  # num_rules 3
        "26000000"  # num_transitions 38
        "18000000"  # num_bindings 24
        "06020000"  # meta_len 518
        "0000000000000000"  # reserved
    )
    magic, version, num_rules, num_trans, num_bindings, meta_len, reserved = _header(bundle)
    assert (magic, version, reserved) == (MAGIC, VERSION, 0)
    assert len(bundle) == (
        HEADER.size
        + num_rules * RULE.size
        + num_trans * TRANSITION.size
        + num_bindings * BINDING.size
        + meta_len
    )


def test_rules_in_file_name_order():
    s = 1_000_000_000
    assert _rules(_bundle()) == [
        (5, 4, 0, 0, 4, 0, 30 * s),  # container-escape, cgroup
        (3, 2, 20, 1, 2, 0, 30 * s),  # fileless-exec, process
        (4, 3, 26, 1, 3, 0, 10 * s),  # reverse-shell, process
    ]


def test_cells():
    bundle = _bundle()
    # container-escape: escalating + host_mount -> breakout_imminent, deny.
    assert _cell(bundle, 0, 2, 2) == (3, 2)
    assert _cell(bundle, 0, 3, 3) == (4, 3)
    # fileless-exec: memfd_created + memfd_exec -> compromised, kill.
    assert _cell(bundle, 1, 1, 1) == (2, 3)
    # reverse-shell: connected + stdio_redirect -> stdio_redirected, observe.
    assert _cell(bundle, 2, 1, 1) == (2, 0)
    assert _cell(bundle, 2, 2, 2) == (3, 3)
    # Unspecified cells stay put and observe.
    assert _cell(bundle, 0, 4, 0) == (4, 0)
    assert _cell(bundle, 2, 0, 2) == (0, 0)


def test_binding_order_and_padding():
    b = _bindings(_bundle())
    h = HOOK_VALUES
    any_arg = (NO_ARG, ARG_ANY, 0)
    for i, prefix in enumerate(SOCKETS):
        assert b[i] == (h["openat"], 0, 0, 1, PATH_PREFIX, len(prefix), *any_arg,
                        prefix.ljust(64, b"\0"))  # fmt: skip
        assert b[3 + i] == (h["connect"], 0, 0, 1, PATH_SUN_PREFIX, len(prefix), *any_arg,
                            prefix.ljust(64, b"\0"))  # fmt: skip
    no_path = (NO_ARG, PATH_ANY, 0)
    assert b[6] == (h["setns"], 0, 1, *no_path, 1, 3, 0x30020000, b"\0" * 64)
    assert b[8] == (h["mount"], 0, 2, *no_path, 3, 4, 0x1E0000, b"\0" * 64)
    assert [x[0] for x in b[9:13]] == [h["fsmount"], h["move_mount"], h["execve"], h["execveat"]]
    # fileless-exec
    assert b[13][:3] == (h["memfd_create"], 1, 0)
    assert b[14] == (h["execveat"], 1, 1, *no_path, 4, 3, 0x1000, b"\0" * 64)
    assert b[15][:6] == (h["execve"], 1, 1, 0, PATH_PREFIX, len(b"/proc/self/fd/"))
    # reverse-shell
    assert b[17] == (h["connect"], 2, 0, *no_path, *any_arg, b"\0" * 64)
    assert b[18] == (h["dup2"], 2, 1, *no_path, 1, 2, 2, b"\0" * 64)
    assert b[19] == (h["dup3"], 2, 1, *no_path, 1, 2, 2, b"\0" * 64)
    assert [x[9].rstrip(b"\0") for x in b[20:24]] == [
        b"/bin/sh",
        b"/bin/bash",
        b"/usr/bin/sh",
        b"/usr/bin/bash",
    ]


def test_bindings_per_hook():
    counts: dict[int, int] = {}
    for b in _bindings(_bundle()):
        counts[b[0]] = counts.get(b[0], 0) + 1
    h = HOOK_VALUES
    assert counts == {
        h["openat"]: 3,
        h["setns"]: 1,
        h["unshare"]: 1,
        h["mount"]: 1,
        h["execve"]: 7,
        h["connect"]: 4,
        h["dup2"]: 1,
        h["dup3"]: 1,
        h["memfd_create"]: 1,
        h["execveat"]: 2,
        h["fsmount"]: 1,
        h["move_mount"]: 1,
    }


def test_metadata_bytes():
    meta = _meta(_bundle())
    assert meta == (
        b'{"rules":['
        b'{"events":["runtime_socket_open","namespace_manipulation","host_mount",'
        b'"critical_execve"],"name":"container-escape","scope":"cgroup","states":["normal",'
        b'"suspicious","escalating","breakout_imminent","compromised"]},'
        b'{"events":["memfd","memfd_exec"],"name":"fileless-exec","scope":"process",'
        b'"states":["normal","memfd_created","compromised"]},'
        b'{"events":["outbound_connect","stdio_redirect","shell_exec"],"name":"reverse-shell",'
        b'"scope":"process","states":["normal","connected","stdio_redirected","compromised"]}'
        b"]}"
    )
    assert json.loads(meta)["rules"][0]["name"] == "container-escape"


def test_deterministic():
    assert _bundle() == _bundle()
    files = rule_files(RULES)
    assert rule_files(None, reversed(files)) == files
    assert compile_files(rule_files(None, reversed(files)))[1] == _bundle()


def test_cli(tmp_path, monkeypatch, capsys):
    out = tmp_path / "policy.bin"
    argv = ["statewall-compile", "--input", str(RULES / "reverse-shell.yml")]
    argv += ["--input", str(RULES / "container-escape.yml"), "--out", str(out)]
    monkeypatch.setattr(sys, "argv", argv)
    cli.main()
    assert "compiled 2 rules (container-escape, reverse-shell)" in capsys.readouterr().out
    assert _header(out.read_bytes())[2:5] == (2, 32, 20)


def test_cli_reports_rule_errors(tmp_path, monkeypatch):
    bad = tmp_path / "bad.yml"
    bad.write_text("name: Bad\n")
    monkeypatch.setattr(sys, "argv", ["x", "--input", str(bad), "--out", str(tmp_path / "o")])
    with pytest.raises(SystemExit, match="bad.yml"):
        cli.main()


# Schema acceptance / rejection.

BASE = {
    "name": "r",
    "scope": "process",
    "states": ["a", "b"],
    "events": {"e": [{"hook": "execve"}]},
    "transitions": [{"from": "a", "event": "e", "to": "b", "action": "kill"}],
}


def _with(**changes) -> dict:
    rule = copy.deepcopy(BASE)
    for key, value in changes.items():
        if value is None:
            del rule[key]
        else:
            rule[key] = value
    return rule


def _ev(*bindings) -> dict:
    return {"events": {"e": list(bindings)}}


def test_accepts_minimal_rule():
    rule = parse_rule(_with())
    assert (rule.window_ns, rule.terminal_from, rule.scope) == (0, 2, "process")
    assert rule.bindings[0].path_kind == PATH_ANY
    assert (rule.bindings[0].arg_index, rule.bindings[0].arg_op) == (NO_ARG, ARG_ANY)


def test_accepts_terminal_suffix():
    assert parse_rule(_with(terminal=["b"])).terminal_from == 1
    assert parse_rule(_with(terminal=["a", "b"])).terminal_from == 0


def test_prefixes_share_the_arg_predicate():
    arg = {"index": 2, "eq": 7}
    rule = parse_rule(_with(**_ev({"hook": "openat", "path_prefix": ["/x", "/y"], "arg": arg})))
    assert [(b.pattern, b.path_arg, b.arg_index, b.arg_op, b.arg_value) for b in rule.bindings] == [
        (b"/x", 1, 2, 1, 7),
        (b"/y", 1, 2, 1, 7),
    ]


@pytest.mark.parametrize(
    "hook,arg", [("openat", 1), ("execve", 0), ("execveat", 1), ("mount", 1), ("memfd_create", 0)]
)
def test_path_argument_per_hook(hook, arg):
    rule = parse_rule(_with(**_ev({"hook": hook, "path_prefix": ["/p"]})))
    assert (rule.bindings[0].path_kind, rule.bindings[0].path_arg) == (PATH_PREFIX, arg)


def test_pattern_limits_in_bytes():
    ok = "/" + "a" * 62
    assert len(parse_rule(_with(**_ev({"hook": "openat", "path_prefix": [ok]}))).bindings) == 1
    with pytest.raises(RuleError, match="1..63 bytes"):
        parse_rule(_with(**_ev({"hook": "openat", "path_prefix": [ok + "a"]})))
    with pytest.raises(RuleError, match="1..63 bytes"):
        parse_rule(_with(**_ev({"hook": "openat", "path_prefix": ["/" + "é" * 32]})))


def test_yaml_hex_and_arg_ops(tmp_path):
    path = tmp_path / "r.yml"
    path.write_text(
        "name: r\nscope: cgroup\nwindow_seconds: 5\nstates: [a, b]\n"
        "events:\n  e:\n    - hook: mount\n      arg: {index: 3, mask_none: 0x1E0000}\n"
        "    - hook: bpf\n      arg: {index: 0, eq: 0xFFFFFFFFFFFFFFFF}\n"
        "transitions:\n  - {from: a, event: e, to: b, action: deny}\n"
    )
    rule = load_rule(path)
    assert [(b.arg_op, b.arg_value) for b in rule.bindings] == [(4, 0x1E0000), (1, 2**64 - 1)]
    assert rule.window_ns == 5_000_000_000


def test_rejects_duplicate_yaml_keys(tmp_path):
    path = tmp_path / "r.yml"
    path.write_text("name: r\nname: s\n")
    with pytest.raises(RuleError, match="duplicate key"):
        load_rule(path)


def _too_many_execve() -> dict:
    return {"events": {f"e{i}": [{"hook": "execve"}] for i in range(9)}}


@pytest.mark.parametrize(
    "rule,msg",
    [
        ([], "mapping"),
        (_with(extra=1), "unknown keys"),
        (_with(name=None), "missing keys"),
        (_with(scope=None), "missing keys"),
        (_with(states=None), "missing keys"),
        (_with(events=None), "missing keys"),
        (_with(transitions=None), "missing keys"),
        (_with(name="Rule"), "rule name"),
        (_with(name="1rule"), "rule name"),
        (_with(name="règle"), "rule name"),
        (_with(name=1), "rule name"),
        (_with(scope="pod"), "scope"),
        (_with(window_seconds=-1), "window_seconds"),
        (_with(window_seconds=1.5), "window_seconds"),
        (_with(window_seconds=True), "window_seconds"),
        (_with(states=[]), "states"),
        (_with(states=["a", "a"]), "unique"),
        (_with(states=["a", "B"]), "state"),
        (_with(terminal=["a"]), "suffix"),
        (_with(terminal=["c"]), "suffix"),
        (_with(terminal=["x", "a", "b"]), "suffix"),
        (_with(terminal=[]), "terminal"),
        (_with(events={}), "events"),
        (_with(events={"E": [{"hook": "execve"}]}), "event"),
        (_with(events={"e": []}), "non-empty list"),
        (_with(events={"e": {"hook": "execve"}}), "non-empty list"),
        (_with(**_ev("execve")), "mapping"),
        (_with(**_ev({"hook": "open"})), "unknown hook"),
        (_with(**_ev({})), "unknown hook"),
        (_with(**_ev({"hook": "execve", "match": 1})), "unknown keys"),
        (_with(**_ev({"hook": "setns", "path_prefix": ["/x"]})), "path argument"),
        (_with(**_ev({"hook": "connect", "path_prefix": ["/x"]})), "path argument"),
        (_with(**_ev({"hook": "openat", "sun_path_prefix": ["/x"]})), "only valid on connect"),
        (_with(**_ev({"hook": "openat", "path_prefix": []})), "non-empty list"),
        (_with(**_ev({"hook": "openat", "path_prefix": "/x"})), "non-empty list"),
        (_with(**_ev({"hook": "openat", "path_prefix": [""]})), "1..63 bytes"),
        (_with(**_ev({"hook": "openat", "path_prefix": [1]})), "strings"),
        (_with(**_ev({"hook": "openat", "path_prefix": ["/a\0"]})), "NUL"),
        (_with(**_ev({"hook": "dup2", "arg": 1})), "arg must be a mapping"),
        (_with(**_ev({"hook": "dup2", "arg": {"index": 6, "le": 2}})), "index"),
        (_with(**_ev({"hook": "dup2", "arg": {"index": -1, "le": 2}})), "index"),
        (_with(**_ev({"hook": "dup2", "arg": {"index": True, "le": 2}})), "index"),
        (_with(**_ev({"hook": "dup2", "arg": {"le": 2}})), "index"),
        (_with(**_ev({"hook": "dup2", "arg": {"index": 1}})), "exactly one"),
        (_with(**_ev({"hook": "dup2", "arg": {"index": 1, "le": 2, "eq": 1}})), "exactly one"),
        (_with(**_ev({"hook": "dup2", "arg": {"index": 1, "lt": 2}})), "unknown keys"),
        (_with(**_ev({"hook": "dup2", "arg": {"index": 1, "le": -1}})), r"2\^64"),
        (_with(**_ev({"hook": "dup2", "arg": {"index": 1, "le": 2**64}})), r"2\^64"),
        (_with(**_ev({"hook": "dup2", "arg": {"index": 1, "le": True}})), r"2\^64"),
        (_with(**_ev({"hook": "dup2", "arg": {"index": 1, "le": "2"}})), r"2\^64"),
        (_with(**_too_many_execve()), "max is 8"),
        (_with(**_ev({"hook": "openat", "path_prefix": [f"/{i}" for i in range(9)]})), "max is 8"),
        (_with(transitions=[]), "transitions"),
        (_with(transitions=["a"]), "mapping"),
        (_with(transitions=[{"from": "x", "event": "e", "to": "b", "action": "kill"}]), "from"),
        (_with(transitions=[{"from": "a", "event": "e", "to": "x", "action": "kill"}]), "to"),
        (_with(transitions=[{"from": "a", "event": "x", "to": "b", "action": "kill"}]), "event"),
        (_with(transitions=[{"from": "a", "event": "e", "to": "b", "action": "drop"}]), "action"),
        (_with(transitions=[{"from": "a", "event": "e", "to": "b"}]), "action"),
        (
            _with(transitions=[{"from": "a", "event": "e", "to": "b", "action": "kill", "x": 1}]),
            "unknown keys",
        ),
        (_with(transitions=[BASE["transitions"][0], BASE["transitions"][0]]), "duplicate"),
        (
            _with(
                states=[f"s{i}" for i in range(33)],
                events={f"e{i}": [{"hook": HOOKS[i % 16]}] for i in range(32)},
                transitions=[{"from": "s0", "event": "e0", "to": "s1", "action": "kill"}],
            ),
            "max is 1024",
        ),
    ],
)
def test_rejects_invalid_rules(rule, msg):
    with pytest.raises(RuleError, match=msg):
        parse_rule(rule)


def _named(name: str, **changes) -> object:
    return parse_rule(_with(name=name, **changes))


def test_link_rejects_too_many_bindings_across_rules():
    a = _named("a", **_ev(*[{"hook": "execve"}] * 5))
    b = _named("b", **_ev(*[{"hook": "execve"}] * 4))
    with pytest.raises(RuleError, match="bundle: hook 'execve' has 9 bindings"):
        emit_bundle([a, b])


def test_link_rejects_too_many_rules():
    with pytest.raises(RuleError, match="1..16"):
        emit_bundle([_named(f"r{i}", **_ev({"hook": "bpf"})) for i in range(17)])
    with pytest.raises(RuleError, match="1..16"):
        emit_bundle([])


def test_link_rejects_too_many_transitions():
    big = {
        "states": [f"s{i}" for i in range(32)],
        "events": {f"e{i}": [{"hook": HOOKS[i]}] for i in range(16)},
        "transitions": [{"from": "s0", "event": "e0", "to": "s1", "action": "kill"}],
    }
    rules = [_named(n, **big) for n in ("a", "b", "c")]  # 512 each
    emit_bundle(rules[:2])
    with pytest.raises(RuleError, match="1536 transitions, max is 1024"):
        emit_bundle(rules)


def test_link_rejects_duplicate_names():
    with pytest.raises(RuleError, match="duplicate rule names"):
        emit_bundle([_named("a"), _named("a")])
