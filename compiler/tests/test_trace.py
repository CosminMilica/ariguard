"""Loading labeled syscall-hook traces."""

from __future__ import annotations

import pytest

from ariguard_compiler import trace


def test_load_jsonl_object_lines(tmp_path):
    f = tmp_path / "t.jsonl"
    f.write_text(
        '{"label": "attack", "source": "a", "events": [{"hook": "setns"}, {"hook": "execve", "path": "/bin/sh"}]}\n'
        "# a comment line is ignored\n"
        '{"label": "benign", "events": [{"hook": "openat", "path": "/etc/x"}]}\n',
        encoding="utf-8",
    )
    traces = trace.load_jsonl(f)
    assert [t.label for t in traces] == ["attack", "benign"]
    assert traces[0].hooks == ("setns", "execve")
    assert traces[0].events[1].path == "/bin/sh"
    assert traces[0].source == "a"


def test_bare_event_list_takes_label_from_the_file(tmp_path):
    f = tmp_path / "attack.jsonl"
    f.write_text('[{"hook": "connect", "inet": true}, {"hook": "dup2"}]\n', encoding="utf-8")
    traces = trace.load_jsonl(f, default_label="attack")
    assert traces[0].label == "attack"
    assert traces[0].events[0].inet is True


def test_unknown_hook_is_rejected(tmp_path):
    f = tmp_path / "t.jsonl"
    f.write_text('{"label": "attack", "events": [{"hook": "nope"}]}\n', encoding="utf-8")
    with pytest.raises(trace.TraceError):
        trace.load_jsonl(f)


def test_bad_label_is_rejected(tmp_path):
    f = tmp_path / "t.jsonl"
    f.write_text('{"label": "weird", "events": [{"hook": "setns"}]}\n', encoding="utf-8")
    with pytest.raises(trace.TraceError):
        trace.load_jsonl(f)


def test_load_dir_merges_attack_and_benign(tmp_path):
    (tmp_path / "attack.jsonl").write_text('[{"hook": "setns"}]\n', encoding="utf-8")
    (tmp_path / "benign.jsonl").write_text('[{"hook": "openat"}]\n', encoding="utf-8")
    traces = trace.load(tmp_path)
    labels = sorted(t.label for t in traces)
    assert labels == ["attack", "benign"]


def test_from_audit_groups_by_process_in_time_order():
    lines = [
        {"cgroup_id": 1, "pid": 10, "ts_ns": 2, "hook": "execve"},
        {"cgroup_id": 1, "pid": 10, "ts_ns": 1, "hook": "setns"},
        {"cgroup_id": 2, "pid": 20, "ts_ns": 1, "hook": "connect", "dst_ip": "10.0.0.1"},
    ]
    traces = trace.from_audit(lines, label="attack")
    by_pid = {t.source: t for t in traces}
    p10 = next(t for t in traces if "pid=10" in t.source)
    assert p10.hooks == ("setns", "execve")  # reordered by ts_ns
    p20 = next(t for t in traces if "pid=20" in t.source)
    assert p20.events[0].inet is True  # dst_ip -> inet
    assert len(by_pid) == 2
