"""Parsing strace output into attack-labeled traces (honeypot capture, F11 discovery)."""

from __future__ import annotations

from ariguard_compiler import strace, trace

SAMPLE = """\
execve("/bin/sh", ["sh", "-c", "echo x > /etc/cron.d/evil"], 0x7ffc) = 0
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib/aarch64-linux-gnu/libc.so.6", O_RDONLY) = 3
openat(AT_FDCWD, "/etc/cron.d/evil", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3
connect(5, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("10.0.0.9")}, 16) = 0
connect(6, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
getpid()                                = 7
--- SIGCHLD {si_signo=SIGCHLD} ---
+++ exited with 0 +++
"""


def test_parse_text_extracts_hooks_paths_and_inet():
    t = strace.parse_text(SAMPLE, source="t")
    assert t.label == trace.ATTACK
    assert t.hooks == ("execve", "openat", "connect", "connect")  # getpid + signal/exit skipped
    assert t.events[0].path == "/bin/sh"
    assert t.events[1].path == "/etc/cron.d/evil"
    assert t.events[2].inet is True  # AF_INET, non-loopback
    assert t.events[3].inet is False  # loopback 127.0.0.1
    # linker/locale openat noise is dropped, leaving the attack signal
    assert all(not (e.path or "").startswith(("/lib/", "/etc/ld.so")) for e in t.events)


def test_parse_dir_one_trace_per_pid_and_dedup(tmp_path):
    (tmp_path / "st.100").write_text(SAMPLE)
    (tmp_path / "st.101").write_text('openat(AT_FDCWD, "/tmp/x", O_RDONLY) = 3\n')
    (tmp_path / "st.102").write_text("")  # empty → dropped
    traces, seen = strace.parse_dir(tmp_path)
    assert len(traces) == 2
    assert len(seen) == 3  # all files keyed, even the empty one
    # a second pass skipping what we saw yields nothing new
    again, _ = strace.parse_dir(tmp_path, skip=seen)
    assert again == []


def test_to_jsonl_roundtrips_through_the_loader():
    t = strace.parse_text(SAMPLE, source="t")
    jsonl = strace.to_jsonl([t])
    back = trace.from_records([__import__("json").loads(line) for line in jsonl.splitlines()])
    assert back[0].hooks == t.hooks
    assert back[0].events[2].inet is True


def test_cli_writes_jsonl(tmp_path):
    (tmp_path / "st.100").write_text(SAMPLE)
    out = tmp_path / "out.jsonl"
    rc = strace.main(["--dir", str(tmp_path), "--out", str(out)])
    assert rc == 0
    assert out.read_text().strip()
    # a second run posts nothing new (state file remembers it)
    rc2 = strace.main(["--dir", str(tmp_path), "--out", str(out)])
    assert rc2 == 0
