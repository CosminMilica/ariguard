"""Parse ``strace`` output into labeled traces for the miner.

A honeypot runs its workload under ``strace -f -ff -qq -e trace=<hooks> -o <prefix>``, which writes
one file per process (``<prefix>.<pid>``), each a time-ordered list of the syscalls we hook. Every
process on a honeypot is attack behavior by definition, so each file becomes one ``attack`` trace.
This is the cheap, no-kernel-change way to get *full* syscall sequences (unlike the agent's audit
stream, which carries only rule-matched events) — the raw material the miner needs to discover
*new* chains.

Deliberately lenient: unparseable or non-hook lines are skipped, never fatal.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import trace
from .schema import HOOK_VALUES

# strace prints each syscall by its name; our hook names are the syscall names, so the map is
# identity for the 16 we trace. Keep it explicit so an unexpected syscall is ignored, not mapped.
_HOOK_SYSCALLS = set(HOOK_VALUES)

# syscalls whose first quoted string argument is the path/name we match on.
_PATH_SYSCALLS = {"openat", "execve", "execveat", "mount", "memfd_create"}

# openat of the dynamic linker / locale / shared libraries is startup noise every process makes; it
# drowns the attack signal, so drop it. Attack-relevant opens (/etc/shadow, /etc/cron*, sockets,
# /proc/self/uid_map, ...) are kept. Only applied to openat; other hooks are rare and all kept.
_NOISE_OPENAT = (
    "/lib/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/share/locale",
    "/etc/ld.so.cache",
)

# strace prefixes a syscall line with the pid under -f ("1234  execve(...") or -ff with a header
# ("[pid 1234] execve(...") — strip either, bare or empty, before the syscall name.
_CALL = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?(\w+)\(")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_LOOPBACK = re.compile(r'inet_addr\("127\.')


def _event(line: str) -> trace.Event | None:
    """Parse one strace line into an Event, or None if it is not a hooked syscall."""
    m = _CALL.match(line)
    if not m:
        return None
    hook = m.group(1)
    if hook not in _HOOK_SYSCALLS:
        return None
    path = None
    if hook in _PATH_SYSCALLS:
        q = _QUOTED.search(line)
        if q:
            path = q.group(1)
    if hook == "openat" and path and path.startswith(_NOISE_OPENAT):
        return None  # linker/locale startup noise, not attack signal
    inet = hook == "connect" and "AF_INET" in line and not _LOOPBACK.search(line)
    return trace.Event(hook=hook, path=path, inet=inet)


def parse_text(text: str, *, label: str = trace.ATTACK, source: str = "honeypot") -> trace.Trace:
    """Parse one process's strace output (a ``<prefix>.<pid>`` file) into a labeled trace."""
    events = [e for line in text.splitlines() if (e := _event(line))]
    return trace.Trace(label=label, events=tuple(events), source=source)


def parse_dir(
    path: str | Path,
    *,
    prefix: str = "sess",
    label: str = trace.ATTACK,
    skip: set[str] = frozenset(),
) -> tuple[list[trace.Trace], set[str]]:
    """Parse each ``<prefix>*`` strace file under ``path`` not already in ``skip`` into one trace.

    With ``strace -f`` (follow, single file per session), each file holds one whole attack session
    time-ordered across its processes — so a cross-process chain (e.g. unshare then mount in two
    children) is captured as one trace. Files are keyed by ``name:size`` so a still-growing session
    is re-read when it next grows.
    """
    out: list[trace.Trace] = []
    seen: set[str] = set()
    for f in sorted(Path(path).glob(f"{prefix}*")):
        if not f.is_file():
            continue
        key = f"{f.name}:{f.stat().st_size}"
        seen.add(key)
        if key in skip:
            continue
        t = parse_text(f.read_text(errors="replace"), label=label, source=f.name)
        if t.events:
            out.append(t)
    return out, seen


def to_jsonl(traces: list[trace.Trace]) -> str:
    """Serialize traces to the miner's JSONL form (one object per line)."""
    lines = []
    for t in traces:
        events = [
            {
                "hook": e.hook,
                **({"path": e.path} if e.path else {}),
                **({"inet": True} if e.inet else {}),
            }
            for e in t.events
        ]
        lines.append(json.dumps({"label": t.label, "source": t.source, "events": events}))
    return "\n".join(lines)


# --- capture CLI (honeypot sidecar) -----------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ariguard-trace-capture",
        description="Parse a honeypot's strace output into attack-labeled traces and POST them to "
        "the console for the rule-generation loop to mine.",
    )
    parser.add_argument("--dir", required=True, help="directory of strace -ff files")
    parser.add_argument("--prefix", default="sess", help="strace -o file prefix (default: sess)")
    parser.add_argument("--label", default=trace.ATTACK, choices=[trace.ATTACK, trace.BENIGN])
    parser.add_argument("--console", help="console base URL; POST traces to /api/v1/traces")
    parser.add_argument(
        "--token", default=os.environ.get("ARIGUARD_TOKEN", ""), help="control-plane bearer token"
    )
    parser.add_argument("--state", help="file remembering posted traces (default: <dir>/.posted)")
    parser.add_argument("--out", help="also append the JSONL here")
    args = parser.parse_args(argv)

    state = Path(args.state) if args.state else Path(args.dir) / ".posted"
    posted: set[str] = set()
    if state.exists():
        posted = set(state.read_text().split())

    traces, seen = parse_dir(args.dir, prefix=args.prefix, label=args.label, skip=posted)
    if not traces:
        print("no new traces", file=sys.stderr)
        return 0
    body = to_jsonl(traces)

    if args.out:
        with open(args.out, "a", encoding="utf-8") as fh:
            fh.write(body + "\n")
    if args.console:
        url = f"{args.console.rstrip('/')}/api/v1/traces"
        req = urllib.request.Request(url, data=body.encode(), method="POST")
        req.add_header("Content-Type", "application/x-ndjson")
        if args.token:
            req.add_header("Authorization", "Bearer " + args.token)
        try:
            with urllib.request.urlopen(req, timeout=30):
                pass
        except (urllib.error.URLError, OSError) as exc:
            print(f"ariguard-trace-capture: post failed: {exc}", file=sys.stderr)
            return 1

    state.write_text("\n".join(sorted(posted | seen)))
    print(f"captured {len(traces)} trace(s) ({len(body)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
