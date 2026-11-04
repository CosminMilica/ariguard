"""Labeled syscall-hook traces: the input to data-driven rule mining (A1/A2).

A *trace* is one workload run captured as an ordered list of hook events, labeled ``attack``
or ``benign``. Traces come from a full-syscall capture during a testbed scenario (the attack
chain and its benign twin) and are committed as JSONL fixtures, so mining is offline and
deterministic -- the same philosophy as :mod:`ariguard_compiler.validate`.

Fixture format (one JSON object per line, one line = one run)::

    {"label": "attack", "source": "escape-as-root",
     "events": [{"hook": "openat", "path": "/run/containerd/containerd.sock"},
                {"hook": "setns"}, {"hook": "mount", "path": "/mnt"},
                {"hook": "execve", "path": "/mnt/payload"}]}

``hook`` is required and must name one of :data:`ariguard_compiler.schema.HOOKS`; ``path``
(the opened/exec'd path) and ``inet`` (an AF_INET non-loopback ``connect``) are optional and
feed predicate inference. A directory of traces may instead hold ``attack.jsonl`` and
``benign.jsonl`` whose lines carry only the event list (the label comes from the file name).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .schema import HOOK_VALUES

ATTACK = "attack"
BENIGN = "benign"
_LABELS = (ATTACK, BENIGN)


class TraceError(ValueError):
    """Raised when a trace file is malformed or names an unknown hook."""


@dataclass(frozen=True)
class Event:
    """One observed hook invocation in a trace."""

    hook: str
    ts_ns: int = 0
    path: str | None = None
    inet: bool = False


@dataclass(frozen=True)
class Trace:
    """One labeled workload run: an ordered sequence of hook events."""

    label: str
    events: tuple[Event, ...]
    source: str = ""

    @property
    def hooks(self) -> tuple[str, ...]:
        """The ordered hook names, the unit of sequence mining."""
        return tuple(e.hook for e in self.events)


def _event(obj: object, where: str) -> Event:
    if not isinstance(obj, dict):
        raise TraceError(f"{where}: each event must be an object")
    hook = obj.get("hook")
    if hook not in HOOK_VALUES:
        raise TraceError(f"{where}: unknown hook {hook!r}")
    ts = obj.get("ts_ns", 0)
    if not isinstance(ts, int) or isinstance(ts, bool) or ts < 0:
        raise TraceError(f"{where}: ts_ns must be a non-negative integer")
    path = obj.get("path")
    if path is not None and not isinstance(path, str):
        raise TraceError(f"{where}: path must be a string")
    inet = obj.get("inet", False)
    if not isinstance(inet, bool):
        raise TraceError(f"{where}: inet must be a boolean")
    return Event(hook=hook, ts_ns=ts, path=path, inet=inet)


def _run(obj: object, where: str, default_label: str | None) -> Trace:
    if isinstance(obj, list):  # a bare event list; the label comes from the file name
        if default_label is None:
            raise TraceError(f"{where}: a bare event list needs a label from the file name")
        events = [_event(e, where) for e in obj]
        return Trace(label=default_label, events=tuple(events), source=where)
    if not isinstance(obj, dict):
        raise TraceError(f"{where}: a run must be an object or an event list")
    label = obj.get("label", default_label)
    if label not in _LABELS:
        raise TraceError(f"{where}: label must be one of {_LABELS}, got {label!r}")
    raw = obj.get("events")
    if not isinstance(raw, list) or not raw:
        raise TraceError(f"{where}: events must be a non-empty list")
    events = [_event(e, where) for e in raw]
    source = obj.get("source") or where
    return Trace(label=label, events=tuple(events), source=str(source))


def load_jsonl(path: str | Path, default_label: str | None = None) -> list[Trace]:
    """Load one JSONL trace file; ``default_label`` labels bare event-list lines."""
    traces: list[Trace] = []
    for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        where = f"{path}:{lineno}"
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TraceError(f"{where}: invalid JSON: {exc}") from exc
        traces.append(_run(obj, where, default_label))
    return traces


def load_dir(path: str | Path) -> list[Trace]:
    """Load a scenario directory: ``attack.jsonl`` and/or ``benign.jsonl`` (label by file name),
    plus any other ``*.jsonl`` whose lines carry their own label."""
    base = Path(path)
    traces: list[Trace] = []
    for label in _LABELS:
        f = base / f"{label}.jsonl"
        if f.exists():
            traces.extend(load_jsonl(f, default_label=label))
    for f in sorted(base.glob("*.jsonl")):
        if f.stem in _LABELS:
            continue
        traces.extend(load_jsonl(f))
    if not traces:
        raise TraceError(f"{path}: no traces found")
    return traces


def load(path: str | Path) -> list[Trace]:
    """Load traces from a scenario directory or a single JSONL file."""
    p = Path(path)
    return load_dir(p) if p.is_dir() else load_jsonl(p)


def from_audit(lines: list[dict], label: str) -> list[Trace]:
    """Group agent audit-event objects into per-process traces (live capture of covered events).

    The agent's audit stream only emits events that matched a rule, so this sees what the
    current library already catches -- useful to confirm a mined rule against live data, not to
    discover new chains (that needs a full-syscall capture written to the fixture format).
    Groups by ``cgroup_id`` then ``pid``, orders by ``ts_ns``.
    """
    groups: dict[tuple, list[dict]] = {}
    for ev in lines:
        key = (ev.get("cgroup_id"), ev.get("pid"))
        groups.setdefault(key, []).append(ev)
    traces: list[Trace] = []
    for key, evs in groups.items():
        evs.sort(key=lambda e: e.get("ts_ns", 0))
        events = [
            Event(hook=e["hook"], ts_ns=e.get("ts_ns", 0), inet=bool(e.get("dst_ip")))
            for e in evs
            if e.get("hook") in HOOK_VALUES
        ]
        if events:
            traces.append(
                Trace(label=label, events=tuple(events), source=f"cgroup={key[0]} pid={key[1]}")
            )
    return traces
