"""Compile Sigma rules into AriGuard FSM rules (CMP-3.1, the AI bridge).

A kill chain is expressed as a Sigma ``temporal_ordered`` correlation over an ordered
list of syscall detection sub-rules. Each sub-rule selects one syscall (+ optional
predicates); the correlation lists them in order = the FSM. We translate that into the
same v3 rule mapping a hand-written ``rules/*.yml`` uses and hand it to
:func:`schema.parse_rule`, so all validation, limits and the emit path are reused and the
result is structurally identical to a hand-written rule.

Supported Sigma subset (A1):
  sub-rule: name, logsource.category: syscall, a single ``detection`` selection whose
    ``condition`` names it, with fields:
      syscall: <hook>                      (required)
      path|startswith: [..]                -> path_prefix
      sun_path|startswith: [..]            -> sun_path_prefix (connect)
      arg<N>|mask_any|mask_none|lte|eq: v  -> arg predicate on index N
  correlation: type: temporal_ordered, rules: [ordered sub-rule names], timespan,
    and AriGuard extensions: scope (cgroup|process, default cgroup), terminal_action
    (default kill), optional actions {rule_name: action} per step, optional states
    (explicit N+1 names, last is terminal).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .schema import RuleError, Rule, parse_rule

# Sigma field modifier -> v3 arg op key.
_ARG_OPS = {"mask_any": "mask_any", "mask_none": "mask_none", "lte": "le", "eq": "eq"}
_ARG_FIELD = re.compile(r"^arg(\d+)(?:\|(\w+))?$")
_TIMESPAN = re.compile(r"^(\d+)([smhd])$")
_TIMESPAN_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise RuleError(msg)


def _timespan_seconds(value: object) -> int:
    _require(isinstance(value, str), "correlation timespan must be a string like '30s'")
    m = _TIMESPAN.match(value)
    _require(m is not None, f"correlation timespan {value!r} must be <int><s|m|h|d>")
    return int(m.group(1)) * _TIMESPAN_UNIT[m.group(2)]


def _selections(sub: dict, name: str) -> list[dict]:
    """Return the detection selections referenced by ``condition``.

    ``condition`` is a single selection name or an OR of names (``sel1 or sel2``). Each
    selection is an independent alternative with its own predicate shape, so an event can
    match, e.g., openat-by-path OR connect-by-sun_path. Only the ``or`` operator is
    supported (no and/not/parentheses) in this subset.
    """
    detection = sub.get("detection")
    _require(isinstance(detection, dict), f"sub-rule {name!r}: detection must be a mapping")
    condition = detection.get("condition")
    _require(isinstance(condition, str) and condition, f"sub-rule {name!r}: detection needs a condition")
    tokens = condition.split()
    names = [t for t in tokens[::2]]
    joiners = [t for t in tokens[1::2]]
    _require(
        all(j.lower() == "or" for j in joiners) and all(n in detection for n in names),
        f"sub-rule {name!r}: condition must be selection names joined by 'or' (got {condition!r})",
    )
    sels = []
    for n in names:
        sel = detection[n]
        _require(isinstance(sel, dict), f"sub-rule {name!r}: selection {n!r} must be a mapping")
        sels.append(sel)
    return sels


def _bindings(sel: dict, name: str) -> list[dict]:
    """Translate one Sigma selection into v3 event binding mappings (one per syscall).

    ``syscall`` may be a single hook or a list of alternatives (e.g. [dup2, dup3]); each
    alternative becomes its own binding carrying the same predicates.
    """
    hooks = sel.get("syscall")
    hooks = hooks if isinstance(hooks, list) else [hooks]
    _require(
        bool(hooks) and all(isinstance(h, str) and h for h in hooks),
        f"sub-rule {name!r}: selection needs a 'syscall' (hook name or list of hook names)",
    )
    shared: dict = {}
    for field, value in sel.items():
        if field == "syscall":
            continue
        if field == "path|startswith":
            shared["path_prefix"] = value if isinstance(value, list) else [value]
            continue
        if field == "sun_path|startswith":
            shared["sun_path_prefix"] = value if isinstance(value, list) else [value]
            continue
        m = _ARG_FIELD.match(field)
        _require(
            m is not None and m.group(2) in _ARG_OPS,
            f"sub-rule {name!r}: unsupported selection field {field!r}",
        )
        _require("arg" not in shared, f"sub-rule {name!r}: at most one arg predicate per selection")
        shared["arg"] = {"index": int(m.group(1)), _ARG_OPS[m.group(2)]: value}
    return [{"hook": h, **shared} for h in hooks]


def _to_rule_dict(subrules: dict[str, dict], corr: dict) -> dict:
    """Build the v3 rule mapping from the sub-rules and the correlation."""
    _require(corr.get("type") == "temporal_ordered", "correlation type must be temporal_ordered")
    name = corr.get("name") or corr.get("title")
    _require(isinstance(name, str) and name, "correlation needs a name")
    order = corr.get("rules")
    _require(isinstance(order, list) and order, "correlation 'rules' must be a non-empty list")
    for r in order:
        _require(r in subrules, f"correlation references unknown sub-rule {r!r}")

    n = len(order)
    if "states" in corr:
        states = corr["states"]
        _require(
            isinstance(states, list) and len(states) == n + 1,
            f"correlation 'states' must list {n + 1} names (one per step plus 'normal')",
        )
    else:
        states = ["normal", *(f"stage_{i}" for i in range(1, n)), "compromised"]

    scope = corr.get("scope", "cgroup")
    terminal_action = corr.get("terminal_action", "kill")
    step_actions = corr.get("actions", {}) or {}
    _require(isinstance(step_actions, dict), "correlation 'actions' must be a mapping")

    events = {
        r: [b for sel in _selections(subrules[r], r) for b in _bindings(sel, r)] for r in order
    }
    transitions = []
    for i, r in enumerate(order):
        action = step_actions.get(r, terminal_action if i == n - 1 else "observe")
        transitions.append({"from": states[i], "event": r, "to": states[i + 1], "action": action})

    return {
        "name": name,
        "scope": scope,
        "states": states,
        "terminal": [states[-1]],
        "window_seconds": _timespan_seconds(corr["timespan"]) if "timespan" in corr else 0,
        "events": events,
        "transitions": transitions,
    }


def compile_sigma(path: str | Path) -> Rule:
    """Compile a Sigma correlation file (sub-rules + one correlation) into a Rule."""
    try:
        docs = [d for d in yaml.safe_load_all(Path(path).read_text(encoding="utf-8")) if d]
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from exc
    subrules: dict[str, dict] = {}
    correlation: dict | None = None
    for doc in docs:
        _require(isinstance(doc, dict), f"{path}: each document must be a mapping")
        if "correlation" in doc:
            _require(correlation is None, f"{path}: more than one correlation in file")
            corr = dict(doc["correlation"])
            corr.setdefault("name", doc.get("name") or doc.get("title"))
            correlation = corr
        else:
            sub_name = doc.get("name") or doc.get("title")
            _require(isinstance(sub_name, str) and sub_name, f"{path}: sub-rule needs a name")
            subrules[sub_name] = doc
    _require(correlation is not None, f"{path}: no temporal_ordered correlation found")
    return parse_rule(_to_rule_dict(subrules, correlation))


def load_sigma_rules(paths) -> list[Rule]:
    """Compile several Sigma files into Rules, in the given order."""
    return [compile_sigma(p) for p in paths]
