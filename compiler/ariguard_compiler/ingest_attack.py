"""Ingest MITRE ATT&CK (enterprise) and emit a Linux technique catalog.

Wave 0 of the Phase 3 rule-generation pipeline (docs/phase-3-rulegen-plan.md): the user
does not pick techniques by hand -- MITRE does. This fetches the ATT&CK knowledge base,
keeps the techniques that run on Linux/Containers, and maps each onto the 16 syscall hooks
AriGuard traces (``schema.HOOKS``) by scanning the technique's prose for signals. The result
(``compiler/techniques/attack-linux.yml``) is the *input* to the LLM co-author step, not a
rule itself.

Source: ATT&CK enterprise STIX 2.1. Prefers the ``mitreattack-python`` package when it is
installed; otherwise fetches the pinned raw JSON over HTTP. ``--stix <path>`` reads a local
vendored copy so the step can run offline and deterministically.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

import yaml

from .schema import HOOKS

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# Platforms we care about: Linux proper plus containerised workloads.
PLATFORMS = ("Linux", "Containers")

DESCRIPTION_MAX = 400
DETECTION_MAX = 400

# Keyword -> candidate hook table. Each row maps lowercase substrings found in a technique's
# name/description/detection prose to one or more of the 16 syscall hooks we trace. Add a row
# (or extend a keyword list) to teach the ingester a new signal; every hook named here must
# exist in schema.HOOKS (asserted below).
HOOK_SIGNALS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("mount",), ("mount", "fsmount", "move_mount")),
    (("ptrace", "process injection"), ("ptrace",)),
    (("kernel module", "lkm", "insmod", "modprobe"), ("init_module", "finit_module")),
    (
        ("memfd", "reflective", "fileless", "in-memory", "anonymous file"),
        ("memfd_create", "execveat"),
    ),
    (("socket", "connect", "reverse shell", "c2", "command and control"), ("connect",)),
    (("namespace", "setns", "unshare", "nsenter"), ("setns", "unshare")),
    (("/etc/shadow", "/etc/passwd", "credential"), ("openat",)),
    (("ebpf", "bpf"), ("bpf",)),
    (("cron", "crontab"), ("openat", "execve")),
    (("stdin", "stdout", "redirect", "dup"), ("dup2", "dup3")),
    (("exec", "execut", "spawn", "shell"), ("execve", "execveat")),
    (("/proc",), ("openat",)),
)

_HOOK_ORDER = {name: idx for idx, name in enumerate(HOOKS)}
assert all(hook in _HOOK_ORDER for _, hooks in HOOK_SIGNALS for hook in hooks), (
    "HOOK_SIGNALS references a hook not in schema.HOOKS"
)


def map_hooks(text: str) -> list[str]:
    """Return the candidate hooks signalled by ``text``, deduped and in ABI hook order."""
    low = text.lower()
    found: set[str] = set()
    for keywords, hooks in HOOK_SIGNALS:
        if any(k in low for k in keywords):
            found.update(hooks)
    return sorted(found, key=_HOOK_ORDER.__getitem__)


def _external_id(obj: dict) -> str | None:
    """Return the Txxxx ATT&CK id from a technique's external references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _tactics(obj: dict) -> list[str]:
    """Return the ATT&CK tactic names (kill-chain phases), sorted."""
    phases = [
        p.get("phase_name")
        for p in obj.get("kill_chain_phases", [])
        if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")
    ]
    return sorted(set(phases))


def _trim(text: str, limit: int) -> str:
    """Collapse whitespace and trim to ~``limit`` characters with an ellipsis."""
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def _attack_version(objects: list[dict]) -> str:
    """Return the ATT&CK collection version (``x_mitre_version``) for reproducibility."""
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            return str(obj.get("x_mitre_version") or obj.get("spec_version") or "unknown")
    return "unknown"


def load_stix_objects(stix_path: str | None, url: str) -> tuple[list[dict], str]:
    """Load the STIX objects and return (objects, source label).

    Order of preference: a local ``--stix`` file, then the ``mitreattack-python`` package,
    then the pinned raw JSON over HTTP.
    """
    if stix_path:
        data = json.loads(Path(stix_path).read_text(encoding="utf-8"))
        return data.get("objects", []), f"file:{stix_path}"

    try:
        from mitreattack.attackToExcel import attackToExcel
    except ImportError:
        pass
    else:
        store = attackToExcel.get_stix_data("enterprise-attack")
        return [json.loads(o.serialize()) for o in store.query([])], "mitreattack-python"

    with urllib.request.urlopen(url, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("objects", []), url


def build_catalog(objects: list[dict], source: str) -> tuple[dict, int]:
    """Build the catalog document. Returns (document, total Linux/Containers techniques)."""
    techniques = []
    linux_total = 0
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        platforms = obj.get("x_mitre_platforms") or []
        if not any(p in platforms for p in PLATFORMS):
            continue
        linux_total += 1

        tid = _external_id(obj)
        if tid is None:
            continue
        name = obj.get("name", "")
        description = obj.get("description", "") or ""
        detection = obj.get("x_mitre_detection", "") or ""
        hooks = map_hooks(f"{name}\n{description}\n{detection}")
        if not hooks:
            continue

        techniques.append(
            {
                "id": tid,
                "name": name,
                "tactics": _tactics(obj),
                "platforms": [p for p in platforms if p in PLATFORMS],
                "description": _trim(description, DESCRIPTION_MAX),
                "detection": _trim(detection, DETECTION_MAX),
                "candidate_hooks": hooks,
            }
        )

    techniques.sort(key=lambda t: t["id"])
    document = {
        "attack_version": _attack_version(objects),
        "generated": date.today().isoformat(),
        "source": source,
        "platforms": list(PLATFORMS),
        "technique_count": len(techniques),
        "techniques": techniques,
    }
    return document, linux_total


def write_catalog(document: dict, out: str | Path) -> None:
    """Write the catalog as YAML with a generated-file header comment."""
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    header = "# Generated by ariguard_compiler.ingest_attack -- do not edit by hand.\n"
    body = yaml.safe_dump(
        document, sort_keys=False, allow_unicode=True, default_flow_style=False, width=1000
    )
    path.write_text(header + body, encoding="utf-8")


def hook_histogram(techniques: list[dict]) -> dict[str, int]:
    """Count, per hook (in ABI order), how many kept techniques name it."""
    counts = {hook: 0 for hook in HOOKS}
    for t in techniques:
        for hook in t["candidate_hooks"]:
            counts[hook] += 1
    return {hook: counts[hook] for hook in HOOKS if counts[hook]}


def main(argv: list[str] | None = None) -> None:
    """Fetch ATT&CK, build the Linux technique catalog, and report the feasibility signal."""
    parser = argparse.ArgumentParser(
        prog="ingest-attack",
        description="Emit a catalog of Linux ATT&CK techniques mapped onto AriGuard's hooks.",
    )
    parser.add_argument("--out", required=True, help="path to write the technique catalog YAML")
    parser.add_argument("--stix", help="read a local vendored STIX 2.1 JSON instead of fetching")
    parser.add_argument("--url", default=ATTACK_STIX_URL, help="raw STIX JSON URL (fallback)")
    args = parser.parse_args(argv)

    try:
        objects, source = load_stix_objects(args.stix, args.url)
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"ingest-attack: could not load ATT&CK data: {exc}")

    document, linux_total = build_catalog(objects, source)
    write_catalog(document, args.out)

    kept = document["technique_count"]
    print(
        f"ATT&CK v{document['attack_version']} ({source}): "
        f"{linux_total} Linux/Containers techniques, {kept} mapped onto hooks -> {args.out}"
    )
    print("per-hook technique count:")
    for hook, count in hook_histogram(document["techniques"]).items():
        print(f"  {hook:<14} {count}")


if __name__ == "__main__":
    main()
