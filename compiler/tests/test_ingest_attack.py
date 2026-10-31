"""Unit tests for the MITRE ATT&CK ingester's pure mapping/filtering (no network)."""

from ariguard_compiler.ingest_attack import build_catalog, map_hooks


def _technique(tid, name, desc, platforms=("Linux",)):
    return {
        "type": "attack-pattern",
        "name": name,
        "description": desc,
        "x_mitre_platforms": list(platforms),
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


def test_map_hooks_detects_specific_syscalls():
    assert "ptrace" in map_hooks("Adversaries may inject code using ptrace")
    assert "mount" in map_hooks("mounts the host filesystem")
    assert set(map_hooks("loaded via insmod kernel module")) & {"init_module", "finit_module"}
    assert "bpf" in map_hooks("loads an eBPF program")
    assert map_hooks("completely unrelated prose") == []


def test_map_hooks_dedups():
    hooks = map_hooks("ptrace ptrace bpf")
    assert "ptrace" in hooks and "bpf" in hooks
    assert len(hooks) == len(set(hooks))


def test_build_catalog_filters_platform_and_unmapped():
    objects = [
        _technique("T9001", "Ptrace injection", "inject via ptrace"),
        _technique("T9002", "Windows only", "ptrace mention", platforms=("Windows",)),
        _technique("T9003", "No hooks", "benign description with no syscalls"),
    ]
    doc, linux_total = build_catalog(objects, "test")
    ids = [t["id"] for t in doc["techniques"]]
    assert "T9001" in ids  # Linux + mapped -> kept
    assert "T9002" not in ids  # Windows -> excluded
    assert "T9003" not in ids  # Linux but no hook -> excluded
    assert linux_total == 2  # T9001 + T9003 are Linux
    assert doc["technique_count"] == len(doc["techniques"])


def test_build_catalog_skips_revoked():
    obj = _technique("T9004", "Ptrace", "ptrace inject")
    obj["revoked"] = True
    doc, total = build_catalog([obj], "test")
    assert doc["techniques"] == []
    assert total == 0
