import re

ID_RE = re.compile(r"\b(AGT|BPF|CMP|CP|DEP|DOC|EVAL|PKG|PROTO)-(\d+(?:\.\d+)*)(\.\*)?")
ROW_RE = re.compile(r"^\|\s*`\[(.)\]`\s+([A-Z]+-\d+(?:\.\d+)*)\s*\|", re.M)
LEGEND_RE = re.compile(r"^Legend:(.*)$", re.M)

PREFIX_DIR = {
    "AGT": "agent", "BPF": "bpf", "CMP": "compiler", "CP": "control-plane", "DEP": "deploy",
    "DOC": "docs", "EVAL": "testdata", "PKG": "pkg", "PROTO": "proto",
}
LEGEND_SYMBOLS = {" ", "~", "x", "!"}

# ROADMAP reference -> reason it may not resolve.
# TODO: add the row to bpf/TASKS.md or fix the ROADMAP range.
UNRESOLVED_ALLOWLIST = {}


def task_rows(root):
    rows = {}
    for d in set(PREFIX_DIR.values()):
        path = root / d / "TASKS.md"
        if path.exists():
            rows[d] = ROW_RE.findall(path.read_text())
    return rows


def test_every_component_has_tasks_md(repo_root):
    missing = [d for d in sorted(set(PREFIX_DIR.values())) if not (repo_root / d / "TASKS.md").exists()]
    assert not missing, "missing TASKS.md in: " + ", ".join(missing)


def test_roadmap_task_ids_resolve(repo_root):
    rows = task_rows(repo_root)
    defined = {d: {tid for _, tid in r} for d, r in rows.items()}
    text = (repo_root / "ROADMAP.md").read_text()
    problems = []
    for m in ID_RE.finditer(text):
        prefix, num, wild = m.group(1), m.group(2), m.group(3)
        ids = defined.get(PREFIX_DIR[prefix], set())
        ref = f"{prefix}-{num}"
        if wild:
            ok = any(i.startswith(ref + ".") for i in ids)
            ref += ".*"
        else:
            ok = ref in ids
        if not ok and ref not in UNRESOLVED_ALLOWLIST:
            line = text.count("\n", 0, m.start()) + 1
            problems.append(f"ROADMAP.md:{line}: {ref} not found in {PREFIX_DIR[prefix]}/TASKS.md")
    assert not problems, "ROADMAP task references without a TASKS.md row:\n" + "\n".join(problems)


def test_tasks_legend_and_status_symbols(repo_root):
    problems = []
    for d in sorted(set(PREFIX_DIR.values())):
        path = repo_root / d / "TASKS.md"
        if not path.exists():
            continue
        text = path.read_text()
        m = LEGEND_RE.search(text)
        if not m:
            problems.append(f"{d}/TASKS.md: no Legend line")
            continue
        symbols = set(re.findall(r"`\[(.)\]`", m.group(1)))
        if symbols != LEGEND_SYMBOLS:
            problems.append(f"{d}/TASKS.md: legend symbols {sorted(symbols)} != {sorted(LEGEND_SYMBOLS)}")
        for status, tid in ROW_RE.findall(text):
            if status not in LEGEND_SYMBOLS:
                problems.append(f"{d}/TASKS.md: {tid} uses undocumented status [{status}]")
    assert not problems, "\n".join(problems)


def test_task_ids_are_unique_and_in_right_component(repo_root):
    problems = []
    seen = {}
    for d, rows in task_rows(repo_root).items():
        for _, tid in rows:
            prefix = tid.split("-")[0]
            if PREFIX_DIR.get(prefix) != d:
                problems.append(f"{d}/TASKS.md: {tid} has a prefix belonging to another component")
            if tid in seen:
                problems.append(f"{tid} defined in both {seen[tid]} and {d}")
            seen[tid] = d
    assert not problems, "\n".join(problems)
