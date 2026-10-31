import re

TYPE_RE = re.compile(r"^type\s+([A-Z]\w*)\s+struct", re.M)
HEADING_RE = re.compile(r"^###\s+Kernel object contract", re.M)
NAME_RE = re.compile(r"`([A-Z][a-z]+(?:[A-Z][a-z]+)*)`")


def latest_contract_table(text):
    starts = [m.start() for m in HEADING_RE.finditer(text)]
    assert starts, "docs/architecture.md has no '### Kernel object contract' section"
    section = text[starts[-1]:]
    nxt = re.search(r"^#{1,3}\s", section[3:], re.M)
    return section[: nxt.start() + 3] if nxt else section


def test_contract_struct_names_exist_in_go_abi(repo_root):
    doc = (repo_root / "docs" / "architecture.md").read_text()
    go = (repo_root / "pkg" / "fsm" / "abi.go").read_text()
    go_types = set(TYPE_RE.findall(go))
    assert go_types, "no exported struct types found in pkg/fsm/abi.go"
    table_rows = [ln for ln in latest_contract_table(doc).splitlines() if ln.startswith("| map")]
    doc_names = set()
    for row in table_rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        doc_names.update(NAME_RE.findall(cells[-1]))
    assert doc_names, "no ABI struct names parsed from the kernel object contract table"
    missing = sorted(doc_names - go_types)
    assert not missing, (
        "ABI types in docs/architecture.md (latest 'Kernel object contract') missing from "
        f"pkg/fsm/abi.go: {missing}; Go has: {sorted(go_types)}"
    )
