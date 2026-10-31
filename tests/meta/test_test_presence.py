from pathlib import Path

GO_ROOTS = ["agent", "pkg"]

# Package dir (repo-relative) -> reason it may have no _test.go.
GO_NO_TEST_ALLOWLIST = {
    "agent/cmd/ariguard-agent": "main package: flag parsing and wiring only, logic lives in internal/*",
    # TODO: add unit tests for the mitigator decision logic.
    "agent/internal/mitigator": "no tests yet; behaviour covered only by kind e2e (testdata)",
    "agent/internal/audit/ringbuf": "linux-only eBPF ring buffer glue; exercised by ci-kernel/ci-e2e",
    "agent/internal/policy/kmap": "linux-only eBPF map glue; exercised by ci-kernel/ci-e2e",
    "agent/internal/metrics/metricmap": "linux-only eBPF map glue; exercised by ci-kernel/ci-e2e",
    "agent/internal/podsync/podmap": "linux-only eBPF map glue; exercised by ci-kernel/ci-e2e",
}

# Module stem under compiler/ariguard_compiler/ -> reason it may have no test.
PY_STUB_ALLOWLIST = {
    "__init__": "package marker",
    "sigma": "Phase-3 stub, covered by compiler/tests/test_stubs.py (NotImplementedError)",
    "mine": "Phase-3 stub, covered by compiler/tests/test_stubs.py (NotImplementedError)",
}


def go_packages(root: Path):
    for top in GO_ROOTS:
        dirs = {p.parent for p in (root / top).rglob("*.go")}
        for d in sorted(dirs):
            files = list(d.glob("*.go"))
            if any(not f.name.endswith("_test.go") for f in files):
                yield d, files


def test_go_packages_have_tests(repo_root):
    missing = []
    for d, files in go_packages(repo_root):
        rel = d.relative_to(repo_root).as_posix()
        if any(f.name.endswith("_test.go") for f in files):
            continue
        if rel in GO_NO_TEST_ALLOWLIST:
            continue
        missing.append(rel)
    assert not missing, (
        "Go packages with source but no _test.go; add a test or an allowlisted reason in "
        "GO_NO_TEST_ALLOWLIST:\n" + "\n".join(missing)
    )


def test_go_allowlist_paths_exist(repo_root):
    gone = [p for p in GO_NO_TEST_ALLOWLIST if not (repo_root / p).is_dir()]
    assert not gone, "GO_NO_TEST_ALLOWLIST entries that no longer exist: " + ", ".join(gone)


def test_python_modules_have_tests(repo_root):
    pkg = repo_root / "compiler" / "ariguard_compiler"
    tests = repo_root / "compiler" / "tests"
    corpus = "\n".join(p.read_text() for p in tests.glob("test_*.py"))
    missing = []
    for mod in sorted(pkg.glob("*.py")):
        stem = mod.stem
        if stem in PY_STUB_ALLOWLIST:
            continue
        has_file = (tests / f"test_{stem}.py").exists()
        references = f"ariguard_compiler.{stem}" in corpus or f"import {stem}" in corpus \
            or f" {stem}," in corpus or f"import {stem}" in corpus
        if not (has_file or references):
            missing.append(f"compiler/ariguard_compiler/{mod.name}")
    assert not missing, (
        "Python modules with no test file or test import; add a test or an entry in "
        "PY_STUB_ALLOWLIST:\n" + "\n".join(missing)
    )
