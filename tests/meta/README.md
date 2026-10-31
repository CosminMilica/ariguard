# Meta-tests

Pure file-scanning tests that guard CI and docs. No VM, cluster, or network. Needs only
Python 3.11+, `pyyaml`, `pytest`.

Run from the repo root:

    compiler/.venv/bin/python -m pytest tests/meta -q

| Test | Guards |
|---|---|
| `test_workflow_pins.py` | `.github/workflows/*.yml` and `.github/actions/**` parse as YAML; every `uses:` is a 40-hex commit SHA or a local `./` path (or is in `UNPINNED_ALLOWLIST`). |
| `test_test_presence.py` | Every Go package with non-test sources under `agent/` and `pkg/` has a `_test.go`; every `compiler/ariguard_compiler/*.py` module has a `test_<mod>.py` or is imported by a test (or is in `PY_STUB_ALLOWLIST`). |
| `test_docs_truth.py` | Every task ID in `ROADMAP.md` (`AGT-1.5.4`, `EVAL-1.5.4`, wildcards like `BPF-2.*`) resolves to a row in the matching `*/TASKS.md`; each TASKS.md legend is exactly `[ ] [~] [x] [!]` and rows use only those; IDs are unique and in the right component file. |
| `test_abi_doc_sync.py` | Struct names in the latest "Kernel object contract" table of `docs/architecture.md` exist as exported structs in `pkg/fsm/abi.go` (names only, not layout; the Go-only `Binding` is not required in the doc). |

`conftest.py` provides the `repo_root` fixture.

## Allowlists

Each allowlist is a dict at the top of its test file: `{key: "one-line reason"}`.
Add an entry only with a reason, and mark gaps to be fixed with a `# TODO`. Remove the
entry when the gap is closed.

- `UNPINNED_ALLOWLIST` (`test_workflow_pins.py`): action name without ref. Currently every third-party action is tag-pinned; pin to SHAs and empty it.
- `GO_NO_TEST_ALLOWLIST` (`test_test_presence.py`): repo-relative package dir.
- `PY_STUB_ALLOWLIST` (`test_test_presence.py`): module stem.
- `UNRESOLVED_ALLOWLIST` (`test_docs_truth.py`): ROADMAP task ID that does not resolve yet.
