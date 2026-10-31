# CI gates — plan

Goal: a PR merges only if every layer is verified — format, unit, cross-language contract,
BPF build, verifier load on real kernels, and the end-to-end attack/benign check.
Every gate is a `make ci-*` target, so local runs and CI run the same thing.

## Gates

| Gate | What it proves | Runs on | When |
|---|---|---|---|
| G0 hygiene | fmt + lint: `cargo fmt --check`, `clippy`, `gofmt -l`, `golangci-lint`, `ruff check/format --check`, `buf lint`, `shellcheck` | ubuntu-latest | every PR, required |
| G1 unit | `cargo test -p statewall-common`, `go test -race ./...`, `pytest`, `check_audit.py --self-test` | ubuntu-latest | every PR, required |
| G2 contract | golden is fresh (`make golden && git diff --exit-code`), `go mod tidy` clean, `buf breaking` vs main, generated proto fresh (after PROTO-0.1) | ubuntu-latest | every PR, required |
| G3 bpf | object builds with pinned nightly + bpf-linker; ABI check against the object's BTF; insn-count budget | ubuntu-latest | every PR, required |
| G4 kernel | object loads + attaches on a kernel matrix; Go integration tests drive the chain and read `SW_AUDIT` | VM on KVM runner | every PR, required |
| G5 e2e | `phase1-exit-check.sh` (later `demo-escape`) on kind inside a VM | VM on KVM runner | PR touching `bpf/ agent/ pkg/ compiler/ testdata/`, main, nightly |
| G6 security | `govulncheck`, `cargo deny`, `pip-audit`, `gitleaks` | ubuntu-latest | every PR, required |
| G7 perf | latency + memory-vs-process (EVAL-4.1/4.2), stored as trend | VM on KVM runner | nightly only, not a merge gate |

## Gaps the gates close

| Gap today | Fix |
|---|---|
| ABI sizes/offsets are hardcoded in `pkg/fsm/abi_test.go`; a Rust-side layout change is not caught | G3: Go test parses BTF from `bin/statewall.bpf.o` (cilium/ebpf `btf`) and compares struct sizes, field offsets and map `max_entries` with `pkg/fsm` |
| Verifier acceptance is only checked by hand in the Lima VM | G4: load + attach in CI on each kernel in the matrix |
| `rust-toolchain.toml` is `nightly` (floating) | pin a dated nightly; bump via PR so G3/G4 see it |
| Go 1.25 in `go.mod`, 1.27.3 in the VM | one version, read by CI from `go.mod` |
| Golden can drift from the rule file | G2 regenerates and diffs |
| Exit check only runs manually | G5 |

## Kernel gates (G4/G5)

GitHub-hosted runners can't reboot with `lsm=...,bpf`, so kernel tests run in a VM:

- **G4** — [vimto](https://github.com/lmb/vimto) (what cilium/ebpf uses): `go test -exec vimto -tags integration` on kernels from `ghcr.io/cilium/ci-kernels`. Fast, no kind.
- **G5** — [little-vm-helper](https://github.com/cilium/little-vm-helper) (what Tetragon uses): full Ubuntu image with docker + kind, custom cmdline (`lsm=bpf` for phase 2).

Kernel matrix: `5.15`, `6.1`, `6.6`, `6.8` (dev VM), `stable`. Phase 2 LSM tests skip below 5.7 by design; the matrix floor stays ≥ 5.15.
arm64: G3 builds for both arches; kernel runs are amd64 only until arm64 runners expose KVM.

## Layout

```
.github/
├── workflows/
│   ├── ci.yml          G0 G1 G2 G3 G6 — fast, required
│   ├── kernel.yml      G4 — kernel matrix, required
│   ├── e2e.yml         G5 — path-filtered + main + nightly
│   └── nightly.yml     G7 + full G5
└── dependabot.yml      go, cargo, pip, actions
Makefile                ci-hygiene ci-unit ci-contract ci-bpf ci-kernel ci-e2e ci-security
agent/internal/integration/   //go:build integration — load, attach, chain, audit
pkg/fsm/btf_test.go           ABI vs object BTF (skips if object missing locally)
```

Branch protection on `main`: G0–G4 + G6 required, G5 required once stable (start as informational).

## Tasks

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` CI-0.1 | `make ci-*` targets wrapping existing commands; `ruff`/`golangci-lint`/`shellcheck` configs | — | all targets pass locally |
| `[ ]` CI-0.2 | Pin Rust nightly + bpf-linker; align Go version | — | toolchains read from repo files |
| `[ ]` CI-0.3 | `ci.yml` with G0, G1, G2, G6 + caching (cargo, go, pip) | CI-0.1 | green on main, < 5 min |
| `[ ]` CI-1.1 | G3: BPF build job, object uploaded as artifact | CI-0.2 | `statewall.bpf.o` per arch on every PR |
| `[ ]` CI-1.2 | `pkg/fsm/btf_test.go`: ABI vs object BTF | CI-1.1 | renaming/resizing a Rust field fails CI |
| `[ ]` CI-1.3 | Insn-count budget per program (`bpftool prog show` / cilium/ebpf stats), fail above threshold | CI-2.1 | budget file committed, regression fails |
| `[ ]` CI-2.1 | `kernel.yml` with vimto + kernel matrix; load + attach test | CI-1.1 | all six programs attach on every kernel |
| `[ ]` CI-2.2 | Integration tests: chain in a test cgroup → `compromised`; out-of-order, expiry, hot swap | CI-2.1 | the manual phase-1 runs are automated |
| `[ ]` CI-3.1 | `e2e.yml` with little-vm-helper image (docker, kind, `lsm=bpf`) running `phase1-exit-check.sh` | CI-1.1 | exit check green in CI, artifacts uploaded |
| `[ ]` CI-3.2 | Extend G5 with `demo-escape` (deny `-EPERM`, kill) | BPF-2.2, CI-3.1 | phase 2 enforcement verified per PR |
| `[ ]` CI-4.1 | Branch protection + required checks | CI-0.3, CI-2.1 | direct pushes to main blocked |
| `[ ]` CI-5.1 | `nightly.yml`: perf trend (EVAL-4.1/4.2) | AGT-4.1, BPF-4.1 | results stored per run |

Order: CI-0.* → CI-1.1/1.2 → CI-2.* → CI-3.1 → CI-4.1. CI-3.2 and CI-5.1 follow phases 2 and 4.

## Open

- vimto attach for tracepoints needs `debugfs`/`tracefs` in the guest — confirm on the first run.
- KVM on free GitHub-hosted runners: available on `ubuntu-latest` (x86); if it gets flaky, fall back to a self-hosted runner.
