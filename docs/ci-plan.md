# CI gates

A PR merges only if every layer is verified: format, unit, cross-language contract,
BPF build, verifier load on real kernels, and the end-to-end attack/benign check.
Every gate is a `make ci-*` target; CI runs exactly those targets. One workflow, jobs
chained as a pipeline:

```
Lint ──────┐
Unit ──────┼──► Build BPF ──┬──► Kernel (5.15 · 6.1 · 6.6 · 6.12 · 7.0 · stable · host) ──┐
Contracts ─┘                └──► End-to-end ─────────────────────────────────────────┼──► CI
Security ────────────────────────────────────────────────────────────────────────────┘
```

`CI` aggregates every job into a summary table and is the single required check.
Kernel and e2e jobs reuse the object built once in `Build BPF`.

## Cost: free only

The repo is public, so everything runs on free GitHub tiers. No paid runners or services.

| Need | Free option | Limit to respect |
|---|---|---|
| Runners | GitHub-hosted `ubuntu-latest` (x86, has KVM) | standard runners only, never larger runners; 6 h per job |
| Kernel VMs | vimto + `ghcr.io/cilium/ci-kernels` | pulled from public ghcr, no own registry |
| Cache | `Swatinem/rust-cache`, `setup-go` cache | 10 GB per repo, LRU eviction |
| Artifacts | `actions/upload-artifact` (BPF object, e2e audit on failure) | 7-day retention |
| Security | govulncheck, cargo-deny, pip-audit, gitleaks CLI (not the action) | — |
| Perf trend | `benchmark-action/github-action-benchmark` → `gh-pages` (later) | — |
| Deps | Dependabot | — |

## Gates

| Gate | Target | What it proves | Blocking |
|---|---|---|---|
| G0 hygiene | `ci-hygiene` | `cargo fmt --check`, `clippy -D warnings`, `gofmt`, `golangci-lint`, `ruff check/format`, `buf lint`, `shellcheck` | yes |
| G1 unit | `ci-unit` | `cargo test -p statewall-common`, `go test ./...`, `pytest`, `check_audit.py --self-test` | yes |
| G2 contract | `ci-contract` | golden regenerated = committed, `go mod tidy -diff`, `buf breaking` vs `origin/main` | yes |
| G3 bpf | `ci-bpf` | object builds; Go mirror = object BTF (sizes, offsets, names, map types/capacities); program/section contract; ≤ 512 insns per program | yes |
| G4 kernel | `ci-kernel KERNEL=…`, `ci-kernel-host` | object loads + attaches on 5.15, 6.1, 6.6, 6.12, 7.0, stable (VM) and the runner kernel; chain → `compromised`, fragments, out of order, expiry, hot swap | yes |
| G5 e2e | `ci-e2e` | `phase1-exit-check.sh` on kind, directly on the runner kernel | yes |
| G6 security | `ci-security` | `govulncheck`, `cargo deny check`, `pip-audit`, `gitleaks` (full history) | yes |
| G7 perf | — | latency + memory-vs-process (EVAL-4.1/4.2) | later, nightly only |

Triggers: every PR, push to `main`, nightly at 03:00 UTC (catches new kernels/advisories), manual.
Superseded PR runs are cancelled. Artifacts (BPF object, e2e audit) are uploaded on failure.

## Kernel matrix (G4)

[vimto](https://github.com/lmb/vimto) boots each kernel from `ghcr.io/cilium/ci-kernels` and
runs `go test -tags integration` inside it as root (`.vimto.toml`).

All matrix kernels pass. Pre-6.8 verifiers need the path-prefix loop in `prefix_matches` to exit
on a constant bound, not on `plen`.

Open: on the runner kernel (7.0-azure) the programs attach but the chain raises no events;
`stable` (7.2) passes. The 7.0 matrix entry and the per-program run counts logged on failure
separate a 7.0 regression from an Azure-specific one.

Without KVM (e.g. inside the Lima VM): `VIMTO_DISABLE_KVM=true make ci-kernel KERNEL=5.15`.

G5 runs on the runner kernel (≥ 6.8, BTF, tracepoints) because phase 1 needs no BPF LSM.
Phase 2 LSM tests need `lsm=...,bpf` on the cmdline, which the runner can't set: move G5 to a
[little-vm-helper](https://github.com/cilium/little-vm-helper) image then (CI-3.2).

## Layout

```
.github/
├── actions/setup/            composite: Go + optional Rust/bpf-linker/Python
├── workflows/ci.yml          pipeline: checks → Build BPF → kernel matrix + e2e → CI
└── dependabot.yml            gomod, cargo, pip, actions (weekly, grouped)
.golangci.yml                 default linters, includes the integration tag
.vimto.toml                   kernel VM config for G4
bpf/deny.toml                 cargo-deny policy
Makefile                      ci ci-hygiene ci-unit ci-contract ci-bpf ci-kernel ci-e2e ci-security
pkg/fsm/btf_test.go           G3: ABI vs object BTF
agent/internal/loader/object_test.go       G3: program contract + insn budget
agent/internal/integration/chain_test.go   G4: chains in a child cgroup, asserts SW_AUDIT
```

Object tests skip when `bin/statewall.bpf.o` is missing; CI sets `STATEWALL_REQUIRE_OBJECT=1`
so they fail instead.

## Tasks

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` CI-0.1 | `make ci-*` targets; golangci/buf/cargo-deny configs | — | all targets pass locally |
| `[x]` CI-0.2 | Pin Rust nightly + bpf-linker; Go toolchain in `go.mod` | — | toolchains read from repo files |
| `[~]` CI-0.3 | `ci.yml`: pipeline of jobs, aggregate `CI` check | CI-0.1 | green on main |
| `[x]` CI-1.1 | G3: BPF build job, object uploaded as artifact | CI-0.2 | object on every PR |
| `[x]` CI-1.2 | `pkg/fsm/btf_test.go`: ABI vs object BTF | CI-1.1 | resizing a field fails CI |
| `[x]` CI-1.3 | Insn budget per program | CI-1.1 | regression above 512 fails |
| `[x]` CI-2.1 | G4 vimto kernel matrix | CI-1.1 | programs load on 6.12 + stable |
| `[x]` CI-2.2 | Integration tests: chain, fragments, out of order, expiry, hot swap | CI-2.1 | manual phase-1 runs automated |
| `[x]` CI-2.3 | Make 5.15/6.1/6.6 blocking | BPF verifier fix | all matrix kernels pass |
| `[~]` CI-3.1 | G5 exit check on kind | CI-1.1 | green on the runner (passes in the dev VM; no audit records on the runner yet) |
| `[ ]` CI-3.2 | G5 on little-vm-helper with `lsm=bpf` + `demo-escape` | BPF-2.2 | phase 2 enforcement verified per PR |
| `[ ]` CI-4.1 | Branch protection + required checks | CI-0.3 | direct pushes to main blocked |
| `[ ]` CI-5.1 | Nightly perf trend (EVAL-4.1/4.2) | AGT-4.1, BPF-4.1 | results stored per run |
