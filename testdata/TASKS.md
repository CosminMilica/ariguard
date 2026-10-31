# testdata — Tasks

Synthetic datasets + benchmark/evaluation harness. See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 1 — Workloads
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` EVAL-1.1 | Synthetic benign workload scripts (training/FP baseline) | — | reproducible benign syscall traffic |
| `[x]` EVAL-1.2 | Container-escape attack script (the demo chain) | — | triggers the FSM to compromised state |
| `[x]` EVAL-1.3 | Phase 1 exit check: run benign + attack, assert on the audit stream | EVAL-1.1, EVAL-1.2, AGT-1.6 | attack reaches `compromised`; benign never passes `suspicious` |

## Phase 1.5 — Generic engine
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` EVAL-1.5.1 | Attacks: `reverse-shell` and `fileless-exec`; a `container-escape` variant that uses `connect` on the socket | CMP-1.5.3 | each drives its rule to `compromised` under its own pod name on kind |
| `[x]` EVAL-1.5.2 | Benign twins: a process that connects then redirects stdio without a shell; a process that creates a memfd then execs a normal binary | CMP-1.5.3 | twins reach at most observe-only states (`connected` / `memfd_created`) |
| `[x]` EVAL-1.5.3 | Expectations file + checker v2: per rule, the expected attacker pod reaches the terminal state through the chain in order; only expected attackers get a non-observe action | AGT-1.5.4 | self-test green; drives the real stream |
| `[x]` EVAL-1.5.4 | Exit check v2: all benign and attack pods at once on kind | EVAL-1.5.1 … 1.5.3 | PASS on kind twice in a row |

EVAL-1.5.1 – 1.5.4: verified on kind (Wave D). No listener: `reverse-seq` connects to a closed
local port. Two manifest changes were needed for correct pod attribution: attack emitters warm
up (`sleep 8`) so the agent resolves their cgroup before the chain fires, and `reverse-seq` /
`fileless-seq` fork so a parent keeps the cgroup alive until the records are drained. One real
rule finding: the container runtime (containerd/shim/CNI, a host cgroup) walked the escape chain
during pod setup — fixed by scoping `namespace_manipulation` to mount/pid/user namespaces
(setns/unshare `mask_any 0x30020000`), which excludes the runtime's network/cgroup/uts work.

## Phase 2 — Enforce mode
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` EVAL-2.1 | Checker A4 + `--enforce`: `enforced` only on attackers' `kill` records; enforce requires attackers' terminal records enforced, dry-run requires none | AGT-2.* | self-test green in both modes; verified by ci-unit (self-test) and ci-e2e (both modes) |
| `[x]` EVAL-2.2 | v2 fixtures with the `enforced` key: dry-run pass, enforce pass, and one failing fixture per A4 reason | EVAL-2.1 | each fails for exactly its assertion; verified by ci-unit self-test |
| `[~]` EVAL-2.3 | `phase2-exit-check.sh` (`STATEWALL_ENFORCE=1`): attackers Failed, benign/host untouched, checker `--enforce` | EVAL-2.1, AGT-2.* | PASS on kind in the VM (authored; not yet run) |

## Phase 4 — Benchmarks & results
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` EVAL-4.1 | Latency harness: syscall overhead (ns) with/without Statewall | AGT-4.1 | reproducible latency numbers |
| `[ ]` EVAL-4.2 | Memory vs. process-count measurement (the flat curve) | BPF-4.1 | flat-line result produced |
| `[ ]` EVAL-4.3 | Efficacy: detection rate + false-positive rate | EVAL-1.*, BPF-2.* | precision/recall per kill chain |
| `[ ]` EVAL-4.4 | Head-to-head vs Falco/Tetragon (reaction timing) | DEP-4.1 | sync (ns) vs async (ms) shown |
| `[ ]` EVAL-4.5 | Results tables + plots for the thesis | EVAL-4.1–4.4 | figures ready for `DOC-3` |
