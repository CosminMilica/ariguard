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
| `[~]` EVAL-2.3 | `phase2-exit-check.sh` (`ARIGUARD_ENFORCE=1`): attackers Failed, benign/host untouched, checker `--enforce` | EVAL-2.1, AGT-2.* | PASS on kind in the VM (authored; not yet run) |

## Phase 4 — Benchmarks & results
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` EVAL-4.1 | Latency harness: syscall overhead (ns) with/without AriGuard | AGT-4.1 | reproducible latency numbers |
| `[x]` EVAL-4.2 | Memory vs. process-count measurement (the flat curve) | BPF-4.1 | flat-line result produced |
| `[x]` EVAL-4.3 | Efficacy: detection rate + false-positive rate | EVAL-1.*, BPF-2.* | precision/recall per kill chain |
| `[ ]` EVAL-4.4 | Head-to-head vs Falco/Tetragon (reaction timing) | DEP-4.1 | sync (ns) vs async (ms) shown |
| `[ ]` EVAL-4.5 | Results tables + plots for the thesis | EVAL-4.1–4.4 | figures ready for `DOC-3` |

EVAL-4.1–4.3: driven by the `ariguard-bench` CLI (latency from BPF run-time stats,
memory curve from RSS + BPF map bytes vs process count, throughput from events/sec +
`audit_dropped`); efficacy from the behavioral gate (detects the attack, no benign false
positive). Observed: flat memory ~938 KiB, ~790k ev/s with 0 drops, ~1–5 µs/hook.
EVAL-4.4 (Falco/Tetragon comparison) is deferred.

## Phase 5 — Real-attack testbed (see [docs/backlog.md](../docs/backlog.md))
Credible evaluation on real exploits, not synthetic syscall drivers.
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` EVAL-5.1 | Vulnerable-app targets: deploy deliberately-vulnerable apps in an isolated test cluster — a web RCE entry point (command-injection / deserialization / Log4Shell-class), a multi-service app (frontend→backend→db) so lateral movement has a target, and a misconfigured/privileged pod for escape (backlog T1) | — | targets deployed; attack surface for RCE + pivot + escape |
| `[ ]` EVAL-5.2 | Real exploit → payload scenarios: known public exploits against EVAL-5.1 to get RCE, then the real post-exploit chain (recon → reverse shell/C2 → creds/escape → pivot to the next service's pod) (backlog T2) | EVAL-5.1 | the FSM is driven by real behavior incl. a real network pivot |
| `[ ]` EVAL-5.3 | Efficacy harness on real attacks: detection rate, false-positive rate, time-to-mitigate measured on EVAL-5.2 scenarios (not synthetic), reported as numbers (backlog T3) | EVAL-5.1, EVAL-5.2 | efficacy numbers for the thesis claim from real attacks |
| `[ ]` EVAL-5.4 | Falco / Tetragon comparison on the real scenarios: same attacks against Falco+Tetragon; compare detection, latency, overhead (the deferred EVAL-4.4, now on real attacks) (backlog T4) | EVAL-5.2, EVAL-5.3 | head-to-head detection/latency/overhead on real attacks |
| `[ ]` EVAL-5.5 | Realistic-scale soak: many services + background benign load to back the "1000 services" claim (backlog T6) | EVAL-5.1 | flat-memory / no-FP claim holds under realistic density |

> Note (backlog T5): the synthetic drivers (`drivers`/e2e/soak) stay as the fast, deterministic
> CI gate; the testbed above is the efficacy evidence, not a per-PR gate — real exploits stay out of CI.
