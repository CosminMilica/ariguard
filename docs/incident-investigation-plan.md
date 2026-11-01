# Incident Investigation — what an SRE needs when the cluster is compromised

Scenario that drives this plan: an SRE runs ~1000 services; an attacker injected a payload into
one and is trying to spread. AriGuard **already blocked the lethal steps autonomously in-kernel**
(SIGKILL via `bpf_send_signal`, `-EPERM` via LSM) — the operator does **not** fire mitigations by
hand. The console's job is therefore **forensics + blast-radius + coverage**: show what the product
stopped, how far each chain got, where else the same pattern appears, and what we are blind to.

**Status: Tier A shipped** — the console (Go + SQLite backend, Vue 3 frontend) ships Triage,
Campaigns (blast-radius), Timeline, Coverage (ATT&CK × 16 hooks + blind spots), Performance and
per-incident JSON export (#1–6), with interactive per-rule FSM diagrams and enforcement mix, plus
read endpoints `/api/triage`, `/api/campaigns`, `/api/containment`, `/api/coverage`, `/api/export`
and rule/namespace/node filters on `/api/events`. **Tier B #7 (ppid ancestry) and #9 (container
image/digest) are now captured and shown**; a Process Tree is built from `ppid`. **Tier C #11
(autonomous workload isolation) is now shipped as C1** — the agent quarantines the pod on a
confirmed terminal and the console shows an `ISOLATED` badge. Still open: #8 (observed argv/path/dst),
#10 (actor correlation, C2) and #12 (lateral-movement graph, C3).

## Enforcement model: process-kill vs pod-isolation (closed by C1)
AriGuard enforces at **process granularity**: `bpf_send_signal(SIGKILL)` kills the task that
triggered the terminal transition, and LSM `-EPERM` fails the offending syscall. This is instant
(µs, in-kernel) and is the real enforcement signal — **the audit `enforced` count, not the k8s
pod phase**. A pod can stay `Running` after a confirmed kill when the malicious code ran in a
*child* while PID1 lives on (exactly the real threat: a payload injected into a long-lived
service). Killing the process stops the act; it does **not** evict/quarantine the workload.
→ This missing layer is now shipped as **autonomous workload isolation** (C1, #11): on a confirmed
terminal the agent's responder also quarantines the pod — labels it `ariguard.io/quarantine=true`
and, in mode `on`, applies a deny-all NetworkPolicy — driven by the agent, never by an operator
clicking. Gated `--isolate=off|dryrun|on`, idempotent, skipping system namespaces and muted pods.

## Design constraints
- **Autonomous enforcement is the product**, not the console. No manual "kill pod / cordon node"
  buttons. Where a chain only reached `observe`, the answer is to *harden the rule/hook so the
  product auto-blocks it* — never to add a human-in-the-loop step.
- **1000 services** → the UI must group/aggregate, not list. Campaign/rollup views first, raw
  event lists last (windowed).
- **Honesty about data**: some forensic fields do not exist yet in the kernel record. Tiers below
  separate "data already end-to-end" from "needs new kernel capture".

## Data we already have end-to-end (no new capture)
`ts_ns, node, namespace, pod, container-name, comm, pid(tgid), ppid, hook/syscall, rule, event,
from_state→to_state, action, enforced` + per-rule predicate metadata (`transitions[].syscalls[]`)
+ `image` / `image_id` (agent-resolved from the pod). `ppid` is captured in-kernel via CO-RE
(`task_struct->real_parent->tgid`, `vmlinux` bindings in `bpf/ariguard-ebpf/src/vmlinux.rs`) and
feeds the Process Tree view.

## Data we do NOT capture yet
`argv`, `opened path`, `connect dst IP:port` → all still need new `AuditRecord` fields
(`bpf/ariguard-common/src/lib.rs` + mirror `agent/pkg/fsm/abi.go`, then plumb
agent→sink→schema→api→ts).

## Plan (tiered)

```
console/frontend/src/
  pages/
    Triage.vue        # T1  live non-terminal chains, ranked by stage depth + recency
    Campaign.vue      # T2  blast-radius: group incidents by rule / ns / node / image / time-bucket
    Timeline.vue      # T3  one global time axis, all events, filter by ns/node/rule/action
    Coverage.vue      # T5  MITRE technique x hook matrix; hooks attached vs total; blind spots
  components/
    ContainmentBar.vue# T4  cluster rollup: auto-blocked vs observe-only (= enforcement gaps)
    ActorCard.vue     # T10 incidents sharing an IOC (image/comm/dst) grouped as one actor
    ProcTree.vue      # T7  process ancestry tree (needs ppid)
console/backend/api/
  triage.go campaign.go timeline.go coverage.go export.go   # aggregation endpoints
bpf/ariguard-common/src/lib.rs + agent/pkg/fsm/abi.go       # T7/T8 new AuditRecord fields
agent/internal/podmeta/podmeta.go                           # T9 read image/digest
```

| # | Feature | Answers (SRE question) | Tier | Needs |
|---|---------|------------------------|------|-------|
| 1 | Threat triage board | "What is mid-attack right now?" (non-terminal chains, ranked) | A | UI+API, data exists |
| 2 | Campaign / blast-radius grouping | "One compromise or a worm? Which ns/nodes?" | A | UI+API, data exists |
| 3 | Global cross-workload timeline | "Entry point → lateral movement, on one axis" | A | UI+API, data exists |
| 4 | Enforcement mix + containment rollup | "What did the product auto-block vs only watch?" | A | UI (rules action-mix shipped) |
| 5 | Coverage matrix (MITRE × hooks) | "Attacker used X — did we even have a sensor?" | A | needs technique↔rule map |
| 6 | Incident evidence export (JSON) | "Attach proof to the ticket" | A | API, data exists |
| 7 | Process ancestry tree | "What spawned the payload?" (highest forensic value) | B | **new kernel field** (ppid) |
| 8 | Observed values (argv / path / dst IP:port) | "The concrete IOC, not just 'predicate matched'" | B | **new kernel fields** |
| 9 | Container image / digest | "Pin the compromised image across the fleet" | B | agent-only (podmeta) |
| 10 | Actor correlation (shared IOC) | "Is this the same attacker across pods?" | C | depends on #8/#9 |
| 11 | **Autonomous workload isolation** (shipped, C1) | "Kill stops the process — also quarantine the pod" (deny-all NetworkPolicy / cordon / evict, product-driven) | C | agent k8s responder + RBAC |
| 11b | Expand autonomous coverage | "Auto-block the chains that only got observed" | C | more hooks/rules + profiles |
| 12 | Lateral-movement graph (ns→ns) | "Watch the spread" | C | depends on #2/#3 |

## Recommended order
Tier A (1–6) first — pure UI/backend on existing data, turns the console into a real IR tool.
Then **#7 (ppid ancestry)** as the first kernel widening: it is the single most valuable forensic
field ("what spawned it") and is a small, bounded `AuditRecord` addition. #8 (observed values)
follows. #9 (image) can land anytime (agent-only). Tier C is the long-game: correlation + pushing
more of the kill-chain into autonomous in-kernel enforcement.
