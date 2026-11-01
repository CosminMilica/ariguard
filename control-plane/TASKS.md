# control-plane — Tasks

Cluster operator (Go / controller-runtime). See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 3 — CRD, reconcile, distribute
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` CP-3.1 | `ThreatPolicy` CRD types + deepcopy + CRD manifest | — | `kubectl apply` installs the CRD |
| `[ ]` CP-3.2 | controller-runtime manager bootstrap | CP-3.1 | manager starts, leader election works |
| `[ ]` CP-3.3 | Reconciler: compile `ThreatPolicy` → transition table | CP-3.2, CMP-3.* | table produced on spec change |
| `[ ]` CP-3.4 | gRPC server: `PushPolicy` to agents, `StreamAudit` sink | PROTO-3.1 | agents receive tables, send audit |
| `[ ]` CP-3.5 | Agent registry / fleet view | CP-3.4 | connected agents listed with status |
| `[ ]` CP-3.6 | Audit aggregation + export (metrics / logs) | CP-3.4 | cluster-wide audit queryable |

> Backlog F7 (dynamic rule/profile distribution to the fleet, so rules push without rebuilding the
> agent image) is this Phase 3: `CP-3.1`–`CP-3.4` + `AGT-3.1` + `PROTO-3.1`. See [docs/backlog.md](../docs/backlog.md).

## Phase 4 — Evaluation support
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` CP-4.1 | Status surface for demo (policies active, mitigations count) | CP-3.6 | single view for the demo/thesis |
