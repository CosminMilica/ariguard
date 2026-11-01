# Tier C — autonomous response, actor correlation, lateral movement

Follows the incident-investigation plan ([docs/incident-investigation-plan.md](incident-investigation-plan.md)).
Tier A (triage/campaigns/timeline/coverage/export) and Tier B1/B2 (container image, ppid
process tree) shipped. Tier C closes the gap that investigation surfaced: **AriGuard kills the
offending process in-kernel, but the pod keeps running** — the product must also isolate the
workload autonomously, and the console must let an SRE reason about *the actor*, not just single
incidents.

## Design constraints
- **Autonomous, not operator-driven.** Isolation is the product's action on a confirmed terminal
  (`enforced=1`, action kill/deny), never a console button. Same stance as enforcement.
- **Isolate, don't destroy.** Default to cutting the blast radius (deny-all NetworkPolicy) and
  marking the pod, so the evidence (process, logs, fs) survives for investigation. Deleting the
  pod is a separate, opt-in escalation.
- **Gated + dry-run first**, like enforce/detect: `isolate=off|dryrun|on`. Dry-run annotates only.
- **Idempotent**: a pod is quarantined once; re-entry is a no-op.
- Build on existing data where possible; new kernel work is avoided (Tier C is user-space/control-plane).

## Plan (tiered)

```
agent/internal/responder/            # C1 the autonomous isolator
  responder.go        # on confirmed terminal -> quarantine(pod) once (idempotent set)
  quarantine_linux.go # k8s client: apply deny-all NetworkPolicy + label; optional cordon/evict
deploy/k8s/base/rbac.yaml            # C1 Role: networkpolicies create/get, pods get/patch/list
deploy/helm/.../templates/rbac.yaml  # C1 same, Helm
console/backend/api/
  actors.go           # C2 GET /api/actors: cluster incidents by shared IOC
  lateral.go          # C3 GET /api/lateral: ns->ns spread edges over time
  quarantine.go       # C1 GET /api/quarantine: what was isolated, when, how
console/frontend/src/pages/
  Actors.vue          # C2 one row per actor (shared image/comm/dst), its incidents + spread
  Lateral.vue         # C3 movement graph (nodes = namespaces, edges = time-ordered spread)
console/frontend/src/components/
  QuarantineBadge.vue # C1 isolation status on Triage/Incident rows
```

| # | Feature | Answers | Needs | Tier |
|---|---------|---------|-------|------|
| C1 | **Autonomous workload isolation** | "Kill stopped the process — is the pod contained?" | agent responder + k8s client + RBAC; console status | **first** |
| C2 | Actor correlation (IOC) | "Is this one attacker across many pods?" | backend grouping by image/comm (+ dst IP once B3 lands) + Actors page | second |
| C3 | Lateral-movement graph | "Watch the spread ns→ns over time" | backend edges from incidents + graph page | third |

## C1 — autonomous workload isolation (detail)
```
 confirmed terminal (audit enforced=1, kill/deny)  ──►  responder
   │  pod identity already resolved (podmeta: ns/pod)
   ▼
 quarantine(pod), once:
   • apply deny-all NetworkPolicy selecting the pod's label (cut C2 + lateral)
   • label pod  ariguard.io/quarantine=<rule>,<ts>  (visible, idempotent key)
   • dryrun: label only, no NetworkPolicy
   • (opt-in escalation) cordon node / evict pod — off by default
   ▼
 record a quarantine event  ──►  console /api/quarantine + QuarantineBadge
```
- **Where**: the agent (DaemonSet) already has the pod identity and runs per-node. First cut: the
  agent applies isolation directly via the in-cluster k8s API (needs RBAC). Later: route the
  decision through the control-plane (CRD/gRPC, Phase 3 B7) for a central policy and audit trail.
- **Safety**: never quarantine the node's own system namespaces or AriGuard itself (same
  allowlist spirit as F2 pod-gating); honor the existing `mutes`.
- **Testing**: e2e — an attacker reaches terminal → assert a deny-all NetworkPolicy exists for its
  pod and the quarantine label is set; a benign twin is never quarantined; dry-run applies no
  NetworkPolicy.

## Recommended order
**C1 first** — highest impact on the "1000-service compromise" scenario, pure control-plane
(zero kernel/verifier risk), and it closes the process-kill ≠ pod-isolation gap. **C2** next
(image/comm IOC already captured; gains dst IP when B3 lands). **C3** last (graph on existing
incident data).

## Honest caveats
- NetworkPolicy requires a CNI that enforces it (Cilium/Calico); kind's default may not — the
  demo pins a CNI or documents the requirement; cordon/evict is the fallback.
- Agent-applied isolation can race if several nodes see the same cgroup; the idempotent label +
  a single-writer guard (or routing through the control-plane) avoids double-apply.
- Actor correlation is only as good as the IOCs; image digest + comm are weak alone, strong once
  joined with the B3 connect dst IP:port.
