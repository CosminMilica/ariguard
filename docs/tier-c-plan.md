# Tier C — autonomous response, actor correlation, lateral movement

Follows the incident-investigation plan ([docs/incident-investigation-plan.md](incident-investigation-plan.md)).
Tier A (triage/campaigns/timeline/coverage/export) and Tier B1/B2 (container image, ppid
process tree) shipped. Tier C closes the gap that investigation surfaced: **AriGuard kills the
offending process in-kernel, but the pod keeps running** — the product must also isolate the
workload autonomously, and the console must let an SRE reason about *the actor*, not just single
incidents.

**Status: C1, C2 and C3 shipped.** Autonomous workload isolation is implemented and wired end to
end (agent responder → RBAC → console); actor correlation (`GET /api/actors`, Actors page) and the
lateral-movement trails view (`GET /api/lateral`, Lateral page) are implemented console-side. Still next:
B3 (observed values — argv/path/connect dst IP:port), which will add the C2 dst IP as an extra IOC.

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
  lateral.go          # C3 GET /api/lateral: per-actor movement trails (ns path over time)
  quarantine.go       # C1 GET /api/quarantine: what was isolated, when, how
console/frontend/src/pages/
  Actors.vue          # C2 one row per actor (shared image/comm/dst), its incidents + spread
  Lateral.vue         # C3 actor-centric trails list + filters + focused path diagram
console/frontend/src/components/
  QuarantineBadge.vue # C1 isolation status on Triage/Incident rows
```

| # | Feature | Answers | Needs | Tier |
|---|---------|---------|-------|------|
| C1 | **Autonomous workload isolation** | "Kill stopped the process — is the pod contained?" | agent responder + k8s client + RBAC; console status | **shipped** |
| C2 | **Actor correlation (IOC)** | "Is this one attacker across many pods?" | `GET /api/actors` clustering by image digest (+ dst IP once B3 lands) + Actors page | **shipped** |
| C3 | **Lateral-movement trails** | "Watch the spread ns→ns over time" | `GET /api/lateral` per-actor namespace trails + actor-centric Lateral page | **shipped** |

## C1 — autonomous workload isolation (detail, shipped)
```
 confirmed terminal (audit enforced=1, kill/deny)  ──►  responder (agent/internal/responder)
   │  pod identity already resolved (podmeta: ns/pod); runs off the audit drain (non-blocking)
   ▼
 quarantine(pod), once:
   • label pod  ariguard.io/quarantine=true  +  annotations
     ariguard.io/quarantine-rule, ariguard.io/quarantined-at   (visible, idempotent key)
   • mode on: create namespace-scoped deny-all NetworkPolicy "ariguard-quarantine"
     (podSelector ariguard.io/quarantine=true, policyTypes Ingress+Egress, no rules = deny all)
   • dryrun: label only, no NetworkPolicy
   • (opt-in escalation) cordon node / evict pod — off by default
   ▼
 report the quarantine  ──►  console POST /api/v1/quarantine (read GET /api/quarantine, ISOLATED badge)
```
- **Where**: the agent (DaemonSet) already has the pod identity and runs per-node. Shipped cut: the
  agent applies isolation directly via the in-cluster k8s API (needs RBAC). Later: route the
  decision through the control-plane (CRD/gRPC, Phase 3 B7) for a central policy and audit trail.
- **Wiring**: an `audit.Reactor` interface is called from the ringbuf audit stream; the agent gets a
  `--isolate=off|dryrun|on` flag (Helm `agent.isolate`, default `off`; kustomize overlay
  `deploy/k8s/overlays/isolate` = `--enforce --isolate=on`). RBAC: the agent ClusterRole gained
  `pods: get,patch` and `networking.k8s.io/networkpolicies: get,list,create,update`
  (`deploy/k8s/base/rbac.yaml` + Helm).
- **Safety**: idempotent (a pod is quarantined once); never quarantines system namespaces
  (`kube-system`, `kube-public`, `kube-node-lease`, `ariguard-system`) or AriGuard itself (same
  allowlist spirit as F2 pod-gating); honors the existing `mutes`.
- **Testing**: unit tests (fake clientset, ~94% coverage, pass with `-race`) cover every mode, the
  skip guards, mute, idempotency, retry-after-API-failure, concurrency, the report callback, the
  NetworkPolicy spec, the `deny` action, label preservation and multi-namespace; a `sink.Quarantine`
  test; a backend quarantine ingest/api test; and an e2e `TestIsolation` (asserts the quarantine
  label + deny-all NetworkPolicy on attackers, and zero benign false positives) via the isolate
  overlay.

## C2 — actor correlation (detail, shipped)
`GET /api/actors` (`console/backend/api/actors.go`, `Actors.vue`) clusters the existing incident
groups by **container image digest** (`image_id`): the same compromised image across many
pods/namespaces is **one actor** — a campaign by payload, not by rule — sorted widest-spread (most
pods) first. Each actor returns its image + digest, incidents, pods, namespaces, nodes, the
killed/blocked/detected counts, the `rules[]` it triggered, the `comms[]`, and
`affected_namespaces[]`. The frontend **Actors** page is a table, one row per actor, with
wide-spread rows accented. Builds on the image + digest captured in Tier B1 and reuses the incident-
group materialization (now carrying `image_id`/`image`/`comm`); no kernel/agent change. Tested by
`TestActors`. Gains the connect dst IP:port as an extra IOC once B3 lands.

## C3 — lateral-movement trails (detail, shipped)
`GET /api/lateral` (`console/backend/api/lateral.go`, `Lateral.vue`) reconstructs attacker
movement as **per-actor trails**: for each actor (container image digest) it returns the distinct
namespaces that actor reached in first-seen order (`path`, earliest-first), `hops` (= len(path) − 1;
0 = no lateral movement), plus its namespaces, pods, incidents, killed/blocked counts, the `rules[]`
it triggered and first/last seen. Actors sort movers-first. The response is `{ actors: [...],
namespaces: [...] }`, the namespace list feeding the filter. The frontend **Lateral** page is an
actor-centric, filterable, scalable view (not a single graph, which was a hairball at scale): an
explainer intro; Actor + Namespace dropdowns and a "Moved only" toggle (default on, hops ≥ 1); a
list of actors, each row showing the actor image and its namespace path rendered as chips with
arrows (ns-a → ns-b → ns-c) alongside hops/namespaces/pods/incidents, killed/blocked badges, rules
and first/last seen; and a focused inline-SVG path diagram (a clean left→right line of the
namespaces) shown only when a single actor is selected. Console-only, on existing incident data.
Tested by `TestLateral`.

## Recommended order
**C1 first** — highest impact on the "1000-service compromise" scenario, pure control-plane
(zero kernel/verifier risk), and it closes the process-kill ≠ pod-isolation gap. **C2** next
(image/comm IOC already captured; gains dst IP when B3 lands). **C3** last (trails on existing
incident data).

## Honest caveats
- NetworkPolicy requires a CNI that enforces it (Cilium/Calico); kind's default may not — the
  demo pins a CNI or documents the requirement; cordon/evict is the fallback.
- Agent-applied isolation can race if several nodes see the same cgroup; the idempotent label +
  a single-writer guard (or routing through the control-plane) avoids double-apply.
- Actor correlation is only as good as the IOCs; image digest + comm are weak alone, strong once
  joined with the B3 connect dst IP:port.
