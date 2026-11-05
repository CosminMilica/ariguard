# Enforcement model

AriGuard decides *whether to kill* at three levels: the whole fleet, a single namespace, and (for
visibility) a threat seen across nodes. All three are driven from the console and hot-swapped by the
agents without a restart.

## Levers

| Level | Control | Effect | Set from |
|-------|---------|--------|----------|
| **Fleet mode** | `enforce_mode` (detect \| enforce) | detect = observe only; enforce = kill at terminal states (pod cgroups only). Agents re-apply the current bundle under the new mode. | Settings → *Enforcement mode*; `POST /api/mode` |
| **Namespace observe-only** | `observe_namespaces` | pods in these namespaces are detected but never killed or quarantined — yet their events still count as **attack** (unlike muted pods), so a discovery honeypot keeps running and its mined rules still promote. | Settings → *Namespace enforcement*; `POST /api/observe-namespaces` |
| **Mute (pod)** | `mutes` | a pod is excluded from kill + quarantine **and** its events count as benign (operator allowlist, F5). Muting a quarantined pod releases it (F6). | `POST /api/mutes` |
| **Fleet correlation** | — (read-only) | surfaces one threat (an image **actor**, or a rule) active on ≥2 nodes, with a per-node breakdown and a *spreading* flag. The coordinated / worm signal. | Analysis → *Fleet*; `GET /api/fleet` |

Observe-only vs. mute is the key distinction: both stop the kill, but **mute = known-good** (benign in
telemetry) while **observe-only = known-bad, just don't act here** (attack in telemetry). A honeypot
wants observe-only; a false-positive-prone benign workload wants mute.

## How a mode change reaches the kernel

```
console (SQLite config/observe_namespaces/mutes)
   │  GET /api/v1/mode, /api/v1/observe-namespaces, /api/v1/mutes   (agent polls, ~10s)
   ▼
agent
   ├─ fleet mode   → re-apply last bundle with the new enforce flag (policy.Apply WithEnforce)
   ├─ observe ns   → drop those pods' cgroups from AG_PODS (kill-gate) + responder skips/releases them
   └─ mutes        → same kill-gate/responder skip, and counted benign in console telemetry
```

## Files

```
console/backend/
  store/schema.sql              config, observe_namespaces, mutes tables
  ingest/mode.go                GET /api/v1/mode          (agent poll)
  ingest/observe.go             GET /api/v1/observe-namespaces
  ingest/mutes.go               GET /api/v1/mutes
  api/mode.go                   GET/POST /api/mode        (frontend)
  api/observe.go                GET/POST/DELETE /api/observe-namespaces
  api/mutes.go                  POST/DELETE /api/mutes
  api/fleet.go                  GET /api/fleet            (cross-node correlation)
agent/
  cmd/ariguard-agent/main_linux.go   enforceMode (atomic) + mode poller; observe/mute kill-gate
  internal/sink/sink.go              Mode(), ObserveNamespaces(), Mutes() fetchers; SetEnforce()
  internal/responder/responder.go    quarantine skip + release for muted pods and observe namespaces
console/frontend/src/pages/
  Settings.vue                  fleet-mode toggle + per-namespace Detect/Enforce
  Fleet.vue                     cross-node threats
```
