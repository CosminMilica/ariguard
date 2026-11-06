# Detector comparison (T4)

AriGuard vs **Falco** vs **Tetragon** on the same real kill-chains (the T3 scenarios), to show the
architectural difference: AriGuard detects a multi-stage attack as one *correlated* in-kernel FSM
incident, whereas Falco (signatures) and Tetragon (programmable probes) fire on *isolated* events.

Not a CI gate — it deploys two extra node agents and drives real exploits.

## Files
- `run-compare.sh` — deploys both tools, drives the three chains in detect mode, tallies detections,
  samples each agent's CPU, writes `RESULTS-compare.md`, tears down (set `KEEP=1` to leave installed).
- `falco.yaml` — Falco rendered from its Helm chart (modern eBPF driver, default rules).
- `tetragon.yaml` — Tetragon rendered from its Helm chart (v1.2.0: later charts' TracingPolicy CRD
  CEL rules are rejected by the cluster's Kubernetes 1.31).
- `tetragon-policy.yaml` — hand-written TracingPolicies; Tetragon ships no detection rules, so each
  watches one chain's characteristic syscall (memfd_create / setns / dup3).

## Run
```
KUBE_CONTEXT=kind-statewall-dev ./run-compare.sh
```

## What it shows
Falco's default rules catch the reverse-shell and fileless IOCs but miss the container-escape chain
(its namespace-change rule is off by default); Tetragon catches only what a policy explicitly names,
with no built-in correlation; AriGuard catches all three as full chains. AriGuard's detection runs
in-kernel (agent near-idle, per-syscall cost on the workload), Falco/Tetragon evaluate in user space.
See `RESULTS-compare.md` for the measured table.
