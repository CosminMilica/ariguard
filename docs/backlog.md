# AriGuard — backlog: missing tests & functionality

What's shipped: in-kernel FSM detection + kill/LSM-deny, Phase 3 rule pipeline, Phase 4 bench,
the console (Triage, Campaigns, Timeline, Coverage, Performance, Actors, Lateral, Export),
Tier C C1 autonomous isolation, C2 actor correlation, C3 actor-spread trails.

What's missing splits in two: **credible evaluation** (test with real attacks, not synthetic
syscall drivers) and **functionality** that real attacks need (observed values, true lateral
movement, fleet control plane). The honest gap the testbed exposes: today's "lateral movement"
is *inferred* (same image across namespaces over time), not *observed* network pivoting.

## Testing — credible evaluation

| ID | Task | Why | Depends | Size |
|----|------|-----|---------|------|
| T1 | **Vulnerable-app targets** — deploy deliberately-vulnerable apps in an isolated test cluster: a web RCE entry point (command-injection / deserialization / Log4Shell-class), a multi-service app (frontend→backend→db) so lateral movement has a target, and a misconfigured/privileged pod for escape | synthetic drivers don't prove real detection | — | M |
| T2 | **Real exploit → payload scenarios** — use known public exploits against T1 to get RCE, then run the real post-exploit chain (recon → reverse shell/C2 → creds/escape → **pivot to the next service's pod**) | exercises the FSM with real behavior + real network pivot | T1 | M–L |
| T3 | **Efficacy harness on real attacks** — detection rate, false-positive rate, time-to-mitigate measured on T2 scenarios (not synthetic), reported as numbers | the evidence for the thesis efficacy claim | T1,T2 | M |
| T4 | **Falco / Tetragon comparison** — run the same real scenarios against Falco+Tetragon; compare detection, latency, overhead | the deferred Phase 4 comparison, now on real attacks | T2,T3 | M |
| T5 | **Keep synthetic drivers for CI gating** — the current drivers/e2e/soak stay (fast, deterministic); the testbed is the efficacy evidence, not a CI gate | CI stays fast; don't run real exploits per-PR | — | S |
| T6 | **Realistic-scale soak** — many services + background benign load to back the "1000 services" claim | the flat-memory/no-FP claim under realistic density | T1 | M |

## Functionality — gaps

| ID | Task | Why | Depends | Size |
|----|------|-----|---------|------|
| F1 | **B3 — observed values in the record**: argv, opened path, and **`connect` dst IP:port** | concrete IOCs, and the input for real lateral movement | — | M (kernel ABI; verifier-safe like the fork map) |
| F2 | **True lateral movement** — map `connect` dst IP → target pod identity (IP→pod from podmeta/k8s), emit **real pod→pod edges** | observed pivoting, not image-correlation inference | F1 | M |
| F3 | **Relabel C3 honestly** — call the current image-correlation view "**actor spread**"; reserve "**lateral movement**" for F2's observed network pivots | don't claim what we don't observe | — | S |
| F4 | **Richer actor IOCs (C2)** — add dst IP (and later file hash) to the actor key once B3 lands | stronger "same actor" correlation | F1 | S |
| F5 | **Agent-side mutes/allowlist** — the responder's `muted` is currently nil; push the console mute list to the agent so quarantine/kill honor it | operator control; avoid isolating known-good | — | S |
| F6 | **Quarantine lifecycle** — release/un-quarantine action, optional escalation (cordon/evict), and a cordon/evict fallback where the CNI doesn't enforce NetworkPolicy | isolation is one-way today; kindnet can't enforce NP | — | M |
| F7 | **Control plane / CRD** — dynamic rule/profile distribution to the fleet (Phase 3 deferred) so rules push without rebuilding the agent image | the "fleet" half of the product | PROTO/CP | L |
| F8 | **Rule-library expansion** — more hooks + chains (persistence/cron, more MITRE techniques) | broader coverage; the Coverage page shows the blind spots | — | M |
| F9 | **A2 — ML sequence mining** for rule generation (Phase 3 deferred) | the ML half of the AI bridge | — | L |
| F10 | **Console hardening** — SQLite retention/rotation, auth, multi-node correlation across agents | production/longevity, and cross-node campaigns/actors | — | M |

## Recommended order
1. **F3** (relabel — quick honesty fix, ship with the C2/C3 PR).
2. **F1 (B3)** — observed values incl. connect dst IP. Prerequisite for real lateral + richer IOCs. Do it verifier-safe (separate program/map, like the ppid fork approach — not a task_struct walk in the hot path).
3. **T1 + T2** — vulnerable-app testbed + real exploit scenarios.
4. **F2** — true lateral movement (dst IP → pod) once B3 + testbed exist.
5. **T3 efficacy**, then **T4 Falco comparison** on real attacks.
6. Then the long game: **F7 control plane**, **F8 rules**, **F9 ML**, **F6/F5/F10** hardening.

## Honest notes
- Running real exploits is authorized security research here (own tool, isolated cluster, public
  deliberately-vulnerable apps). It stays **out of CI** (T5) — CI keeps the deterministic drivers.
- B3 (F1) touches the record ABI; the 5.15/6.1 verifier limit bit us on ppid — keep B3's capture
  minimal and prefer a dedicated program/map over widening the hot-path programs.
- Until F2, the "lateral" view is actor-spread inference (F3), not observed pivoting.
