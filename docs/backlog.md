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
| T1 | ~~**Vulnerable-app targets**~~ **(done)** — command-injection web apps (`tests/testbed/app/`): www-data (DVWA) + root escape targets, a **three-tier frontend→backend→db** across two namespaces for lateral, a reverse-shell target + listener, and benign look-alikes | synthetic drivers don't prove real detection | — | M |
| T2 | ~~**Real exploit → payload scenarios**~~ **(done)** — real post-exploit chains over the web RCE: container-escape (www-data stalls / root completes), reverse-shell (connect→dup2→in-place exec), and a **two-hop lateral pivot** frontend→backend→db observed as pod→pod edges (F2) | exercises the FSM with real behavior + real network pivot | T1 | M–L |
| T3 | **Efficacy harness on real attacks** — `run-suite.sh` runs every scenario + benign twins and writes a detection / lateral-edge / **false-positive** table (`RESULTS-suite.md`); **done** for detection + FP. Still: detection-*rate* across many variants and a per-event time-to-mitigate figure (the latter is `ariguard-bench`'s synchronous-kill latency) | the evidence for the thesis efficacy claim | T1,T2 | M |
| T4 | **Falco / Tetragon comparison** — run the same real scenarios against Falco+Tetragon; compare detection, latency, overhead | the deferred Phase 4 comparison, now on real attacks | T2,T3 | M |
| T5 | **Keep synthetic drivers for CI gating** — the current drivers/e2e/soak stay (fast, deterministic); the testbed is the efficacy evidence, not a CI gate | CI stays fast; don't run real exploits per-PR | — | S |
| T6 | **Realistic-scale soak** — many services + background benign load to back the "1000 services" claim | the flat-memory/no-FP claim under realistic density | T1 | M |

## Functionality — gaps

| ID | Task | Why | Depends | Size |
|----|------|-----|---------|------|
| F1 | **B3 — observed values**: ~~`connect` dst IP:port~~ **(done — `AG_CONNDST` map; see architecture.md)**; still argv + opened path | concrete IOCs, and the input for real lateral movement | — | M (kernel ABI; verifier-safe like the fork map) |
| F2 | ~~**True lateral movement**~~ **(done)** — the agent resolves each `connect` dst IP → target pod (podmeta IP→pod index) and tags the event with `dst_pod`/`dst_ns`; `GET /api/edges` reconstructs observed **pod→pod** edges (cross-namespace first), shown as "Network pivots" on the Lateral page | observed pivoting, not image-correlation inference | F1 | M |
| F3 | ~~**Relabel C3 honestly**~~ **(done)** — the image-correlation view is now "**actor spread**" (inference); "**lateral movement / network pivots**" is reserved for F2's observed edges | don't claim what we don't observe | — | S |
| F4 | **Richer actor IOCs (C2)** — add dst IP (and later file hash) to the actor key once B3 lands | stronger "same actor" correlation | F1 | S |
| F5 | ~~**Agent-side mutes/allowlist**~~ **(done)** — the agent polls `GET /api/v1/mutes`; muted pods are excluded from `AG_PODS` (no kill) and skipped by the responder (no quarantine) | operator control; avoid isolating known-good | — | S |
| F6 | ~~**Quarantine lifecycle**~~ **(done)** — isolation is reversible: muting a quarantined pod releases it (removes the label → drops out of the deny-all NP selector), reported to the console as `released`; `--isolate-fallback=evict` deletes the pod for CNIs that ignore NetworkPolicy (kindnet) | isolation was one-way; kindnet can't enforce NP | — | M |
| F7 | **Control plane** — dynamic rule distribution to the fleet, rules push without rebuilding the agent image: ~~console-served bundle + agent poll + hot-swap~~ **(done — `PUT`/`GET /api/v1/policy`, `policysync`)**; a Kubernetes CRD + reconciler is a further option | the "fleet" half of the product **and the enabler of the autonomous rulegen loop** (see [autonomous-rulegen.md](autonomous-rulegen.md)) | — | L |
| F11 | ~~**Autonomous rulegen loop**~~ **(done + scheduled)** — the orchestrator `loop.py` (`ariguard-rulegen-loop`) closes the loop: mine the corpus + ingest community feeds → build one bundle (curated enforced, proposals **shadow**, admission respects `MAX_RULES` + the per-hook binding budget) → read `GET /api/v1/rules/telemetry` → `decide_mode` promotes/holds/retires → `PUT /api/v1/policy` (F7). Runs unattended as a Kubernetes **CronJob** (`deploy/helm` `rulegen.enabled`, `make rulegen-image`). Shadow = terminal `observe` (no kernel flag). Bulk audit export `GET /api/v1/audit/export` (JSONL) feeds `trace.from_audit`. **Remaining:** agent full-syscall "learn mode" for novel-chain *discovery* from production (kernel change, deferred) — today discovery is honeypot/fixtures + feeds, fleet audit confirms/promotes. (Note: with the busy hooks at the verifier-capped budget after F8, newly mined rules on those hooks wait for headroom; the loop skips them cleanly and still ingests feeds + promotes.) | keep the library current with new attack methods, cheaply and without an LLM | F7 | M |
| F8 | ~~**Rule-library expansion**~~ **(done, round 1)** — added the **Persistence** tactic (previously 0% covered) and **Indicator Removal**: `persistence-cron` (T1053.003), `persistence-ssh-key` (T1098.004), `persistence-startup-script` (T1037.004/T1546.004), `defense-evasion-log-tamper` (T1070.002/.003). Each is a `execve(shell) → openat(persistence-path + write/trunc flags)` chain; the write/trunc arg predicate distinguishes planting/tampering from reading. The per-hook binding budget (`MAX_BINDINGS_PER_HOOK`) blocked this at 8 (openat/execve were full), so it was raised **8→14** — 14 is the empirical ceiling of the **5.15** verifier (16 and 15 fail to load there; the loop's iteration count drives verifier-state growth). To fit 14, the path `PATTERN_LEN` was also halved **64→32** (14 iterations at the full 64 also fails 5.15; all existing prefixes are ≤31 bytes). openat and execve are now exactly 14/14; `defense-evasion-log-tamper` uses a single `/bin/sh` anchor to fit. Gated by the in-kernel behavioral gate + the 5.15→7.0 verifier matrix. More tactics (discovery, more MITRE) remain for round 2. | broader coverage; the Coverage page shows the blind spots | — | M |
| F9 | ~~**A2 — ML sequence mining**~~ **(done)** — `mine.py`/`trace.py`: contrast sequential-pattern mining learns kill-chain rules from labeled attack/benign syscall traces (frequent-in-attack, absent-in-benign), gated by the same schema + A4 + behavioral replay as hand-written rules; re-discovers the shipped chains and learns a new `finit_module→bpf` one | the ML half of the AI bridge | — | L |
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
- A bare outbound `connect` is the reverse-shell chain's entry step but is itself benign (every pod
  connects out). The engine still tracks the `connected` state (and the connect event feeds F2
  pivots), but the console treats `connected` as **non-threat**: only real threat states
  (`suspicious`/`memfd_created`/`stdio_redirected`/`escalating`/`breakout_imminent`/`compromised`) or
  an enforcement action count as alerting. This stops kube-apiserver/agent/etc. showing as
  reverse-shell threats. A rule-level FP-killer (require the connect to be followed by stdio+shell
  before surfacing) is a future option.

## Testbed run 1 — findings (2026-11-02)

First real attack through the new testbed ([`tests/testbed/`](../tests/testbed/),
T1+T2 slice 1): real HTTP command-injection in DVWA → `www-data` shell → recon →
container-escape chain, detect-only. Full transcript + audit in
[`tests/testbed/RESULTS.md`](../tests/testbed/RESULTS.md).

- **Detection works on a real attack, attribution is correct.** `container-escape` fired on
  RCE-driven syscalls (`openat` runtime socket → `suspicious`, `setns` → `escalating`), attributed
  to the right pod/container several processes below apache.
- **Chain stopped at `escalating`, by design of the real world:** the web RCE lands as `www-data`,
  which lacks `CAP_SYS_ADMIN` even in a privileged container. `setns` fired `EPERM` (detected);
  `mount` was refused by util-linux *before* the syscall (nothing to detect). A real escape needs
  privesc to root first — our synthetic driver runs as root and skips that.
  → **new task:** add a privesc step so the full chain is exercised; report "attempt detected" vs
  "escape completed" separately in T3.
- **FP evidence for F1/B3:** 19 benign apache/mariadb loopback `connect` calls matched the
  `reverse-shell` rule (`connected`, observe). Without `connect` dst IP the rule cannot ignore
  loopback/same-pod traffic. This is concrete motivation to do **F1 (B3)** next, then **F4** (dst IP
  in the actor key), as already ordered above.
  - **Update:** the connect-dst half of **B3 is now shipped** — `connect` audit events carry
    `dst_ip`/`dst_port` (verified: `1.2.3.4:4444` from a real RCE connect). Captured via a dedicated
    `AG_CONNDST` map so the hot-path handler stays within the verifier budget (see
    [`docs/architecture.md`](architecture.md)). Remaining B3: argv + opened path. Next: use `dst_ip`
    to make `reverse-shell` ignore loopback (kills the 19-record FP), then **F4**.
  - **Done (FP-killer + F4):** `reverse-shell`'s `outbound_connect` now requires an AF_INET
    non-loopback connect (new `PATH_INET` binding predicate, `inet: true` in the rule / `family: inet`
    in Sigma). The testbed's noise dropped **19 → 0** (the FPs were AF_UNIX DB sockets + loopback,
    not just loopback TCP), with the escape chain unaffected. **F4**: the console now stores
    `dst_ip`/`dst_port` and `/api/actors` surfaces each actor's C2 destinations (`dst_ips`), shown as
    chips on the Actors page.

## Testbed run 2 — findings (2026-11-02)

Slice 2 ([`tests/testbed/run-root.sh`](../tests/testbed/run-root.sh)): the same escape chain
against a **root-running** web app, detect then enforce. Transcript + audit in
[`tests/testbed/RESULTS-root.md`](../tests/testbed/RESULTS-root.md).

- **Full chain + synchronous kill demonstrated on a real attack.** As root the chain completes to
  `compromised` (openat → setns → `fsmount` → execve, all attributed to the pod); under `--enforce`
  the terminal execve is `enforced=true` and the payload never runs (empty step-4 output). The core
  thesis claim, now shown on a real exploit rather than a synthetic driver.
- **Privilege spectrum is the honest efficacy framing:** attempt detected at any privilege (slice 1,
  www-data → `escalating`); completion blocked only once escalated to root (slice 2). T3 should
  report these two separately.
- **Tier C1 demonstrated on a real attack.** After rebuilding + kind-loading the agent image to
  current `main`, the enforce+isolate run quarantined the compromised pod autonomously: label
  `ariguard.io/quarantine=true` + deny-all `NetworkPolicy/ariguard-quarantine`, off the real kill.
  The rebuilt image also restored the Tier B record fields (`ppid`, `image`, `image_id`) the stale
  deployed image lacked. (The dev cluster had been running a pre-C1 image — refresh it after
  agent changes.)
