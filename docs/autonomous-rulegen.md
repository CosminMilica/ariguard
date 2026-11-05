# Autonomous rule generation (no LLM)

Status: engine implemented (compiler); the live fleet loop depends on the control plane (backlog F7).

Goal: keep the rule library current with new attack methods **autonomously and cheaply** — no LLM,
no API key, CPU-only. The LLM co-author (A3) was only ever a prose→rule translator billed per call.
We replace it with sources that update themselves for free and a data-driven miner that learns from
behavior, all funnelled through the one gate every rule must pass.

## Three cheap sources, one gate

```
  (1) community feeds        (2) honeypot / canary       (3) fleet baseline
  SigmaHQ · Atomic · Falco   deliberately-vulnerable       each workload's own
  (humans write them, free)  pods; every trace = attack    learned "normal"
        │                            │                            │
        │ feeds.ingest_dir           │ trace capture (attack)     │ learn_baseline (benign)
        ▼                            ▼                            ▼
        │                     autogen.mine_novel: subsequences frequent in attack,
        │                     NOVEL against the baseline (frequency stats, no model)
        ▼                            ▼
  ┌──────────────────────── the SAME gate ────────────────────────┐
  │ schema (parse_rule) + A4 (validate + round-trip) + behavioral  │
  │ replay: fire on every attack trace, silent on every benign one │
  └────────────────────────────────┬───────────────────────────────┘
                                    ▼
                         SHADOW (detect-only) on the fleet
                                    │  measure hits + false positives on real traffic
                                    ▼
                    decide_mode: ENFORCE when it has caught real
                    attacks over a window with 0 false positives;
                    RETIRE on any benign fire; else stay SHADOW
```

Why no LLM is needed: source (1) is the security community's continuously-updated detections — we
already compile Sigma, so we just ingest the expressible ones; sources (2) and (3) learn from real
behavior with plain frequency statistics (a gap-allowed PrefixSpan and a contrast score), which run
on a CPU on the node. Nothing is billed, nothing is hallucinated, and every output is explainable:
each rule carries the subsequence and contrast score it was learned from.

## Why it is safe to be autonomous

Nothing kills a process from a rule that has not proven itself. A newly minted rule is **shadow**
(detect-only): it emits audits but never kills. The console measures, per rule, how many real
attacks it caught and whether it ever fired on benign traffic; `decide_mode` promotes it to
**enforce** only after a window of real catches with zero false positives, and **retires** it on a
single benign fire. Autonomy up to enforcement; enforcement earned on data, not hoped for.

## What is implemented (this change)

| Piece | Module |
| --- | --- |
| Labeled trace model + loaders | `trace.py` |
| Contrast sequence mining + gate (attack vs benign twin) | `mine.py` (`ariguard-mine`) |
| Learned fleet baseline + novelty mining | `autogen.py` `learn_baseline`, `mine_novel` |
| Shadow→enforce promotion policy | `autogen.py` `decide_mode` |
| Autonomous pass (baseline + honeypot → shadow rules) | `autogen.py` `autogenerate` (`ariguard-autogen`) |
| Community-feed ingestion (Sigma → FSM, auto-filtered) | `feeds.py` |

Fixtures in `testdata/traces/` prove it: `ariguard-autogen testdata/traces/fleet` learns the fleet
baseline from the benign runs and proposes a new shadow rule `unshare → mount → execve` (a
user-namespace escape not in the hand-written library), gated and silent on all benign traffic.

## The live loop (F11)

The engine above runs offline on a trace corpus. `loop.py` (`ariguard-rulegen-loop`) is the
orchestrator that closes the loop against a running console, in one deterministic pass:

```
ariguard-rulegen-loop \
  --rules-dir rules --sigma-dir rules/sigma/generated \   # curated library (always enforced)
  --corpus testdata/traces --feeds vendor/sigma \          # discovery: mine + ingest community
  --console http://ariguard-console                        # F7: pull telemetry, push the bundle
```

1. **Mining service** — **done**, and scheduled. `build_bundle` runs `autogenerate` over the labeled
   corpus (fleet baseline + honeypot) and `feeds.ingest_dir` over the community Sigma snapshot, links
   the curated library + the survivors into one bundle. Admission respects both `MAX_RULES` and the
   per-hook binding budget (`MAX_BINDINGS_PER_HOOK`): the curated library has priority, so a proposal
   that would overflow a busy hook (e.g. `execve` at capacity after the F8 library) is skipped this
   pass rather than failing the build. It runs as a Kubernetes **CronJob** (`deploy/helm`
   `rulegen.enabled`, image `make rulegen-image`) — CPU-only and offline but for the two console
   calls, so the fleet's policy stays current with no operator in the loop.
2. **Live distribution (F7)** — **done**. The console is the control plane: the loop
   `PUT /api/v1/policy` (the compiled bundle), and every agent polls `GET /api/v1/policy?have=<version>`
   every `policyInterval` and hot-swaps a new version into the kernel maps (the existing SIGHUP
   apply path), with no image rebuild. Version = the bundle's SHA-256, so an unchanged push is a
   fleet-wide 304. Shadow vs enforce is just the terminal action compiled into a rule: a shadow
   rule's is `observe`, the promoted one's is `kill` — no per-rule kernel flag.
3. **Shadow telemetry + auto-promote** — **done**. The console computes per-rule behavior at
   `GET /api/v1/rules/telemetry` (terminal-state hits, distinct pods, time span, and *benign fires*
   = hits on a muted/operator-declared-known-good pod). The loop maps it to `ShadowMetrics` and lets
   `decide_mode` promote a proven rule (enough hits over enough days, zero benign fires) to enforce,
   hold it in shadow, or retire one that fired on benign traffic — then re-pushes. A newly mined
   rule therefore ships `observe`-only and can never kill until it has earned it on real traffic.
4. **Full-syscall trace capture + discovery** — **done via the honeypot** ([`tests/honeypot`](../tests/honeypot/README.md)),
   no kernel change. The agent's audit stream carries **only rule-matched** events, so it confirms
   rules and drives promotion but cannot *discover* new chains. A honeypot closes that gap: a
   deliberately-vulnerable decoy runs each injected command under `strace -f`, a capture sidecar
   (`ariguard-trace-capture`) parses the whole session into an attack-labeled trace (dropping
   linker/locale noise) and POSTs it to the console (`POST /api/v1/traces`); the loop pulls it
   (`--honeypot` / `GET /api/v1/traces/export`). Because a honeypot gives sparse, diverse one-off
   attacks (no frequency support for contrast mining), the loop also runs **per-trace backbone
   discovery** (`autogen.backbone_rules`): each attack's *rare-hook* backbone (unshare/mount/setns/
   ptrace/bpf/module/memfd/fsmount/…, plus an inet connect) becomes a candidate directly, gated
   against the benign baseline, admitted **shadow**. Proven live: a honeypot attack minted
   `auto-unshare-mount-bpf` (observe), pushed via F7 and hot-swapped into the agent. A full-syscall
   *benign* baseline (honeypot running benign commands) would sharpen it further; the agent-side
   kernel "learn mode" stays deferred (verifier/perf) since the honeypot already covers discovery.

Distribution, the scheduled mining service (CronJob) and the auto-promote telemetry are implemented
and tested (`compiler/ariguard_compiler/loop.py`, `deploy/helm/.../rulegen-cronjob.yaml`,
`console/backend/ingest/{policy,export}.go`,
`agent/internal/policysync`); full-syscall capture for novel-chain discovery is the one remaining
piece, tracked as backlog F11.
