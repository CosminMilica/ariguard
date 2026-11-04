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

## What the live loop still needs

The engine above runs offline on a trace corpus. Running it continuously against the real fleet
needs the deployment layer, largely **backlog F7 (control plane / CRD)**:

1. **Trace capture** — an agent "learn mode" (or an offline tracer on canary namespaces) shipping
   full syscall-hook traces: benign from normal workloads, attack from honeypots.
2. **A mining service** — a scheduled job running `autogenerate` / `feeds.ingest_dir` over the
   rolling corpus.
3. **Live distribution (F7)** — push accepted shadow rules to the fleet without rebuilding the
   agent image (CRD / gRPC `PushPolicy`).
4. **Shadow telemetry + auto-promote** — the console records per-rule hits/false-positives and
   drives `decide_mode` to promote or retire.

These are deployment/control-plane work (they need the fleet and F7), tracked separately; the
decision logic they call — mining, gating, baseline, promotion — is implemented and tested here.
