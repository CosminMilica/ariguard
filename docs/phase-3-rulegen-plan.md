# Phase 3 — Automated rule generation + validation pipeline (A3 + A4 + behavioral gate)

Status: implemented (control-plane fleet distribution, wave 5, still deferred). The Sigma
`temporal_ordered` → FSM compiler (`sigma.py`, multi-selection OR), the MITRE ATT&CK ingester
(`ingest_attack.py` → `compiler/techniques/attack-linux.yml`), A4 validation (`validate.py`) and
the behavioral gate are in place; the committed rule library is now 7 kill-chains (container-escape,
reverse-shell, fileless-exec native + bpf-tampering, cred-access-exfil, kernel-module-load,
ptrace-injection generated). Goal: stop hand-writing rules. Generate kill-chain rules from threat
intelligence (ATT&CK/Sigma, NL descriptions) with an LLM, and **trust nothing until it is
validated** — structurally and behaviorally. The output is a committed, validated rule
library; the generator runs offline, CI/kernel only re-verify the committed artifacts.

## The pipeline
```
  technique spec (ATT&CK id + NL description + hooks)
        │
        ▼  A3 generator (LLM, offline, author-time)
        │     emits: Sigma temporal_ordered rule  +  attack driver  +  benign twin
        ▼
  compile_sigma (existing)  ──►  bundle v3
        │
        ▼  A4 validation (deterministic, no LLM)
        │     structural (schema) + round-trip + kernel limits (≤16 rules, ≤1024
        │     transitions, ≤8 bindings/hook, pattern ≤63B, known hooks only)
        ▼
  behavioral gate (in-kernel harness)
        │     run attack driver → rule MUST reach terminal
        │     run benign twin   → rule MUST stay normal (no false positive)
        ▼
  promote → compiler/rules/sigma/generated/<name>.yml   (committed)
        │
        ▼  (later) control plane B7 → dynamic push to the fleet
```
An LLM hallucination that is malformed, oversized, misses the attack, or fires on the benign
is **rejected** — only rules passing A4 **and** both behavioral checks enter the library.

## The LLM step: co-author, no API key
The generator does not call a hosted model. The LLM step is **Claude Code acting as the
co-author in-session** (human-in-the-loop, "LLM-assisted compilation"): it reads the technique
catalog and writes the Sigma rule + drivers for each entry. The output is **committed**, so the
artifact is deterministic and reproducible; CI never invokes an LLM. A hosted-API backend
(`llm.py`) is an optional later upgrade, not required to run the pipeline.

## Wave 0 — MITRE ingestion (where techniques come from)
The user does not pick techniques by hand — MITRE does. An ingester fetches the ATT&CK
knowledge base and emits a catalog that drives generation:
```
  MITRE ATT&CK (STIX 2.1 JSON, pinned/vendored; or TAXII) 
     │  ingest_attack.py: platform = Linux/Containers; scan name+description+detection
     │  for hook-relevant signals; keep techniques that map onto our 16 hooks
     ▼
  compiler/techniques/attack-linux.yml   (id, name, description, tactics, candidate_hooks)
```
ATT&CK gives descriptions + detection prose + data sources, **not** syscall FSM chains — so the
catalog is the *input to the co-author step*, not the rule itself. Atomic Red Team (mapped to
ATT&CK) supplies real attack procedures to reuse as behavioral-gate attack drivers.

## How we run it (two clearly-separated modes)
**Author-time (generation — needs an LLM, run by a human, not in CI):**
- `make generate TECHNIQUES=compiler/techniques/<catalog>.yml` → for each technique the LLM
  produces a Sigma rule + a minimal attack driver + a benign twin, then runs A4 and the
  behavioral gate (in the dev VM / kernel). Passing rules are written to
  `rules/sigma/generated/` and the drivers to `testdata/generated/`. A human reviews and
  **commits** them. The LLM prompt, model id and few-shot examples are recorded for
  reproducibility; the committed rule is the deterministic artifact.
- Auto-repair loop: if A4 rejects, the validation error is fed back to the LLM and it retries
  up to N times before the technique is skipped (reported, never silently dropped).

**CI-time (validation — deterministic, no LLM, every PR):**
- `ci-compiler` (A4) compiles the committed generated rules and asserts they load.
- The behavioral gate re-runs the committed attack/benign drivers in the kernel matrix / e2e,
  so the committed library is continuously re-verified without regenerating.

This split is the point: **LLM generates offline → artifacts committed → CI/kernel validate
the artifacts.** No LLM dependency or non-determinism in CI.

## Tested + reproducible guarantee (non-negotiable)
Every generated rule ships **with its own committed test**: a Sigma rule +
`attack`/`benign` drivers + the expected outcome, all in git. The behavioral gate re-runs
these drivers **in CI** on every PR, so each rule is continuously proven to (a) detect its
attack and (b) not fire on its benign twin. Generation is offline and the artifacts are
committed, so results are fully reproducible and CI never calls an LLM. A rule with no passing
committed test never enters the library.

## Components / files
```
compiler/ariguard_compiler/
  generate.py     # A3: technique spec -> LLM -> Sigma + drivers; auto-repair; pluggable backend
  llm.py          # LLM client interface; Anthropic backend + a replay/offline backend for CI/tests
  validate.py     # A4: round-trip + limits checks reused by generate and ci-compiler
compiler/techniques/            # input catalogs (ATT&CK id + NL + candidate hooks)
compiler/rules/sigma/generated/ # committed, validated generated rules
testdata/generated/             # committed attack driver + benign twin per generated rule
testdata/scripts/behavioral-gate.* # runs drivers in-kernel, asserts detect-attack + no-FP
```

## Waves
1. **A4 validation** (`validate.py`) — pure, deterministic, reused everywhere; unit tests.
2. **Generator scaffold** (`generate.py` + `llm.py`) — prompt (few-shot from our 3 Sigma
   rules), strict-subset output, auto-repair loop; Anthropic backend + replay backend so
   tests/CI run without a live LLM.
3. **Behavioral gate** — driver format (attack + benign), a runner on the kernel harness,
   promote-on-pass; a committed example proving detect-attack + no-FP.
4. **First real batch** — generate + validate rules for ~5-8 ATT&CK techniques (kernel module
   load, ptrace injection, bpf tampering, cred access, cron persistence, …); commit the library.
5. **(later)** wire the library into control plane B7 for dynamic fleet distribution.

## Risks / honesty
- LLM output must match our exact Sigma subset → enforced by few-shot + A4 rejection +
  auto-repair; never trust raw output.
- A valid rule can still be over-broad (false positives in the wild). The benign twin reduces
  but does not eliminate this; mitigate by requiring path/arg predicates and testing several
  benign twins per rule. Documented, not hidden.
- Kernel caps: ≤16 rules per loaded policy. Generation builds a **library**; a deployment
  selects a profile of ≤16; the control plane distributes it.
- Reproducibility: generation is offline and the artifact is committed; CI never calls an LLM.
