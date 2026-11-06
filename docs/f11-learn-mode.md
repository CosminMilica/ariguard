# F11 learn-mode — novel-chain discovery from production

Today the rulegen loop discovers chains from the honeypot (strace) and community feeds. **Learn-mode**
lets the agent emit full-syscall sequences from opt-in production namespaces, so the loop mines novel
kill-chains from real traffic and gates them against a *real* benign baseline (fewer false positives).
Reuses the existing trace pipeline: `/api/v1/traces` → `honeypot_traces` → `loop.pull_traces` →
`autogen.backbone_rules` / contrast mining.

## Key constraint

`handle()` is `#[inline(always)]`, so it is inlined into all 16 `sw_<hook>` programs, which sit at the
**5.15 verifier ceiling** (adding one string read to `sw_execve` for argv already tipped it). So the
learn emit must NOT touch `handle()` or the existing wrappers. Instead it runs as **dedicated `_learn`
programs — a second program on each `sys_enter_<hook>` tracepoint** (the same trick as argv), each tiny
(a cgroup-set gate + a ring write, no FSM), so it has its own budget.

Volume: production is noisy, so learn-mode is **opt-in per namespace** (default off = zero overhead and
no emit) and bounded; the emit is gated by `AG_LEARN_PODS` (empty by default).

## Flow

```
opt-in namespaces (console: learn_namespaces)
   │  agent resolves ns -> cgroups -> AG_LEARN_PODS (cgroup set)
   ▼
sw_<hook>_learn (16, one per tracepoint)  --emit LearnRecord{cgroup,tgid,hook,ts}--> AG_LEARN ring
   ▼
agent: drain ring -> assemble per-(cgroup,tgid) hook sequences over a window -> Trace
   │  label: benign (baseline) by default; attack if the pod also tripped a threat-state rule
   ▼  POST /api/v1/traces (source="learn")
console honeypot_traces  --GET /api/v1/traces/export-->  rulegen loop mines novel chains + real baseline
```

## Phases (each its own PR from main)

| Phase | Deliverable | Files |
|-------|-------------|-------|
| **1. eBPF emit** | `AG_LEARN` ring + `AG_LEARN_PODS` gate; 16 `sw_<hook>_learn` programs (macro-generated); `LearnRecord` ABI. **Validate it loads on the 5.15 verifier.** | `bpf/*`, `pkg/fsm` (ABI, abi/btf tests), `agent/internal/loader` (map names + attach) |
| **2. Agent assembly** | drain `AG_LEARN`, assemble per-(cgroup,tgid) sequences over a window into `Trace`s, label, POST `/api/v1/traces` (source="learn") | `agent/internal/learn/*` (new), `main_linux.go`, `sink` |
| **3. Control + safety** | `learn_namespaces` set (console endpoint + schema + UI); agent resolves → `AG_LEARN_PODS`; sampling / ring budget | `console/backend`, `Settings.vue`, agent poll |
| **4. Loop + console** | `source="learn"` handling + retention; loop mines (real baseline improves gating, attack chains feed discovery) | `ingest/traces.go`, `loop.py` (minor) |
| **5. Eval + docs** | end-to-end: a novel chain in a learn namespace is discovered; measure overhead (opt-in only) | `tests/testbed`, `bench`, this doc |

## Decisions (defaults chosen)

- Learn traces are **benign by default** (baseline); promoted to **attack** only if the pod reached a
  threat state — production is mostly benign.
- A **dedicated `learn_namespaces`** set (not reused `observe_namespaces`): different semantics.
- **Phased**, not one PR: Phase 1 carries the verifier risk and is validated on the kernel matrix first.
