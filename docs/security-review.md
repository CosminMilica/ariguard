# AriGuard security & correctness review

Findings from a multi-dimension audit (eBPF dataplane, Go agent, console backend, Python rulegen, and
a cross-cutting security pass), 2026-11-07. Ranked by severity. Each row: the defect, where it lives,
and the fix direction. Status: **fixed** (this branch), **deferred** (follow-up), or **doc** (an
inherent threat-model limitation to record in the dissertation rather than "fix").

## Root causes
Three structural issues explain most of the findings:
- **A — the control-plane *write* surface is unauthenticated**, and the same resource is mirrored across
  trust tiers (agents read the token-gated `/api/v1/*`, but the writes that drive them are on the open
  `/api/*`).
- **B — no cryptographic trust** where it is needed: policy bundle, community feeds, trace labels and the
  benign baseline are all "whatever the console/agent sent".
- **C — enforcement-critical mechanisms on fragile foundations**: `sys_enter` tracepoints (not LSM),
  LRU maps (self-evictable), poll-based cgroup tracking (race window), fail-open policy swap.

## Tier 1 — Critical

| # | Finding | Where | Fix | Status |
|---|---------|-------|-----|--------|
| C1 | Enforcement-disabling writes are unauthenticated: `POST /api/mode`, `POST/DELETE /api/mutes`, `/api/observe-namespaces`, `/api/learn-namespaces` are on the open `/api/*` surface, not behind the token. Any in-cluster pod turns the fleet to detect-only; CORS `*` makes it drive-by. | `console/backend/ingest/auth.go:12`, `console/backend/api/api.go:40-50` | Require the token on the control-plane *write* methods; frontend sends it. | **fixed** |
| C2 | Policy bundle is unsigned; agent loads whatever the console serves. Default token is `""`, so `PUT /api/v1/policy` is open out of the box. | `agent/internal/policy/policy.go:34`, `console/backend/ingest/policy.go`, `deploy/helm/ariguard/values.yaml:12` | Sign bundles at rulegen (ed25519), verify in the agent; make the push token mandatory. | **in progress** — Phase 1: `pkg/fsm` ed25519 sign/verify, `ariguard-ctl keygen/sign/push`, console stores+serves a detached `X-Policy-Signature`. Phase 2 (done): agent `--policy-pubkey`; control-plane bundles verified in `sink.Policy` and the `--bundle` file (+ `.sig` sidecar, verify-if-present) at startup/SIGHUP, fail-closed. Phase 3 (done): Helm wires the public key (`agent.policySigning.publicKey` → ConfigMap → `--policy-pubkey`); ops guide in `docs/policy-signing.md`. **Remaining**: rulegen CronJob auto-sign (needs `ariguard-ctl` in the rulegen image) + anti-rollback monotonic version |
| C3 | Failed policy hot-swap zeroes `AG_POLICY` and leaves it zeroed on error → fail-open (no detection, no enforcement) until the next successful swap. | `agent/internal/policy/policy.go:42-64`, callers in `agent/cmd/ariguard-agent/main_linux.go` | On Apply error, roll back to the last known-good bundle. | **fixed** |
| C4 | Self-mute = kill + quarantine bypass + auto-release of an active quarantine; mutes keyed by bare pod name (namespace-blind collisions). | `agent/cmd/ariguard-agent/main_linux.go:63-74`, `agent/internal/responder/responder.go`, `console/backend/store/schema.sql` (mutes) | Auth the write (C1 closes the attacker path); key mutes by `namespace/pod`; don't auto-release on mute. | **fixed** — mutes keyed by `namespace/pod` end to end (console API + telemetry/workloads/overview/autonomy joins, agent responder + kill-gate, frontend). Auth is already C1. Auto-release on mute is **kept by design**: it is the operator's release path (the UI "Release" button mutes), and C1 already blocks the self-mute abuse; a separate explicit-release action is a possible future split |
| C5 | Rulegen gate `simulate` advances multiple FSM states on one syscall; the kernel applies exactly one event per rule per syscall → certifies rules that miss in prod / rejects good ones. | `compiler/ariguard_compiler/mine.py:271-292` | One transition per rule per syscall (first matching event wins), matching the kernel. | **fixed** |
| C6 | Community-feed rules bypass shadow mode and ship as enforcing `kill` on first match, while the UI shows "shadow". | `compiler/ariguard_compiler/loop.py:217-223`, `sigma.py:137` | Force feed rules shadow-first; enforce only when telemetry promotes. | **fixed** |
| C7 | `pull_traces` defaults label-less records to ATTACK (incl. dict rows, not just bare lists) → destroys the benign baseline; normal chains get promoted to kill. | `compiler/ariguard_compiler/loop.py:68-82`, `trace.py:88` | Console-pulled traces must carry explicit labels; don't force ATTACK. | **fixed** |

## Tier 2 — High (detection evasion / fail-dangerous)

| # | Finding | Where | Fix | Status |
|---|---------|-------|-----|--------|
| H1 | LRU eviction of `AG_STATE`/`AG_DENY`: attacker floods with benign PIDs/syscalls to evict mid-chain state → slow chains never reach terminal (silent FN, no metric). | `bpf/ariguard-ebpf/src/main.rs:80,116` | Non-evicting hash for enforcement-critical maps; emit an insert-full metric. | deferred / doc |
| H2 | DENY is a no-op on every hook except mount/move_mount (no LSM consumer) → silent detect-only, `enforced=0`. | `bpf/ariguard-ebpf/src/main.rs:517-529` | Validate at policy-load that a DENY event is raised by at least one LSM-backed hook (reject a fully-dead deny). Adding LSM hooks / deny→kill fallback deferred. | **fixed** (validation) |
| H3 | Empty/absent benign baseline silently disables all suppression (support 0 → everything passes). | `compiler/ariguard_compiler/mine.py:98-101`, `autogen.py:50-54` | Refuse to mine (loud warning, no candidates) when there is attack traffic but no benign baseline. | **fixed** |
| H4 | Pod-creation → cgroup-tracking race (≤2s): no kill, and the audit event is dropped (`IsPod` false). | `agent/internal/podmeta/podmeta.go:159`, `agent/internal/audit/ringbuf/stream_linux.go:51` | Drive cgroup tracking from a creation event; don't drop unclassified non-root cgroups. | **partial** — IsPod now re-walks on a cache miss (rate-limited), shrinking the new-pod window from ~2s to ~250ms. Full creation-event (fanotify/cgroup_mkdir) tracking deferred |
| H5 | Narrow syscall coverage + spoofable matching: only `openat` (not `open`/`openat2`/`creat`); no `rename/unlink/chmod/symlink`; path prefix on un-canonicalized string; IPv6 egress invisible; kill is post-hoc. | `bpf/ariguard-ebpf/src/main.rs` (hooks, `read_connect_dst`, path match) | LSM-layer matching; parse AF_INET6; route open-family into one hook; add file-mutation hooks. | doc (threat-model) + deferred |
| H6 | Learn-mode drain blocks on synchronous HTTP POST → `AG_LEARN` fills, kernel drops records. | `agent/internal/learn/learnring/drain_linux.go:44`, `learn.go:135` | Shipping moved to a dedicated goroutine behind a buffered channel; the ring drainer (Add) never blocks on HTTP and drops batches when the buffer is full. | **fixed** |
| H7 | Mutes/observe not honored when pod metadata is unavailable (nil client / API down) → muted pod is still killed (fail-dangerous). | `agent/cmd/ariguard-agent/main_linux.go:63-74`, `podmeta.go:115` | When mutes/observe are in use, a cgroup whose pod identity cannot be resolved is excluded from the kill-gate (fail-closed). | **fixed** |
| H8 | A single attacker-triggerable "benign fire" retires a rule fleet-wide; retired rules are re-mined → oscillation. | `compiler/ariguard_compiler/autogen.py:126`, `loop.py:186-236` | Require N>1 benign fires from distinct sources (needs source-tracked telemetry); persist a retired-chain denylist. `decide_mode` already exposes `max_benign_fires` for tuning. | deferred (telemetry schema) |

## Tier 3 — Medium

| # | Finding | Where | Status |
|---|---------|-------|--------|
| M1 | Console DoS: single SQLite connection + queries with no `LIMIT`/span cap (`/api/actors?from=0&to=…`, `/api/export`); no HTTP server timeouts (Slowloris); unbounded result sets → OOM. | `console/backend/store/sqlite.go:43`, `api/api.go:88`, `api/export.go:85`, `main.go:81` | **fixed** (31-day span cap, `LIMIT 50000` on per-event queries, HTTP read/write/idle timeouts; single-conn kept) |
| M2 | `advance` is `#[inline(always)]` inside the 14× binding loop, inlined into all 16 programs → real 5.15 verifier-ceiling risk. Make it a bpf-to-bpf subprogram. | `bpf/ariguard-ebpf/src/main.rs:436` | deferred (verifier-matrix) |
| M3 | `simulate` window = total chain duration; kernel = inter-step gap. Plus honeypot/strace traces carry `ts_ns=0`, so the window is never validated by the gate. | `compiler/ariguard_compiler/mine.py:281`, `strace.py:69` | **fixed** (per-step sliding window matching the kernel) |
| M4 | Promotion unsatisfiable at default `min_hits=1` (`days_observed` derived from the hit span → 0 on one hit); `min_days`/`min_hits` silently coupled. | `compiler/ariguard_compiler/loop.py:96-103` | **fixed** (shadow age = `first_seen → now`) |
| M5 | Unauthenticated read API leaks the rules, coverage and per-pod attack chains → an attacker maps detection coverage and crafts a bypass. | `console/backend/api/api.go:19-39` | deferred (read-API auth = UX change) |
| M6 | Privileged agent + cluster-wide `pods: delete/patch` RBAC → large blast radius on agent compromise. | `deploy/helm/ariguard/templates/agent-rbac.yaml:16`, `agent-daemonset.yaml:81` | **fixed** — RBAC scoped per mode: detect-only gets no `pods:delete`/`networkpolicies:create`; destructive verbs gated on `isolate`/`isolateFallback`. `docs/agent-rbac.md` |
| M7 | An audit-file write error tears down the whole agent; a metrics-endpoint error calls `stop()`. | `agent/cmd/ariguard-agent/main_linux.go:210,378`, `audit/ringbuf/stream_linux.go:82` | **fixed** (both non-fatal: log + continue) |
| M8 | Learn-trace mislabel under churn: `markThreat` runs host-wide into a FIFO `ThreatSet(8192)`; non-learn marks evict learn-cgroup marks → trace mislabeled benign. | `agent/internal/audit/ringbuf/stream_linux.go:79`, `learn/threat.go` | **fixed** (refresh-on-mark LRU) |
| M9 | `_drop_subsumed` keeps the longer superset chain and drops the shorter, more-general discriminator → attacker doing just the prefix evades. | `compiler/ariguard_compiler/mine.py:188-198` | deferred (precision/recall trade-off: the shorter discriminator raises false-positive risk, regressing the "no-FP under load" property; keeping the specific longer chain is the safer default) |
| M10 | Non-observe audit events are never coalesced; a kill/deny retry loop floods and drop-oldest loses distinct events. | `agent/internal/sink/sink.go:411` | **fixed** (coalesce repeated identical non-observe events; distinct events keyed by action never merge) |

## Tier 4 — Low / informational / doc drift
Fixed in this branch:
- Stale comments: `Binding` "104 bytes" → 72, `MaxBindingsPerHook` "8->16" → 14. `abi.go`, `emit.py`, `lib.rs`.
- `AG_PODS` bare literal `16384` → `MAX_TRACKED_WORKLOADS`. `main.rs`.
- `GROUP_CONCAT` split naive on `,` → `char(31)` separator + Go-side dedupe. `api/campaigns.go`, `actors.go`.
- LIKE metacharacters escaped (`ESCAPE '\'`). `api/api.go` `like()`, `events.go`, `workloads.go`.
- `Content-Disposition` filename sanitized. `api/export.go`.
- `toNS` int64 overflow — resolved by the M1 span cap. `api/api.go`.
- `X-Traces-Accepted` counts actual newly-inserted rows. `ingest/traces.go`.
- Scraper prune honors `--retention` (26h floor) and logs its error. `scrape/scraper.go`, `main.go`.
- `GetPolicy` distinguishes `sql.ErrNoRows` (204) from a real DB error (500). `ingest/policy.go`.
- Internal error text no longer leaked; `fail()`/ingest `serverError` log the detail, return a generic 500. `api/api.go`, `ingest/*`.
- `commcache` O(n) eviction → O(1) ring index. `agent/internal/audit/commcache.go`.
- Rule-name truncation collisions → hash suffix (`chain_name`). `mine.py`, `autogen.py`.
- `--dry-run` no longer performs the honeypot network pull. `loop.py`.

Deferred (eBPF behavior/ABI — each needs verifier-matrix validation):
- `stash_argv` argc holes mis-assemble argv. `main.rs:740`.
- tgid-reuse stale FSM state (no clear on `sched_process_exit`). `main.rs:463`.
- Root-cgroup skip assumes cgroup v2 id == 1 (silent-fail on v1/hybrid). `main.rs:34`.
- `ACTION_THROTTLE` has no in-kernel effect. `main.rs:531`.
- `AG_LEARN` ring drops are silent (no metric). `main.rs:159`.
- Retention prunes the learn-mode benign baseline with everything else (needs a separate/longer learn retention). `store/retention.go:23`.

## Confirmed OK
ABI is consistent (no drift; `abi_test.go`/`btf_test.go` would catch a size change). No string-concatenated
SQL — all dynamic parts are constants, user values are bound parameters. Constant-time token compare.
No `pickle`/`eval`/`exec`/`subprocess` in the compiler; YAML `SafeLoader` + duplicate-key rejection;
rule-name validator blocks path traversal. `AG_DENY` has a 1s TTL; the kill path re-reads committed state
before signalling; `dup2`/`dup3`, `execve`/`execveat`, `init_module`/`finit_module` variant pairs are
covered.
