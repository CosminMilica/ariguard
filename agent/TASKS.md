# agent — Tasks

Node data-plane manager (Go / cilium/ebpf). See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 0 — Spike
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` AGT-0.1 | Load the Rust-built BPF object via `cilium/ebpf` | BPF-0.1 | object loads without ABI errors |
| `[x]` AGT-0.2 | Attach the kprobe and read one map value | AGT-0.1, BPF-0.2 | value round-trips kernel→user |
| `[x]` AGT-0.3 | Decide binding strategy (bpf2go vs BTF-generated structs) | AGT-0.2 | documented decision + working bindings |

AGT-0.1/0.2: verified in the VM; `sw_execve` attached, audit records stream as JSON; no loader changes needed.
AGT-0.3: hand-mirrored structs in `pkg/fsm` with size/offset tests, no bpf2go (the object is Rust).
cilium/ebpf checks every Put against the map's value size, and the BTF maps carry the Rust types
(`bpftool map dump` pretty-prints them).

## Phase 1 — Load, maps, telemetry
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` AGT-1.1 | Load all programs + maps, attach per the active policy | AGT-0.3, BPF-1.4 | all hooks attached at startup |
| `[x]` AGT-1.2 | Ring buffer reader → structured audit events | BPF-1.6 | events parsed into Go structs |
| `[x]` AGT-1.3 | Populate `AG_TRANSITIONS`, `AG_BINDINGS`, `AG_DIMS` from a policy bundle v2 | PKG-1.4, BPF-1.2 | policy active in the kernel |
| `[x]` AGT-1.4 | Hot-swap the policy without reloading programs (write `AG_DIMS` last) | AGT-1.3 | new policy active, no detach |
| `[ ]` AGT-1.5 | Resolve `cgroup_id` → pod metadata — moved to `AGT-1.5.4` | AGT-1.2 | audit events carry pod name/ns |
| `[x]` AGT-1.6 | Dev mode: plain binary on the VM, `--object`, `--bundle`, JSON audit to stdout (D7) | AGT-1.1 | `sudo ariguard-agent --bundle …` streams audit |

AGT-1.1–1.4, AGT-1.6: verified in the VM; all six hooks attach, SIGHUP hot swap keeps detection working, EVAL-1.3 passes. No agent changes needed.

## Phase 1.5 — Generic engine
Contract: [docs/architecture.md](../docs/architecture.md#phase-15-decisions).

| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` AGT-1.5.1 | Loader v3: 16 hooks, `AG_POLICY`/`AG_RULES`; a hook whose tracepoint is missing is skipped with a warning (E14) | BPF-1.5.3 | agent starts on arm64; `dup2` skipped with a warning, all other hooks attach |
| `[x]` AGT-1.5.2 | Policy apply v3 with the hot-swap order `POLICY=0 → RULES → TRANSITIONS → BINDINGS → POLICY` | PKG-1.5.2 | SIGHUP reload keeps detection (integration "hot swap" subtest) |
| `[x]` AGT-1.5.3 | Audit v3: 64-byte record, `comm`, rule/state/event names from the bundle metadata | PKG-1.5.2 | JSON lines name the rule/states and carry `comm` (`python3`, `coredns`, …) |
| `[x]` AGT-1.5.4 | Pod resolution: cgroup id → cgroup path → container id → namespace/pod/container via the Kubernetes API, cached (E12) | AGT-1.5.3 | audit lines on kind carry the pod name; all four attackers resolve in the exit check |
| `[x]` AGT-1.5.5 | Port the CI tests to v3: `loader/object_test.go`, `integration/chain_test.go` | AGT-1.5.1, AGT-1.5.2 | both pass against the v3 object on 6.8 and on the 5.15/stable matrix |

AGT-1.5.1–1.5.5: runtime-verified in the VM (Wave C/D). Pod resolution (AGT-1.5.4) needs the
workload's cgroup to be registered before its chain fires and to persist until the record is
drained — short-lived emitters must warm up and stay alive (see testdata attack manifests).

## Phase 2 — Mitigation surface (branch `feat/mitigation`)
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` AGT-2.1 | Populate `AG_PODS` from `podmeta` (add pod cgroups, prune on deletion) | BPF-2.1 | only pod cgroups are enforcement candidates; verified by ci-e2e (attackers killed, non-pod runtime not) |
| `[x]` AGT-2.2 | Read `AG_METRICS`, expose Prometheus (events, kills, audit_dropped) | BPF-2.6 | metrics scrapeable on an HTTP endpoint; verified by ci-e2e (`ariguard_kills_total` 0 in detect, +4 in enforce) |
| `[x]` AGT-2.3 | `--enforce` flag → `Policy.enforce`; health/readiness; graceful detach | BPF-2.4 | dry-run vs enforce switch; verified by ci-e2e/ci-kernel (`AG_POLICY.enforce` flips, clean teardown, no leaked sw_ programs) |

Note: AGT-2.1/2.2/2.3 code complete (podsync, metrics, `--enforce`, `--metrics-addr`); runtime verification in the VM.

## Phase 3 — Fleet
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` AGT-3.1 | gRPC client: receive `PushPolicy`, stream audit upstream | PROTO-3.1, CP-3.4 | policies arrive from control plane |

## Phase 4 — Evaluation support
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` AGT-4.1 | pprof / overhead instrumentation for benchmarks | AGT-1.1 | CPU/mem profiles collectable |
