# AriGuard Console — improvement plan

Grounded in a live run against the real agent. Status: `[~]` in progress · `[ ]` todo · `[x]` done.

## P0 — signal vs noise + consistency (in progress)
- `[~]` Agent: stop flooding the sink with benign `observe` events (dedup/rate-limit per (cgroup,rule,state); non-observe always passes). The feed was 500 rows, all `observe` (web-client 415), burying real kills.
- `[~]` Backend: `Mitigations` KPI = enforced kills in the window (from audit) so KPI ≡ feed ≡ chain; keep cumulative `kills_total` separately. `kills_series` from audit, not the counter.
- `[~]` Backend: `/api/events?significant=1` (severity!='' or action!='observe') so the UI shows detections, not noise.
- `[x]` Backend DB persistent via PVC (local-path) — restart/redeploy no longer wipes history (the counter↔audit desync source).

## P1 — real-data fidelity + UX (timeline is here)
- `[~]` Grafana-style time brush: drag on the events / severity charts to select a window; all views filter to it; reset to preset. Backend accepts `?from=&to=`.
- `[ ]` Incidents view: one persistent card per detected attack — pod, rule, chain steps, outcome (killed/blocked), time, node. The durable "what happened" (also covers process-scoped attacks that never show in the cgroup Workloads gauge).
- `[ ]` "Inspect attack chain" opens a modal with the pod's full chain (and from an Events row), instead of navigating to Overview.
- `[ ]` Workloads: subtitle "live cgroup FSM state"; badge "recently compromised" from audit so process-scoped attackers are visible there too.
- `[ ]` Real `comm` from the last audit event per cgroup (today it is the container name).

## P2 — robustness / ops / tests
- `[ ]` Stable access: NodePort/Ingress or `make console-forward` (port-forward is fragile).
- `[ ]` Integration test: gauge + audit → API consistency (would have caught the `rule=""` drop); optional wire into e2e via `--sink-url`.
- `[ ]` Multi-node scrape/scale; mark stale agents.
- `[ ]` (optional) resource requests/limits on console pods.

## P3 — dissertation value
- `[ ]` Overhead/latency panel (events/sec, enforcement latency) for the evaluation chapter.
- `[ ]` Export incidents (CSV / screenshot / report).
- `[ ]` Comparison hooks (Falco/Tetragon).

## Known real-data facts (not bugs)
- `reverse-shell` / `fileless-exec` are process-scoped (state on the forked child, keyed by tgid); the per-cgroup Workloads gauge cannot show their compromised state — it lives in audit/Events. Workloads = live cgroup state; Events/Incidents = history.
- A benign `web-client` reaches the non-terminal `connected` state of `reverse-shell` and is correctly never killed (observe) — good teaching point, but it is the main noise source P0 addresses.
