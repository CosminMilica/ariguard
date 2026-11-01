# AriGuard Console — design

A lightweight web console to watch AriGuard with **real data** while running
locally or in CI: workloads and their FSM state, the attack chains as they
unfold, mitigations (kills), events, rules and agent health.

Not a mockup — every feature in the dashboard is backed by live agent data.

## Data flow

```
AriGuard agent ──push register (startup/reload)──┐
   (--sink-url) ──push audit batch (on events)───┤
                                                  ▼
                                        console backend (Go)
   agent /metrics  ◄───scrape every ~3s──────────┤   └─ write ─► SQLite (file)
   (counters + per-workload gauges)               │                 ▲
                                                   │   GET /api/*    │
frontend (Vue) ──poll 2-3s, ?range=15m|1h|24h──────┴─────────────────┘
```

Transport: **push** for audit + register (captures SIGHUP reloads promptly),
**scrape** for `/metrics` (counters and the per-workload state gauges).

## Every dashboard feature → its real source

| Feature | Source |
|---|---|
| KPI Workloads, FSM state breakdown | scrape `ariguard_workload_state{pod,ns,node,comm,rule}` |
| KPI Events/sec, "Syscall events" chart | scrape `ariguard_events_total` → timeseries → rate |
| KPI Mitigations, kills timeline | scrape `ariguard_kills_total` |
| KPI Audit dropped | scrape `ariguard_audit_dropped_total` |
| KPI Rules, Rules page (scope/states/window/terminal/hits) | register (bundle) + hits from audit |
| KPI Agents, Nodes page (kernel/hooks/insns/status) | register + heartbeat freshness |
| Workloads table (pod/ns/node/comm/rule/state/action) | scrape workload gauges + last action from audit |
| Events feed, Attack chain per pod | push audit (rule/state/syscall/comm/enforced/ts) |
| Severity timeline | audit bucketed by severity over time |
| Settings (metrics addr, bundle, ring buffer, kernel, enforce) | register |
| Triage queue, Campaigns, Containment | `/api/triage`, `/api/campaigns`, `/api/containment` over audit |
| Timeline page | audit over time |
| Coverage page | `/api/coverage` (rules × audit) |
| Performance page | agent `ariguard_program_run_time_ns_total` / `ariguard_program_runs_total` / `ariguard_bpf_map_bytes` + events/sec |
| Per-incident Export | `/api/export` |
| Rule detail: FSM diagram, syscall + predicate per transition, enforcement mix | register bundle (per-rule transition table + actions) |
| Analysis: attack chain (comm/pid/hook) + Process Tree | push audit (`ppid`) |
| Container image / digest per event | push audit (podmeta image / image_id) |
| Filters / search / row menu / time-range / nav | frontend over the API |

Settings **Enforce/Detect toggle is read-only** (reflects register); live
control (backend→agent) is a later, separate addition.

## Agent additions (small)

1. `--sink-url`: push **register** at startup + on SIGHUP (node, kernel, hooks,
   enforce, ring bytes, `bundle{rules[]}`), doubling as the "agent up" signal.
2. Push **audit** batches (`audit.Event` + node + ts) to the sink.
3. Expose a per-workload gauge in `/metrics` from `AG_PODS`+`AG_STATE`+podmeta
   so scrape yields the full workload table (including `normal` pods).

## Backend (Go + SQLite, no cgo)

Ingest: `POST /api/v1/register`, `POST /api/v1/audit`.
Scraper: polls each agent's `/metrics` every ~3s.
Read API (all accept `?range=15m|1h|24h`): `/api/overview`, `/api/workloads`,
`/api/events` (also `?rule=&namespace=&node=` filters), `/api/rules`,
`/api/nodes`, `/api/settings`, `/api/chain?pod=`, `/api/triage`,
`/api/campaigns`, `/api/containment`, `/api/coverage`, `/api/export`.

SQLite tables: `nodes`, `rules`, `audit_events`, `metric_samples`,
`workloads`, `mutes`.

## File tree

```
console/
  DESIGN.md
  docker-compose.yml          # backend + frontend, one `up`
  backend/
    main.go                   # http server: ingest + scraper + api
    store/ (sqlite.go, schema.sql)
    api/   (overview.go, workloads.go, events.go, rules.go, nodes.go, chain.go)
    ingest/(register.go, audit.go)
    scrape/(scraper.go, prom.go)
  frontend/
    index.html, vite.config.ts, package.json
    src/ (App.vue, api.ts, pages/{Overview,Triage,Campaigns,Workloads,Events,Timeline,Coverage,Performance,Rules,Nodes,Settings}.vue,
          components/{Sidebar,Topbar,StatTiles,Chart,Table,Chip,RowMenu,Chain,Feed}.vue)
```

Scaffold backend + frontend from Forge templates, then trim.

## Implementation waves (small agents)

1. Agent: `--sink-url` + register + audit push + workload gauge in `/metrics`.
2. Backend: schema + ingest + scraper + API.
3. Frontend: full Vue port of the design, wired to the API, live polling.
4. Glue: `docker-compose.yml` + `make console-up`; e2e may run with `--sink-url`
   so real data appears during tests.

## Cost

SQLite file (no DB server), one Go binary, a static Vue build. Runs with a
single `docker compose up` (or two local processes). No broker, no Postgres.
