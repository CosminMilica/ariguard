# AriGuard Console

A lightweight web console to watch AriGuard with **real data**: workloads and
their FSM state, attack chains as they unfold, mitigations (kills), events,
rules and agent health. See [DESIGN.md](DESIGN.md) for the full design.

Backend: Go + SQLite (pure-Go, no cgo). Frontend: Vue 3 + Vite. One small image.

## Run it

```sh
make console-up          # build + run at http://localhost:8080
make console-down        # stop
```

Or for development (two terminals):

```sh
make console-backend     # Go API on :8080
make console-frontend    # Vite dev server (proxies to :8080)
```

## Point an agent at it

The agent sends data when started with `--sink-url`:

```sh
# local binary
ariguard-agent --enforce --metrics-addr :9102 --sink-url http://localhost:8080

# in kind: set --sink-url to the console Service, e.g.
#   http://ariguard-console.ariguard-system.svc:8080
```

The agent then pushes `register` (node, kernel, rules, enforce) and `audit`
events; the backend also scrapes the agent's `/metrics` for the counters and
the per-workload state gauge. Open the console and watch it fill live.

## Layout

| Path | Purpose |
|---|---|
| `backend/` | Go API: ingest (`/api/v1/register`, `/api/v1/audit`), scraper, read API (`/api/*`), SQLite |
| `frontend/` | Vue dashboard (Overview, Workloads, Events, Rules, Nodes, Settings) |
| `Dockerfile` | multi-stage build → one image serving frontend + API |
| `docker-compose.yml` | one service, a volume for the SQLite file |
