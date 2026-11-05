# Honeypot — autonomous rule discovery (F11)

A deliberately-vulnerable decoy that turns real attacks into new detection rules, with no LLM and no
kernel change. It closes the loop the audit stream can't: the agent only emits *rule-matched* events,
so it can confirm existing rules but not discover new chains. The honeypot captures the **full**
syscall sequence of an attack instead.

```
attacker ──► honeypot (/exec runs the command under strace)
                 │  writes st.<pid> per process to a shared volume
                 ▼
          capture sidecar  (ariguard-trace-capture)
                 │  parses strace → attack-labeled traces → POST /api/v1/traces
                 ▼
             console  (honeypot_traces)
                 │  GET /api/v1/traces/export
                 ▼
          rulegen CronJob (ariguard-rulegen-loop --console …)
                 │  mines novel chains vs the benign baseline, gates them,
                 │  adds them SHADOW, pushes the bundle (F7)
                 ▼
             agents hot-swap → the new rule runs observe-only until telemetry promotes it
```

Only an attacker touches a honeypot, so every command it runs is attack behavior by definition — a
free, continuous stream of real, current attack traces.

## Run (isolated cluster only)

```sh
# in the VM
make honeypot-image rulegen-image
kind load docker-image ariguard-honeypot:dev --name <cluster>
kind load docker-image ariguard-rulegen:dev  --name <cluster>
kubectl apply -f tests/honeypot/honeypot.yaml

# attack it (command injection by design)
kubectl -n ariguard-honeypot port-forward svc/honeypot 8081:80 &
curl --get --data-urlencode 'cmd=unshare -Urm; mount -t proc none /mnt; /bin/sh -c id' http://127.0.0.1:8081/exec

# the capture sidecar posts traces; the rulegen CronJob (or a manual run) mines them
kubectl -n ariguard-system create job rulegen-now --from=cronjob/ariguard-rulegen
kubectl -n ariguard-system logs job/rulegen-now
```

A mined chain only lands if it fits the per-hook binding budget (busy hooks can be full); it enters
`shadow` (observe) and is promoted to enforce only after it proves itself on real traffic.

## Safety

`SYS_PTRACE` + command injection by design. Authorized security research on our own tool, on an
isolated cluster. Never expose it outside. Cleanup: `kubectl delete ns ariguard-honeypot`.
