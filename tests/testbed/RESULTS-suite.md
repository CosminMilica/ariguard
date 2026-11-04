# Efficacy suite — results

Run 2026-11-04T15:11:42+00:00 against a running enforce+sink agent.
Mitigation is synchronous (the terminal syscall is killed in-kernel); per-event latency is
measured separately by `ariguard-bench`, not here.

## Detections

| pod | rule | max state | outcome | steps |
|---|---|---|---|---|
| revshell-target-7464c8c9fb-n7zkl | reverse-shell | compromised | killed | 6 |
| vuln-root-ddf8df988-r9x96 | container-escape | compromised | killed | 4 |

## Observed lateral edges (F2)

| source | destination | cross-ns | ports |
|---|---|---|---|
| ariguard-testbed/frontend-55756dd759-kpphv | ariguard-internal/backend-7f5476bbf9-wdvgh | True | [8080] |
| ariguard-testbed/revshell-target-7464c8c9fb-n7zkl | ariguard-testbed/attacker-listener-5f65ffb4fc-jjh95 | False | [4444] |
| ariguard-internal/backend-7f5476bbf9-wdvgh | ariguard-internal/db-5b49f87d4f-5kkwp | False | [5432] |

## False-positive check (benign twins)

**PASS** — no benign twin raised an incident.

