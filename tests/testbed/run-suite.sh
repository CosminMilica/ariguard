#!/usr/bin/env bash
# Efficacy suite: run every real-attack scenario against a running enforce+sink agent, then read
# the console to build a detection/FP/time-to-mitigate table and assert the benign twins never
# fired. NOT a CI gate (real exploits); the deterministic gate stays the synthetic drivers.
#
# Prerequisite: the agent is deployed with --enforce and --sink-url (e.g. the isolate overlay with
# the sink patched in, or Helm agent.enforce+console). Writes RESULTS-suite.md.
#
#   KUBE_CONTEXT=kind-statewall-dev ./run-suite.sh
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
NS_SYS=ariguard-system
NS_TB=ariguard-testbed
NS_INT=ariguard-internal
LOCAL_PORT="${LOCAL_PORT:-8099}"
RESULTS="$HERE/RESULTS-suite.md"

kc() { if [ -n "$KUBE_CONTEXT" ]; then kubectl --context "$KUBE_CONTEXT" "$@"; else kubectl "$@"; fi; }
log() { echo "[suite] $*" >&2; }

# api <path>: query the console read API from inside the backend pod (no host port-forward needed).
api() {
  local be
  be="$(kc -n "$NS_SYS" get pod -o name | grep console-backend | head -1 | cut -d/ -f2)"
  kc -n "$NS_SYS" exec "$be" -- wget -qO- "http://localhost:8080$1"
}

podip() { kc -n "$1" get pod -l "app=$2" -o jsonpath='{.items[0].status.podIP}'; }

# forward <ns> <svc>: (re)start a port-forward to a target service on LOCAL_PORT.
forward() {
  local held; held="$(lsof -tiTCP:"$LOCAL_PORT" -sTCP:LISTEN 2>/dev/null || true)"
  [ -n "$held" ] && { kill $held 2>/dev/null || true; sleep 1; }
  kc -n "$1" port-forward "svc/$2" "$LOCAL_PORT:80" >/tmp/suite-pf.log 2>&1 &
  PF=$!
  sleep 5
  grep -q "Forwarding" /tmp/suite-pf.log || { echo "port-forward failed" >&2; return 1; }
}
unforward() { kill "$PF" 2>/dev/null || true; }

log "deploying targets and benign twins"
kc apply -f "$HERE/app/lateral.yaml" >/dev/null
kc apply -f "$HERE/app/reverse-shell.yaml" >/dev/null
kc apply -f "$HERE/app/vuln-root.yaml" >/dev/null
kc apply -f "$HERE/app/benign-twins.yaml" >/dev/null
kc -n "$NS_TB" rollout status deploy/frontend --timeout=120s
kc -n "$NS_TB" rollout status deploy/revshell-target --timeout=120s
kc -n "$NS_TB" rollout status deploy/vuln-root --timeout=120s
kc -n "$NS_INT" rollout status deploy/backend --timeout=120s
kc -n "$NS_INT" rollout status deploy/db --timeout=120s
kc -n "$NS_INT" rollout status deploy/benign-client --timeout=120s
kc -n "$NS_INT" rollout status deploy/benign-logproc --timeout=120s
log "letting the benign twins run a few cycles"
sleep 20

# container-escape (root)
log "scenario: container-escape (root)"
forward "$NS_TB" vuln-root
BASE="http://127.0.0.1:$LOCAL_PORT" bash "$HERE/exploit/escape-as-root.sh" >/dev/null 2>&1 || true
unforward

# reverse-shell
log "scenario: reverse-shell"
forward "$NS_TB" revshell-target
BASE="http://127.0.0.1:$LOCAL_PORT" LISTENER_IP="$(podip "$NS_TB" attacker-listener)" \
  bash "$HERE/exploit/reverse-shell.sh" >/dev/null 2>&1 || true
unforward

# lateral movement (F2)
log "scenario: lateral movement"
forward "$NS_TB" frontend
BASE="http://127.0.0.1:$LOCAL_PORT" BACKEND_IP="$(podip "$NS_INT" backend)" DB_IP="$(podip "$NS_INT" db)" \
  bash "$HERE/exploit/lateral.sh" >/dev/null 2>&1 || true
unforward

log "settling, then reading the console"
sleep 6
INCIDENTS="$(api '/api/incidents?range=15m')"
EDGES="$(api '/api/edges?range=15m')"

python3 - "$RESULTS" <<PY
import json, sys, datetime
incidents = json.loads('''$INCIDENTS''' or "[]")
edges = json.loads('''$EDGES''' or "[]")

rows = []
for i in incidents:
    rows.append((i.get("pod",""), i.get("rule",""), i.get("max_state",""), i.get("outcome",""), str(i.get("steps",""))))

benign = [r for r in rows if r[0].startswith("benign-")]
attacks = [r for r in rows if not r[0].startswith("benign-")]

out = []
out.append("# Efficacy suite — results\n")
out.append(f"Run {datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')} against a running enforce+sink agent.")
out.append("Mitigation is synchronous (the terminal syscall is killed in-kernel); per-event latency is")
out.append("measured separately by `ariguard-bench`, not here.\n")
out.append("## Detections\n")
out.append("| pod | rule | max state | outcome | steps |")
out.append("|---|---|---|---|---|")
for r in attacks:
    out.append("| " + " | ".join(r) + " |")
out.append("")
out.append("## Observed lateral edges (F2)\n")
out.append("| source | destination | cross-ns | ports |")
out.append("|---|---|---|---|")
for e in edges:
    out.append(f'| {e["src_namespace"]}/{e["src_pod"]} | {e["dst_namespace"]}/{e["dst_pod"]} | {e["cross_ns"]} | {e.get("ports",[])} |')
out.append("")
out.append("## False-positive check (benign twins)\n")
if benign:
    out.append("**FAIL** — benign workloads raised incidents:\n")
    for r in benign:
        out.append("- " + " / ".join(r))
else:
    out.append("**PASS** — no benign twin raised an incident.")
out.append("")
open(sys.argv[1], "w").write("\n".join(out) + "\n")

print("\n".join(out))
print()
print("SUITE:", "FP-FAIL" if benign else "ok", f"({len(attacks)} attack incidents, {len(edges)} edges)")
sys.exit(1 if benign else 0)
PY
