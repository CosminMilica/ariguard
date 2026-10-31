#!/usr/bin/env bash
# Exit check (EVAL-1.3, EVAL-1.5.4, EVAL-2.3): run benign (incl. twins) + attack workloads under the agent, assert on the audit stream.
# STATEWALL_ENFORCE=1: agent runs with --enforce; attackers must be killed, benign pods untouched.
# Runs inside the Lima VM against the kind cluster; needs passwordless sudo.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATEWALL_AGENT="${STATEWALL_AGENT:-$REPO_ROOT/bin/statewall-agent}"
STATEWALL_OBJECT="${STATEWALL_OBJECT:-$REPO_ROOT/bpf/target/bpfel-unknown-none/release/statewall}"
STATEWALL_BUNDLE="${STATEWALL_BUNDLE:-$REPO_ROOT/testdata/golden/policy.bin}"
if [[ -n "${SUDO_USER:-}" ]]; then
    INVOKER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
    INVOKER_HOME="$HOME"
fi
STATEWALL_KUBECONFIG="${STATEWALL_KUBECONFIG:-$INVOKER_HOME/.kube/config}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-statewall-dev}"
NAMESPACE="statewall-eval"
BENIGN_SECONDS="${BENIGN_SECONDS:-30}"
ATTACK_SECONDS="${ATTACK_SECONDS:-15}"
READY_TIMEOUT="${READY_TIMEOUT:-300s}"
STATEWALL_ENFORCE="${STATEWALL_ENFORCE:-0}"
AGENT_MODE_ARGS=()
CHECKER_MODE_ARGS=()
if [[ "$STATEWALL_ENFORCE" == "1" ]]; then
    AGENT_MODE_ARGS=(--enforce)
    CHECKER_MODE_ARGS=(--enforce)
fi

WORKLOADS="$REPO_ROOT/testdata/workloads"
CHECKER="$REPO_ROOT/testdata/scripts/check_audit.py"
WORKDIR="$(mktemp -d -t statewall-exit-check.XXXXXX)"
AUDIT="$WORKDIR/audit.jsonl"
AGENT_LOG="$WORKDIR/agent.log"
AGENT_PIDFILE="$WORKDIR/agent.pid"
AGENT_PID=""

ATTACKS=(container-escape container-escape-connect reverse-seq fileless-seq)

kc() { kubectl --kubeconfig "$STATEWALL_KUBECONFIG" --context "$KUBE_CONTEXT" "$@"; }
log() { echo "[exit-check] $*" >&2; }

agent_alive() { [[ -n "$AGENT_PID" ]] && ps -p "$AGENT_PID" >/dev/null 2>&1; }

stop_agent() {
    [[ -n "$AGENT_PID" ]] || return 0
    sudo -n kill -INT "$AGENT_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
        agent_alive || break
        sleep 0.5
    done
    if agent_alive; then
        sudo -n kill -KILL "$AGENT_PID" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
    AGENT_PID=""
}

# shellcheck disable=SC2329,SC2317  # cleanup and its body run via the EXIT trap, not a direct call
cleanup() {
    stop_agent
    kc delete namespace "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    log "artifacts kept in $WORKDIR"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

for f in "$STATEWALL_AGENT" "$STATEWALL_OBJECT" "$STATEWALL_BUNDLE" "$STATEWALL_KUBECONFIG"; do
    [[ -f "$f" ]] || { log "missing: $f"; exit 2; }
done
kc get nodes >/dev/null

log "starting agent (enforce=$STATEWALL_ENFORCE, audit: $AUDIT)"
# shellcheck disable=SC2016,SC2024
sudo -n sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$AGENT_PIDFILE" \
    "$STATEWALL_AGENT" --object "$STATEWALL_OBJECT" --bundle "$STATEWALL_BUNDLE" \
    --kubeconfig "$STATEWALL_KUBECONFIG" "${AGENT_MODE_ARGS[@]}" >"$AUDIT" 2>"$AGENT_LOG" &
sleep 3
AGENT_PID="$(cat "$AGENT_PIDFILE" 2>/dev/null || true)"
if ! agent_alive; then
    log "agent exited early:"
    cat "$AGENT_LOG" >&2
    exit 1
fi

log "applying benign workloads"
# Wait out a namespace still terminating from a previous run so this run can create it.
deadline=$((SECONDS + ${READY_TIMEOUT%s}))
while kc get namespace "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Terminating; do
    if ((SECONDS > deadline)); then
        log "namespace $NAMESPACE still terminating"
        exit 1
    fi
    sleep 2
done
kc create namespace "$NAMESPACE" --dry-run=client -o yaml | kc apply -f - >/dev/null
kc apply -f "$WORKLOADS/benign/"
kc -n "$NAMESPACE" wait --for=condition=Ready pod --all --timeout="$READY_TIMEOUT"
log "benign baseline for ${BENIGN_SECONDS}s"
sleep "$BENIGN_SECONDS"

log "applying attacks"
for a in "${ATTACKS[@]}"; do
    kc apply -f "$WORKLOADS/attack/$a.yaml"
done
deadline=$((SECONDS + ${READY_TIMEOUT%s}))
for a in "${ATTACKS[@]}"; do
    while true; do
        phase="$(kc -n "$NAMESPACE" get pod "$a" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
        case "$phase" in Succeeded | Running | Failed) break ;; esac
        if ((SECONDS > deadline)); then
            log "attack pod $a not started (phase: ${phase:-unknown})"
            kc -n "$NAMESPACE" describe pod "$a" >&2 || true
            exit 1
        fi
        sleep 2
    done
    log "attack pod $a: $phase"
done
sleep "$ATTACK_SECONDS"
for a in "${ATTACKS[@]}"; do
    kc -n "$NAMESPACE" logs "pod/$a" >&2 || true
done

BENIGN_PODS="$(kc -n "$NAMESPACE" get pod -o name | sed 's|^pod/||' | grep -vxF -f <(printf '%s\n' "${ATTACKS[@]}") || true)"
POD_FAILURES=0
if [[ "$STATEWALL_ENFORCE" == "1" ]]; then
    log "asserting attackers killed and benign pods untouched"
    for a in "${ATTACKS[@]}"; do
        deadline=$((SECONDS + 30))
        phase=""
        while ((SECONDS <= deadline)); do
            phase="$(kc -n "$NAMESPACE" get pod "$a" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
            [[ "$phase" == "Failed" ]] && break
            sleep 2
        done
        if [[ "$phase" == "Failed" ]]; then
            log "ok: attacker $a phase Failed"
        else
            log "FAIL: attacker $a phase ${phase:-unknown}, expected Failed"
            kc -n "$NAMESPACE" describe pod "$a" >&2 || true
            POD_FAILURES=$((POD_FAILURES + 1))
        fi
    done
fi
for b in $BENIGN_PODS; do
    phase="$(kc -n "$NAMESPACE" get pod "$b" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    restarts="$(kc -n "$NAMESPACE" get pod "$b" -o jsonpath='{range .status.containerStatuses[*]}{.restartCount}{"\n"}{end}' 2>/dev/null | awk '{s+=$1} END {print s+0}')"
    if [[ "$phase" == "Failed" || "$restarts" != "0" ]]; then
        log "FAIL: benign pod $b disturbed (phase ${phase:-unknown}, restarts $restarts)"
        kc -n "$NAMESPACE" describe pod "$b" >&2 || true
        POD_FAILURES=$((POD_FAILURES + 1))
    fi
done
if ! agent_alive; then
    log "FAIL: agent died during the run"
    POD_FAILURES=$((POD_FAILURES + 1))
fi
kc get nodes --no-headers >&2 || POD_FAILURES=$((POD_FAILURES + 1))

log "stopping agent"
stop_agent

rc=0
python3 "$CHECKER" --expectations "$REPO_ROOT/testdata/expectations.json" "${CHECKER_MODE_ARGS[@]}" "$AUDIT" || rc=$?
if ((POD_FAILURES > 0)); then
    log "$POD_FAILURES pod/agent assertion(s) failed"
    exit 1
fi
exit "$rc"
