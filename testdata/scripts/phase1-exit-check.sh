#!/usr/bin/env bash
# Phase 1 exit check (EVAL-1.3): run benign + attack workloads under the agent, assert on the audit stream.
# Runs inside the Lima VM against the kind cluster; needs passwordless sudo.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATEWALL_AGENT="${STATEWALL_AGENT:-$REPO_ROOT/bin/statewall-agent}"
STATEWALL_OBJECT="${STATEWALL_OBJECT:-$REPO_ROOT/bpf/target/bpfel-unknown-none/release/statewall}"
STATEWALL_BUNDLE="${STATEWALL_BUNDLE:-$REPO_ROOT/testdata/golden/container-escape.bin}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-statewall-dev}"
NAMESPACE="statewall-eval"
BENIGN_SECONDS="${BENIGN_SECONDS:-30}"
ATTACK_SECONDS="${ATTACK_SECONDS:-15}"
READY_TIMEOUT="${READY_TIMEOUT:-300s}"

WORKLOADS="$REPO_ROOT/testdata/workloads"
CHECKER="$REPO_ROOT/testdata/scripts/check_audit.py"
WORKDIR="$(mktemp -d -t statewall-exit-check.XXXXXX)"
AUDIT="$WORKDIR/audit.jsonl"
AGENT_LOG="$WORKDIR/agent.log"
AGENT_PIDFILE="$WORKDIR/agent.pid"
AGENT_PID=""

kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }
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

cleanup() {
    stop_agent
    kc delete namespace "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    log "artifacts kept in $WORKDIR"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

for f in "$STATEWALL_AGENT" "$STATEWALL_OBJECT" "$STATEWALL_BUNDLE"; do
    [[ -f "$f" ]] || { log "missing: $f"; exit 2; }
done
kc get nodes >/dev/null

log "starting agent (audit: $AUDIT)"
# shellcheck disable=SC2016,SC2024
sudo -n sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$AGENT_PIDFILE" \
    "$STATEWALL_AGENT" --object "$STATEWALL_OBJECT" --bundle "$STATEWALL_BUNDLE" >"$AUDIT" 2>"$AGENT_LOG" &
sleep 3
AGENT_PID="$(cat "$AGENT_PIDFILE" 2>/dev/null || true)"
if ! agent_alive; then
    log "agent exited early:"
    cat "$AGENT_LOG" >&2
    exit 1
fi

log "applying benign workloads"
kc create namespace "$NAMESPACE" --dry-run=client -o yaml | kc apply -f - >/dev/null
kc apply -f "$WORKLOADS/benign/"
kc -n "$NAMESPACE" wait --for=condition=Ready pod --all --timeout="$READY_TIMEOUT"
log "benign baseline for ${BENIGN_SECONDS}s"
sleep "$BENIGN_SECONDS"

log "applying attack"
kc apply -f "$WORKLOADS/attack/container-escape.yaml"
kc -n "$NAMESPACE" wait --for=condition=Ready pod/container-escape --timeout="$READY_TIMEOUT"
sleep "$ATTACK_SECONDS"
kc -n "$NAMESPACE" logs pod/container-escape >&2 || true

log "stopping agent"
stop_agent

python3 "$CHECKER" "$AUDIT"
