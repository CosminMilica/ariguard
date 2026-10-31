#!/usr/bin/env bash
# Phase 2 demo: container-escape under detect-only, then under --enforce. Runs in the Lima VM.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-statewall-dev}"
NS_AGENT="statewall-system"
NS_EVAL="statewall-eval"
ATTACK="$REPO_ROOT/testdata/workloads/attack/container-escape.yaml"
CHAIN_SECONDS="${CHAIN_SECONDS:-25}"
ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-180s}"

kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }
log() { echo "[demo] $*" >&2; }

run_attack() {
    kc delete pod container-escape -n "$NS_EVAL" --ignore-not-found --wait=true >/dev/null
    kc apply -f "$ATTACK" >/dev/null
    sleep "$CHAIN_SECONDS"
    echo "--- attacker pod ---"
    kc -n "$NS_EVAL" get pod container-escape -o wide || true
    kc -n "$NS_EVAL" logs container-escape 2>&1 | tail -n 8 || true
    echo "--- audit (container-escape) ---"
    kc -n "$NS_AGENT" logs ds/statewall-agent --since="${CHAIN_SECONDS}s" 2>/dev/null |
        grep container-escape | tail -n 8 || true
}

cleanup() { kc delete pod container-escape -n "$NS_EVAL" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

kc create namespace "$NS_EVAL" --dry-run=client -o yaml | kc apply -f - >/dev/null

log "deploying agent in detect-only mode"
kc apply -k "$REPO_ROOT/deploy/k8s/overlays/detect" >/dev/null
kc -n "$NS_AGENT" rollout restart ds/statewall-agent >/dev/null
kc -n "$NS_AGENT" rollout status ds/statewall-agent --timeout="$ROLLOUT_TIMEOUT"

log "run 1 (detect-only): expect the chain to reach compromised, attacker keeps running"
run_attack

log "flipping --enforce on"
kc apply -k "$REPO_ROOT/deploy/k8s/overlays/enforce" >/dev/null
kc -n "$NS_AGENT" rollout status ds/statewall-agent --timeout="$ROLLOUT_TIMEOUT"

log "run 2 (--enforce): expect the attacker to be killed"
run_attack

log "kill counter"
kc -n "$NS_AGENT" get pods -l app.kubernetes.io/name=statewall-agent -o name |
    while read -r p; do
        kc get --raw "/api/v1/namespaces/$NS_AGENT/pods/${p#pod/}:9102/proxy/metrics" | grep -i kill || true
    done
