#!/usr/bin/env bash
# demo-load: continuously launch varied attack (and some benign) workloads to fill the
# console with live data, and double as a long soak test. Each instance gets a unique name
# (generateName) so it shows up as a distinct incident. Runs for DURATION seconds.
#
#   DURATION=3600 WAVE=2 INTERVAL=20 KUBE_CONTEXT=kind-... testdata/scripts/demo-load.sh
#
# Needs: kubectl, and $PYTHON (default python3) with PyYAML for the manifest rewrite.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ATTACK_DIR="$REPO_ROOT/testdata/workloads/attack"
BENIGN_DIR="$REPO_ROOT/testdata/workloads/benign"
DURATION="${DURATION:-3600}"     # total run time, seconds
INTERVAL="${INTERVAL:-20}"       # base seconds between waves (+ up to INTERVAL jitter)
WAVE="${WAVE:-2}"                # attack instances per wave
BENIGN_EVERY="${BENIGN_EVERY:-3}" # ~1 in N waves also spawns a benign workload
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-statewall-dev}"
PYTHON="${PYTHON:-python3}"
read -r -a NAMESPACES <<<"${NAMESPACES:-ariguard-eval ariguard-eval-2 ariguard-eval-3}"

kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }
log() { echo "[demo-load] $*"; }

# Rewrite a manifest: drop the fixed name, add generateName, set the namespace.
rewrite() {
  "$PYTHON" -c '
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
b = d["metadata"].pop("name", "attack")
d["metadata"]["generateName"] = b + "-"
d["metadata"]["namespace"] = sys.argv[2]
print(yaml.safe_dump(d))' "$1" "$2"
}

spawn() { # file ns
  if rewrite "$1" "$2" | kc create -f - >/dev/null 2>&1; then
    log "spawned $(basename "$1" .yaml) in $2"
  fi
}

prune() { # remove finished pods so the node does not fill up
  for ns in "${NAMESPACES[@]}"; do
    kc -n "$ns" delete pod --field-selector status.phase==Failed --wait=false >/dev/null 2>&1 || true
    kc -n "$ns" delete pod --field-selector status.phase==Succeeded --wait=false >/dev/null 2>&1 || true
  done
}

cleanup() { log "stopping; pruning"; prune; }
trap cleanup EXIT

for ns in "${NAMESPACES[@]}"; do
  kc create namespace "$ns" --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc label ns "$ns" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null
done

mapfile -t ATTACKS < <(ls "$ATTACK_DIR"/*.yaml)
mapfile -t BENIGN < <(ls "$BENIGN_DIR"/*.yaml 2>/dev/null || true)
[[ ${#ATTACKS[@]} -gt 0 ]] || { log "no attack manifests in $ATTACK_DIR"; exit 2; }

deadline=$(( $(date +%s) + DURATION ))
log "running ${DURATION}s · wave=${WAVE} every ~${INTERVAL}s · ns: ${NAMESPACES[*]} · ${#ATTACKS[@]} attack types"
waves=0
while (( $(date +%s) < deadline )); do
  for ((i = 0; i < WAVE; i++)); do
    spawn "${ATTACKS[RANDOM % ${#ATTACKS[@]}]}" "${NAMESPACES[RANDOM % ${#NAMESPACES[@]}]}"
  done
  if (( ${#BENIGN[@]} > 0 && RANDOM % BENIGN_EVERY == 0 )); then
    spawn "${BENIGN[RANDOM % ${#BENIGN[@]}]}" "${NAMESPACES[RANDOM % ${#NAMESPACES[@]}]}"
  fi
  prune
  waves=$((waves + 1))
  sleep $(( INTERVAL + RANDOM % (INTERVAL + 1) ))
done
log "done after ${waves} waves"
