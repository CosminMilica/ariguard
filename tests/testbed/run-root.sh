#!/usr/bin/env bash
# Slice-2 runner: real web RCE against a ROOT-running vulnerable app, twice — detect-only (the
# full escape chain is allowed to complete to `compromised`), then enforce+isolate (the terminal
# step is killed and the pod autonomously quarantined). Writes tests/testbed/RESULTS-root.md.
#
# NOT a CI gate (real exploit). Isolated dev cluster only.
#
#   KUBECONFIG=~/.kube/ariguard-dev.yaml ./run-root.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
NS_AGENT="ariguard-system"
NS_TESTBED="ariguard-testbed"
LOCAL_PORT="${LOCAL_PORT:-8099}"
ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-180s}"
RESULTS="$HERE/RESULTS-root.md"

kc() { if [ -n "$KUBE_CONTEXT" ]; then kubectl --context "$KUBE_CONTEXT" "$@"; else kubectl "$@"; fi; }
log() { echo "[testbed] $*" >&2; }

# deploy_agent <overlay>: roll the agent onto the given kustomize overlay and wait.
deploy_agent() {
  kc apply -k "$REPO_ROOT/deploy/k8s/overlays/$1" >/dev/null
  kc -n "$NS_AGENT" rollout restart ds/ariguard-agent >/dev/null
  kc -n "$NS_AGENT" rollout status ds/ariguard-agent --timeout="$ROLLOUT_TIMEOUT"
}

# attack: port-forward the target, run the root exploit, print its transcript on stdout.
attack() {
  # free the port from any prior forward (the previous run's kubectl can linger past kill)
  local held; held="$(lsof -tiTCP:"$LOCAL_PORT" -sTCP:LISTEN 2>/dev/null || true)"
  [ -n "$held" ] && { kill $held 2>/dev/null || true; sleep 1; }
  kc -n "$NS_TESTBED" port-forward svc/vuln-root "$LOCAL_PORT:80" >/tmp/testbed-pf.log 2>&1 &
  local pf=$!
  sleep 4
  if ! grep -q "Forwarding from" /tmp/testbed-pf.log 2>/dev/null; then
    echo "FATAL: port-forward failed (local port $LOCAL_PORT in use?)" >&2; cat /tmp/testbed-pf.log >&2; exit 1
  fi
  BASE="http://127.0.0.1:$LOCAL_PORT" bash "$HERE/exploit/escape-as-root.sh" 2>&1 || true
  kill $pf 2>/dev/null || true
  wait $pf 2>/dev/null || true
}

# audit_since <seconds>: container-escape records for the target in the window.
audit_since() {
  kc -n "$NS_AGENT" logs ds/ariguard-agent --since="${1}s" 2>/dev/null \
    | grep -iE 'ariguard-testbed|vuln-root' | grep -iE '"rule":"container-escape"' || true
}

log "deploy the vulnerable target (root web app)"
kc apply -f "$HERE/app/vuln-root.yaml" >/dev/null
kc -n "$NS_TESTBED" rollout status deploy/vuln-root --timeout="$ROLLOUT_TIMEOUT"

# ---- run 1: detect-only — the full chain must reach compromised ----
log "run 1/2: detect-only"
deploy_agent detect
T0=$(date +%s)
DETECT_OUT="$(attack)"
sleep 5
DETECT_AUDIT="$(audit_since $(( $(date +%s) - T0 + 5 )))"

# ---- run 2: enforce + isolate — the terminal execve is killed and the pod quarantined ----
log "run 2/2: enforce + isolate"
deploy_agent isolate
T0=$(date +%s)
ENFORCE_OUT="$(attack)"
sleep 6
ENFORCE_AUDIT="$(audit_since $(( $(date +%s) - T0 + 6 )))"
POD="$(kc -n "$NS_TESTBED" get pod -l app=vuln-root -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
QLABEL="$(kc -n "$NS_TESTBED" get pod -l app=vuln-root -o jsonpath='{.items[0].metadata.labels.ariguard\.io/quarantine}' 2>/dev/null || true)"
QNETPOL="$(kc -n "$NS_TESTBED" get networkpolicy ariguard-quarantine -o name 2>/dev/null || true)"

{
  echo "# Testbed results — real web-RCE escape vs AriGuard (root app: detect + enforce)"
  echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ) · target: \`vuln-root\` (command-injection web app running as root)"
  echo
  echo "## What ran"
  echo "A real attacker flow against a root-running app: HTTP command injection → root shell →"
  echo "recon → full container-escape chain (runtime socket → setns → host mount → execve). Because"
  echo "the app runs as root, the chain completes — unlike slice 1's www-data DVWA shell. Run once"
  echo "detect-only, then once under \`--enforce --isolate=on\`."
  echo
  echo "## Run 1 — detect-only"
  echo "### Exploit transcript"; echo '```'; echo "$DETECT_OUT"; echo '```'
  echo "### Escape kill-chain detected"; echo '```'
  if [ -n "$DETECT_AUDIT" ]; then echo "$DETECT_AUDIT"; else echo "(none)"; fi
  echo '```'
  echo
  echo "## Run 2 — enforce + isolate"
  echo "### Exploit transcript"; echo '```'; echo "$ENFORCE_OUT"; echo '```'
  echo "### Audit (look for enforced=1)"; echo '```'
  if [ -n "$ENFORCE_AUDIT" ]; then echo "$ENFORCE_AUDIT"; else echo "(none)"; fi
  echo '```'
  echo "### Autonomous isolation (Tier C1)"
  echo "- target pod: \`${POD:-<gone>}\`"
  echo "- quarantine label \`ariguard.io/quarantine\`: \`${QLABEL:-<none>}\`"
  echo "- deny-all NetworkPolicy: \`${QNETPOL:-<none>}\` (kindnet does not enforce it; object creation is the signal)"
  echo
  echo "## Analysis (fill in)"
  echo "- Detect: did the chain reach \`compromised\`? which states, which comms?"
  echo "- Enforce: was the terminal step killed (enforced=1)? did the chain stop before completing?"
  echo "- Isolation: was the pod labelled + a NetworkPolicy created?"
  echo "- Compare to slice 1 (www-data): the privilege spectrum."
} > "$RESULTS"

log "wrote $RESULTS"
echo "=== RESULTS-root.md ==="
cat "$RESULTS"
