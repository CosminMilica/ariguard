#!/usr/bin/env bash
# Real-attack testbed runner. Deploys the AriGuard agent detect-only, stands up the vulnerable
# DVWA target, drives the real web-RCE escape exploit against it, and collects the audit the
# agent produced. Writes a raw baseline to tests/testbed/RESULTS.md.
#
# NOT a CI gate (runs a real exploit). Run it against the isolated dev cluster only.
#
#   KUBE_CONTEXT=kind-ariguard-dev ./run.sh
#   # or from the host with the exported kubeconfig:
#   KUBECONFIG=~/.kube/ariguard-dev.yaml ./run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
NS_AGENT="ariguard-system"
NS_TESTBED="ariguard-testbed"
LOCAL_PORT="${LOCAL_PORT:-8099}"   # not 8080: the console is commonly port-forwarded there
ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-180s}"
RESULTS="$HERE/RESULTS.md"

kc() { if [ -n "$KUBE_CONTEXT" ]; then kubectl --context "$KUBE_CONTEXT" "$@"; else kubectl "$@"; fi; }
log() { echo "[testbed] $*" >&2; }

log "1/5 deploy the agent detect-only"
kc apply -k "$REPO_ROOT/deploy/k8s/overlays/detect" >/dev/null
kc -n "$NS_AGENT" rollout restart ds/ariguard-agent >/dev/null
kc -n "$NS_AGENT" rollout status ds/ariguard-agent --timeout="$ROLLOUT_TIMEOUT"
START="$(date +%s)"

log "2/5 deploy the vulnerable target (DVWA + MariaDB)"
kc apply -f "$HERE/app/dvwa.yaml" >/dev/null
kc -n "$NS_TESTBED" rollout status deploy/dvwa --timeout="$ROLLOUT_TIMEOUT"
DVWA_POD="$(kc -n "$NS_TESTBED" get pod -l app=dvwa -o jsonpath='{.items[0].metadata.name}')"
log "target pod: $DVWA_POD"

log "3/5 port-forward the target"
kc -n "$NS_TESTBED" port-forward "svc/dvwa" "$LOCAL_PORT:80" >/tmp/testbed-pf.log 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
sleep 4
if ! kill -0 "$PF" 2>/dev/null || ! grep -q "Forwarding from" /tmp/testbed-pf.log 2>/dev/null; then
  echo "FATAL: port-forward to the target failed (is local port $LOCAL_PORT in use?):" >&2
  cat /tmp/testbed-pf.log >&2
  echo "set LOCAL_PORT=<free port> and re-run." >&2
  exit 1
fi

# Readiness (both containers ready) does not mean DVWA can reach its database yet; the login
# page serves a mysqli fatal until the DB accepts the dvwa user. Wait for a clean page.
log "waiting for DVWA to reach its database"
for i in $(seq 1 30); do
  if ! curl -s "http://127.0.0.1:$LOCAL_PORT/login.php" | grep -qi 'Fatal error'; then break; fi
  sleep 2
done

log "4/5 run the real web-RCE escape exploit"
EXPLOIT_OUT="$(BASE="http://127.0.0.1:$LOCAL_PORT" bash "$HERE/exploit/escape-via-rce.sh" 2>&1 || true)"
echo "$EXPLOIT_OUT"
sleep 5

log "5/5 collect the audit the agent emitted for the target pod"
SINCE=$(( $(date +%s) - START + 5 ))
ALL="$(kc -n "$NS_AGENT" logs ds/ariguard-agent --since="${SINCE}s" 2>/dev/null \
        | grep -iE "ariguard-testbed|$DVWA_POD|dvwa" || true)"
# The escape kill-chain: the signal. Everything else (benign apache/mariadb connects
# classified as reverse-shell "connected" observe) is noise we report as a count.
CHAIN="$(echo "$ALL" | grep -iE '"rule":"container-escape"' || true)"
NOISE_N="$(echo "$ALL" | grep -icE '"rule":"reverse-shell"' || true)"
AUDIT="$CHAIN"

{
  echo "# Testbed results — real web-RCE escape vs AriGuard (detect-only)"
  echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ) · target pod: \`$DVWA_POD\`"
  echo
  echo "## What ran"
  echo "A real attacker flow: HTTP command-injection in DVWA → www-data shell → recon →"
  echo "container-escape chain (runtime socket → setns → host mount → exec), every step issued"
  echo "over the web RCE, not scripted into the pod."
  echo
  echo "## Exploit transcript"
  echo '```'
  echo "$EXPLOIT_OUT"
  echo '```'
  echo
  echo "## Escape kill-chain detected (container-escape rule)"
  echo '```'
  if [ -n "$CHAIN" ]; then echo "$CHAIN"; else echo "(no container-escape audit — see Analysis)"; fi
  echo '```'
  echo
  echo "## Noise"
  echo "- benign apache/mariadb \`connect\` calls classified as reverse-shell \`connected\` (observe): **$NOISE_N** records."
  echo
  echo "## Analysis (fill in)"
  echo "- Detected: which rule(s) fired, at which escape step, final state reached."
  echo "- Missed: steps that produced no audit (false negatives)."
  echo "- Attribution: was the audit attributed to \`$DVWA_POD\` (php/apache child processes)?"
  echo "- False positives: the reverse-shell \`connected\` observations above."
  echo "- Gaps -> backlog: what this exposes (e.g. observed values / B3, lateral / F2)."
} > "$RESULTS"

log "wrote $RESULTS"
echo "=== RESULTS.md ==="
cat "$RESULTS"
