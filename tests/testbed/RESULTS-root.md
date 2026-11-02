# Testbed results — real web-RCE escape vs AriGuard (root app: detect + enforce)

Generated: 2026-11-02T18:12:47Z · target: `vuln-root` (command-injection web app running as root)

## What ran
A real attacker flow against a root-running app: HTTP command injection → root shell →
recon → full container-escape chain (runtime socket → setns → host mount → execve). Because
the app runs as root, the chain completes — unlike slice 1's www-data DVWA shell. Run once
detect-only, then once under `--enforce --isolate=on`.

## Run 1 — detect-only
### Exploit transcript
```
=== RCE established ===
whoami: root

=== stage 1: recon ===
uid=0(root) gid=0(root) groups=0(root)
Linux vuln-root-7d7b484b4-jbdkv 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:39:52 UTC 2026 aarch64 GNU/Linux
sa-token (first 24 chars): eyJhbGciOiJSUzI1NiIsImtp

=== stage 2: escape chain (as root — expected to reach compromised) ===
step 1 (runtime socket): opened-runtime-socket
step 2 (setns host):     setns-done
step 3 (host mount):     mount-done
step 4 (execve payload): exec-done
=== exploit finished ===
```
### Escape kill-chain detected
```
{"ts_ns":121398744115610,"cgroup_id":190654,"pid":2754904,"ppid":2754903,"comm":"cat","hook":"openat","rule":"container-escape","event":"runtime_socket_open","from":"normal","to":"suspicious","action":"observe","enforced":false,"namespace":"ariguard-testbed","pod":"vuln-root-7d7b484b4-jbdkv","container":"app","image":"docker.io/library/python:3.12-slim","image_id":"docker.io/library/python@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"}
{"ts_ns":121400777567671,"cgroup_id":190654,"pid":2754907,"ppid":2754906,"comm":"nsenter","hook":"setns","rule":"container-escape","event":"namespace_manipulation","from":"suspicious","to":"escalating","action":"throttle","enforced":false,"namespace":"ariguard-testbed","pod":"vuln-root-7d7b484b4-jbdkv","container":"app","image":"docker.io/library/python:3.12-slim","image_id":"docker.io/library/python@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"}
{"ts_ns":121402808803906,"cgroup_id":190654,"pid":2754933,"ppid":2754931,"comm":"mount","hook":"fsmount","rule":"container-escape","event":"host_mount","from":"escalating","to":"breakout_imminent","action":"deny","enforced":false,"namespace":"ariguard-testbed","pod":"vuln-root-7d7b484b4-jbdkv","container":"app","image":"docker.io/library/python:3.12-slim","image_id":"docker.io/library/python@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"}
{"ts_ns":121404838246146,"cgroup_id":190654,"pid":2754934,"ppid":2754583,"comm":"python3","hook":"execve","rule":"container-escape","event":"critical_execve","from":"breakout_imminent","to":"compromised","action":"kill","enforced":false,"namespace":"ariguard-testbed","pod":"vuln-root-7d7b484b4-jbdkv","container":"app","image":"docker.io/library/python:3.12-slim","image_id":"docker.io/library/python@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"}
```

## Run 2 — enforce + isolate
### Exploit transcript
```
=== RCE established ===
whoami: root

=== stage 1: recon ===
uid=0(root) gid=0(root) groups=0(root)
Linux vuln-root-7d7b484b4-jbdkv 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:39:52 UTC 2026 aarch64 GNU/Linux
sa-token (first 24 chars): eyJhbGciOiJSUzI1NiIsImtp

=== stage 2: escape chain (as root — expected to reach compromised) ===
step 1 (runtime socket): opened-runtime-socket
step 2 (setns host):     setns-done
step 3 (host mount):     mount-done
step 4 (execve payload): 
=== exploit finished ===
```
### Audit (look for enforced=1)
```
{"ts_ns":121424447835944,"cgroup_id":190654,"pid":2755175,"ppid":2755174,"comm":"cat","hook":"openat","rule":"container-escape","event":"runtime_socket_open","from":"normal","to":"suspicious","action":"observe","enforced":false,"namespace":"ariguard-testbed","pod":"vuln-root-7d7b484b4-jbdkv","container":"app","image":"docker.io/library/python:3.12-slim","image_id":"docker.io/library/python@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"}
{"ts_ns":121426472548068,"cgroup_id":190654,"pid":2755178,"ppid":2755177,"comm":"nsenter","hook":"setns","rule":"container-escape","event":"namespace_manipulation","from":"suspicious","to":"escalating","action":"throttle","enforced":false,"namespace":"ariguard-testbed","pod":"vuln-root-7d7b484b4-jbdkv","container":"app","image":"docker.io/library/python:3.12-slim","image_id":"docker.io/library/python@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"}
{"ts_ns":121428500320646,"cgroup_id":190654,"pid":2755181,"ppid":2755179,"comm":"mount","hook":"fsmount","rule":"container-escape","event":"host_mount","from":"escalating","to":"breakout_imminent","action":"deny","enforced":false,"namespace":"ariguard-testbed","pod":"vuln-root-7d7b484b4-jbdkv","container":"app","image":"docker.io/library/python:3.12-slim","image_id":"docker.io/library/python@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"}
{"ts_ns":121430520138238,"cgroup_id":190654,"pid":2755182,"ppid":2754583,"comm":"python3","hook":"execve","rule":"container-escape","event":"critical_execve","from":"breakout_imminent","to":"compromised","action":"kill","enforced":true,"namespace":"ariguard-testbed","pod":"vuln-root-7d7b484b4-jbdkv","container":"app","image":"docker.io/library/python:3.12-slim","image_id":"docker.io/library/python@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"}
```
### Autonomous isolation (Tier C1)
- target pod: `vuln-root-7d7b484b4-jbdkv`
- quarantine label `ariguard.io/quarantine`: `true`
- deny-all NetworkPolicy: `networkpolicy.networking.k8s.io/ariguard-quarantine` (kindnet does not enforce it; object creation is the signal)

## Analysis

**Detect — the full chain completes to `compromised`.** As root, every step issued over the web
RCE drove a real syscall and the FSM advanced the whole kill-chain, attributed to pod `vuln-root`
/ container `app`:

| step | comm | hook | event | transition |
|---|---|---|---|---|
| runtime socket | `cat` | `openat` | runtime_socket_open | normal → suspicious |
| setns (host) | `nsenter` | `setns` | namespace_manipulation | suspicious → escalating |
| host mount | `mount` | `fsmount` | host_mount | escalating → breakout_imminent |
| execve payload | `python3` | `execve` | critical_execve | breakout_imminent → **compromised** |

The mount matched via `fsmount` (the new mount API), not legacy `mount(2)` — good coverage evidence.

**Enforce — the terminal step is killed synchronously.** The same chain ran and the
`critical_execve` record came back `enforced=true`: `bpf_send_signal(SIGKILL)` fired at the
compromised transition. The proof it is synchronous is the transcript — `step 4` printed no
`exec-done` (compare detect, which did): the payload process was killed **before** it ran, not
alerted on afterwards. The core thesis claim, on a real attack rather than a synthetic driver.

**Autonomous isolation (Tier C1) fired off the real kill.** Within the same run the agent
quarantined the compromised pod with no operator in the loop: label `ariguard.io/quarantine=true`
set, and a deny-all `NetworkPolicy/ariguard-quarantine` created. (kindnet does not enforce
NetworkPolicy, so the object is the signal; a Cilium/Calico CNI would cut the pod's traffic.)

**Richer records (current agent image).** These records carry `ppid` (process ancestry), `image`
and `image_id` (the python digest) — the Tier B capture the previously-deployed image lacked. The
escape chain is now attributable up the process tree and to the exact image.

**The privilege spectrum (vs slice 1).** Same escape chain, two outcomes decided purely by the
privilege the web RCE lands with: www-data stalls at `escalating` (attempt detected); root completes
to `compromised` and is killed + quarantined under enforce. The honest efficacy story is "attempt
detected at any privilege; completion blocked and contained at root".

**Still open — B3 (observed values):** the records carry `image`/`ppid` but still not the opened
path or exec'd argv, so the audit alone can't show *which* socket/binary without the transcript
beside it. That remains the next fix.
