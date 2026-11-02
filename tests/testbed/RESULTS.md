# Testbed results — real web-RCE escape vs AriGuard (detect-only)

Generated: 2026-11-02T19:37:42Z · target pod: `dvwa-74d8978c9c-kmvs7`

## What ran
A real attacker flow: HTTP command-injection in DVWA → www-data shell → recon →
container-escape chain (runtime socket → setns → host mount → exec), every step issued
over the web RCE, not scripted into the pod.

## Exploit transcript
```
[exploit] establishing RCE (setup + login + security=low), verifying with whoami
=== RCE established ===
whoami: www-data

=== stage 1: recon ===
uid=33(www-data) gid=33(www-data) groups=33(www-data)

Linux dvwa-74d8978c9c-kmvs7 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:39:52 UTC 2026 aarch64 GNU/Linux

total 4
drwxrwxrwt 3 root root  140 Nov  2 19:00 .
drwxr-xr-x 3 root root 4096 Nov  2 19:00 ..
drwxr-xr-x 2 root root  100 Nov  2 19:00 ..2026_11_02_19_00_19.618144137
lrwxrwxrwx 1 root root   31 Nov  2 19:00 ..data -> ..2026_11_02_19_00_19.618144137
lrwxrwxrwx 1 root root   13 Nov  2 19:00 ca.crt -> ..data/ca.crt
lrwxrwxrwx 1 root root   16 Nov  2 19:00 namespace -> ..data/namespace
lrwxrwxrwx 1 root root   12 Nov  2 19:00 token -> ..data/token


=== stage 2: escape chain ===
[exploit] step 1: touch the runtime socket (recon of the container runtime)
opened-runtime-socket

[exploit] step 2: setns into PID 1's namespaces (hostPID)
nsenter: reassociate to namespaces failed: Operation not permitted
setns-done

[exploit] step 3: mount a filesystem (privileged)
mount: /mnt: must be superuser to use mount.
       dmesg(1) may have more information after failed mount system call.
mount-done

[exploit] step 4: execute a payload (terminal step)

=== exploit finished ===
```

## Escape kill-chain detected (container-escape rule)
```
{"ts_ns":126524535372543,"cgroup_id":194974,"pid":2771862,"ppid":2771860,"comm":"cat","hook":"openat","rule":"container-escape","event":"runtime_socket_open","from":"normal","to":"suspicious","action":"observe","enforced":false,"namespace":"ariguard-testbed","pod":"dvwa-74d8978c9c-kmvs7","container":"dvwa","image":"ghcr.io/digininja/dvwa:latest","image_id":"ghcr.io/digininja/dvwa@sha256:8029450682bd70e2e8cd1ffe8e46dd1885ff2a913296091cebfa8ba0a7d36498"}
{"ts_ns":126525591664603,"cgroup_id":194974,"pid":2771883,"ppid":2771881,"comm":"nsenter","hook":"setns","rule":"container-escape","event":"namespace_manipulation","from":"suspicious","to":"escalating","action":"throttle","enforced":false,"namespace":"ariguard-testbed","pod":"dvwa-74d8978c9c-kmvs7","container":"dvwa","image":"ghcr.io/digininja/dvwa:latest","image_id":"ghcr.io/digininja/dvwa@sha256:8029450682bd70e2e8cd1ffe8e46dd1885ff2a913296091cebfa8ba0a7d36498"}
```

## Noise
- benign apache/mariadb `connect` calls classified as reverse-shell `connected` (observe): **0** records.

## Analysis (fill in)
- Detected: which rule(s) fired, at which escape step, final state reached.
- Missed: steps that produced no audit (false negatives).
- Attribution: was the audit attributed to `dvwa-74d8978c9c-kmvs7` (php/apache child processes)?
- False positives: the reverse-shell `connected` observations above.
- Gaps -> backlog: what this exposes (e.g. observed values / B3, lateral / F2).
