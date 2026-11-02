# Testbed results — real web-RCE escape vs AriGuard (detect-only)

Generated: 2026-11-02T17:30:24Z · target pod: `dvwa-74d8978c9c-qz2pn`

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

Linux dvwa-74d8978c9c-qz2pn 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:39:52 UTC 2026 aarch64 GNU/Linux

total 4
drwxrwxrwt 3 root root  140 Nov  2 17:26 .
drwxr-xr-x 3 root root 4096 Nov  2 17:26 ..
drwxr-xr-x 2 root root  100 Nov  2 17:26 ..2026_11_02_17_26_29.2807688765
lrwxrwxrwx 1 root root   32 Nov  2 17:26 ..data -> ..2026_11_02_17_26_29.2807688765
lrwxrwxrwx 1 root root   13 Nov  2 17:26 ca.crt -> ..data/ca.crt
lrwxrwxrwx 1 root root   16 Nov  2 17:26 namespace -> ..data/namespace
lrwxrwxrwx 1 root root   12 Nov  2 17:26 token -> ..data/token


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
{"ts_ns":118886235484187,"cgroup_id":185962,"pid":2748644,"comm":"cat","hook":"openat","rule":"container-escape","event":"runtime_socket_open","from":"normal","to":"suspicious","action":"observe","enforced":false,"namespace":"ariguard-testbed","pod":"dvwa-74d8978c9c-qz2pn","container":"dvwa"}
{"ts_ns":118887321457732,"cgroup_id":185962,"pid":2748648,"comm":"nsenter","hook":"setns","rule":"container-escape","event":"namespace_manipulation","from":"suspicious","to":"escalating","action":"throttle","enforced":false,"namespace":"ariguard-testbed","pod":"dvwa-74d8978c9c-qz2pn","container":"dvwa"}
```

## Noise
- benign apache/mariadb `connect` calls classified as reverse-shell `connected` (observe): **19** records.

## Analysis

**Detected.** The `container-escape` rule fired on syscalls issued entirely over the web RCE,
and advanced two states: `normal → suspicious` (the `openat` of the runtime socket, `comm=cat`)
and `suspicious → escalating` (the `setns` from `nsenter`, `comm=nsenter`). This is genuine
detection — the FSM never saw a hand-written attack pod, only apache→php→sh spawning these
syscalls inside the target's cgroup.

**Attribution is correct.** Both records are attributed to pod `dvwa-…` and container `dvwa`,
despite the chain being several processes deep below apache. Per-cgroup tracking holds for a
real web shell.

**The chain stopped at `escalating` — and this is the headline finding.** The web RCE lands as
`www-data` (uid 33), which has no `CAP_SYS_ADMIN` *even in a privileged container*: the privilege
belongs to the container's root, not to www-data. Consequences:
- `setns` was issued and returned `EPERM` — the tracepoint fired at entry, so we **detected** it.
- `mount` was **refused by util-linux in user space** (`must be superuser`) *before* the
  `mount(2)` syscall, so `sys_enter_mount` never fired and there was nothing to detect. The chain
  never reached `breakout_imminent`/`compromised`.

So the honest result is not "we missed the mount" — no mount syscall occurred. A real web-RCE
escape needs a **privilege escalation to root first**; our synthetic driver skips that by running
as root. The next testbed slice should add a privesc step so the full chain is exercised, and the
efficacy numbers should separate "attempt detected" from "escape completed".

**False positives (noise): 19 records.** Benign apache/mariadb outbound `connect` calls match the
`reverse-shell` rule's `outbound_connect` binding and sit at `connected` (observe, no action).
Harmless today, but it buries the signal.

**Gaps → backlog (data-driven):**
- **B3 (observed values — `connect` dst IP, opened path):** the record carries neither the path
  opened nor the connect destination. We cannot confirm from the audit that the `openat` was
  actually `containerd.sock`, and we cannot tell the 19 loopback/intra-pod DB connects from a real
  external C2. Adding dst IP would let the `reverse-shell` rule ignore loopback/same-pod connects
  and kill most of this noise — the single highest-value next fix, exactly as `docs/backlog.md`
  ranks it.
- **Privesc-aware escape scenario (new):** model the www-data → root step so the escape can
  actually complete; until then the escape rule is only reachable to `escalating` from a web RCE.
- Lateral/F2 is untouched here (single pod) — deferred to the multi-service slice.
