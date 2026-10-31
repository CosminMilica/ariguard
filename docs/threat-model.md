# Threat model

## In scope

- Detection and **synchronous** mitigation of multi-stage, syscall-observable attack
  chains on a single node (container escape, local privilege escalation).
- Deterministic, bounded overhead with a fixed memory budget.

## Out of scope (for now)

- Kernel-exploit-based eBPF bypass or tampering with the programs/maps themselves.
- Attacks that never touch the monitored syscalls.
- Cluster-wide correlation across nodes.
- Full MITRE ATT&CK coverage — the FSM is scoped to one or two well-chosen kill chains.

## Known gaps (tracked)

- Mounts through the new mount API (`fsopen`/`fsmount`/`move_mount`) bypass the `mount`
  hook; util-linux ≥ 2.39 uses it by default (`BPF-1.9`).
- Tracepoint path matching sees the user-supplied string; relative paths and symlinks
  bypass the prefix match until phase 2 moves to `lsm/file_open` + `bpf_d_path`.

## False-positive risks found in phase 1

- `host_mount` matches any `mount(2)`, including propagation-only changes. `unshare -m cmd`
  calls `unshare`, then `mount(MS_REC|MS_PRIVATE)`, then `execve`, so one command walks a
  `suspicious` workload all the way to `compromised` (`BPF-2.8`).
- `critical_execve` matches every `execve`; the final step is often an unrelated command.
- Prefix matching is a plain byte prefix: `containerd.sock` also matches
  `containerd.sock.ttrpc`.
- State updates are lookup-then-update, so events from one cgroup on two CPUs can race.
  Harmless for detection, must be settled before enforcement (`BPF-2.6`).

None of these fired on the phase 1 workloads; they are the cases phase 2 must close
before denying or killing anything.

## Assumptions

- Kernel ≥ 5.7 with `CONFIG_BPF_LSM=y` and BTF enabled.
- The agent runs privileged enough to load BPF and attach LSM hooks.
- The control plane and agents trust each other over an authenticated channel.
