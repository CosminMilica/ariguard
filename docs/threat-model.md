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

## Assumptions

- Kernel ≥ 5.7 with `CONFIG_BPF_LSM=y` and BTF enabled.
- The agent runs privileged enough to load BPF and attach LSM hooks.
- The control plane and agents trust each other over an authenticated channel.
