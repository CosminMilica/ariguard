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

## Assumptions

- Kernel ≥ 5.7 with `CONFIG_BPF_LSM=y` and BTF enabled.
- The agent runs privileged enough to load BPF and attach LSM hooks.
- The control plane and agents trust each other over an authenticated channel.
