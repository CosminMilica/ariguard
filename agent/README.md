# agent — node data-plane manager (Go)

Runs as a DaemonSet, one instance per node. Responsibilities:

- **loader** — load and attach the Rust-built eBPF object (via `cilium/ebpf`), and
  populate the state / transition-table maps.
- **mitigator** — apply mitigation actions surfaced by the kernel (deny / kill /
  quarantine) and expose them to the control plane.
- **audit** — drain the kernel ring buffer and stream events upstream.

The agent holds **no decision logic**: detection and enforcement happen in the kernel.
It is a loader, map manager, and telemetry pump.
