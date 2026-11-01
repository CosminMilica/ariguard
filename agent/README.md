# agent — node data-plane manager (Go)

Runs as a DaemonSet, one instance per node. Responsibilities:

- **loader** — load and attach the Rust-built eBPF object (via `cilium/ebpf`), and
  populate the state / transition-table maps.
- **mitigator** — apply mitigation actions surfaced by the kernel (deny / kill /
  quarantine) and expose them to the control plane.
- **audit** — drain the kernel ring buffer and stream events upstream. Each event
  carries `ppid` plus the container image and image_id (from pod metadata); the
  `AuditRecord` wire size is 72 bytes.

The agent holds **no decision logic**: detection and enforcement happen in the kernel.
It is a loader, map manager, and telemetry pump.

## Telemetry & benchmarking

Beyond the event/kill/audit-dropped counters, the agent exposes per-program
run-time and BPF map bytes under `--bpf-stats`
(`ariguard_program_run_time_ns_total`, `ariguard_program_runs_total`,
`ariguard_bpf_map_bytes`). The `ariguard-bench` CLI drives the evaluation
(latency from BPF run-time stats, a memory curve from RSS + BPF map bytes vs
process count, throughput as events/sec + `audit_dropped`).
