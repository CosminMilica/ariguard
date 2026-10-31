# bpf — eBPF data plane (Rust / Aya)

The in-kernel part of Statewall. Two crates:

- **`statewall-common`** — `no_std` types shared across the toolchain boundary:
  FSM states, events, actions and the map key/value layouts. This is the **single
  source of truth** for the ABI; the Go map bindings must match it byte-for-byte.
- **`statewall-ebpf`** — the kernel programs: syscall hooks (kprobe / tracepoint /
  LSM), the zero-allocation FSM engine, and the map definitions.

All kernel code is `no_std` and performs **no dynamic allocation**. State lives in
pre-allocated maps sized at load time.

## Build

```sh
cargo build --release          # produces the BPF object under target/
```

Requires a nightly toolchain with `rust-src` (see `rust-toolchain.toml`) and
`bpf-linker` (`cargo install bpf-linker`).
