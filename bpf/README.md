# bpf — eBPF data plane (Rust / Aya)

The in-kernel part of AriGuard. Two crates:

- **`ariguard-common`** — `no_std` types shared across the toolchain boundary:
  FSM states, events, actions and the map key/value layouts. This is the **single
  source of truth** for the ABI; the Go map bindings must match it byte-for-byte.
- **`ariguard-ebpf`** — the kernel programs: syscall hooks (kprobe / tracepoint /
  LSM), the zero-allocation FSM engine, and the map definitions.

All kernel code is `no_std` and performs **no dynamic allocation**. State lives in
pre-allocated maps sized at load time. The 16 syscall hooks are unchanged.

`AuditRecord` gained a `ppid` field (64 → 72 bytes). `ppid` is read via CO-RE from
`task_struct->real_parent->tgid`, using `vmlinux` bindings generated from the
kernel BTF (`ariguard-ebpf/src/vmlinux.rs`, committed, generated with `aya-tool`).

## Build

```sh
cargo build --release          # target/bpfel-unknown-none/release/ariguard
make build-bpf                 # same, copied to bin/ariguard.bpf.o
```

Requires a nightly toolchain with `rust-src` (see `rust-toolchain.toml`) and
`bpf-linker` (the dev VM installs the upstream static build; `cargo install` needs a
matching shared libLLVM). `.cargo/config.toml` sets the
`bpfel-unknown-none` target, `build-std = ["core"]` and the linker flags:

- `--btf`: emit BTF; maps are BTF-style (`#[btf_map]`, `.maps` section) so
  cilium/ebpf sees their key/value types.
- `--disable-expand-memcpy-in-order`: lets LLVM inline small `memset`s. Without
  it, zeroing struct fields becomes a call to the global `memset` from
  compiler-builtins, which the verifier rejects.
