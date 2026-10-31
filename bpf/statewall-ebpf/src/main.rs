#![no_std]
#![no_main]

// Phase-0 spike: attach a kprobe and confirm the Rust-built object loads via the
// Go (cilium/ebpf) loader. The FSM engine lands in phase 1.

use aya_ebpf::{macros::kprobe, programs::ProbeContext};

#[kprobe]
pub fn statewall(_ctx: ProbeContext) -> u32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
