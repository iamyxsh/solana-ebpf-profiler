#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_printk;
use aya_ebpf::macros::{map, uprobe};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::ProbeContext;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[uprobe]
pub fn uprobe_readline(_ctx: ProbeContext) {
    unsafe { bpf_printk!(b"uprobe fired") };
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
