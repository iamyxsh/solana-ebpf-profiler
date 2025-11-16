#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_printk;
use aya_ebpf::macros::uprobe;
use aya_ebpf::programs::ProbeContext;

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
