#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::{map, uprobe};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::ProbeContext;
use profiler_common::Event;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[uprobe]
pub fn uprobe_readline(_ctx: ProbeContext) {
    let pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;
    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe { (*ptr).pid = pid };
        entry.submit(0);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
