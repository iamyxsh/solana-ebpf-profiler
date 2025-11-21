#![no_std]
#![no_main]

use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_stackid};
use aya_ebpf::macros::{map, perf_event};
use aya_ebpf::maps::{RingBuf, StackTrace};
use aya_ebpf::programs::PerfEventContext;
use aya_ebpf::EbpfContext;
use profiler_common::Event;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static STACKS: StackTrace = StackTrace::with_max_entries(8192, 0);

#[perf_event]
pub fn profile_cpu(ctx: PerfEventContext) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let cycles = unsafe {
        (*ctx.as_ptr().cast::<aya_ebpf::bindings::bpf_perf_event_data>()).sample_period
    };
    let stack_id = unsafe { bpf_get_stackid(ctx.as_ptr(), &STACKS as *const _ as *mut _, 0) };

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            (*ptr).pid = pid;
            (*ptr).stack_id = stack_id;
            (*ptr).cpu_cycles = cycles;
        };
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
