#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_get_current_pid_tgid;

unsafe fn call_bpf_probe_read_user(
    dst: *mut core::ffi::c_void,
    size: u32,
    src: *const core::ffi::c_void,
) -> i64 {
    let f: unsafe extern "C" fn(*mut core::ffi::c_void, u32, *const core::ffi::c_void) -> i64 =
        core::mem::transmute(112i64);
    f(dst, size, src)
}
use aya_ebpf::macros::{map, perf_event, uprobe, uretprobe};
use aya_ebpf::maps::{Array, PerCpuArray, RingBuf};
use aya_ebpf::programs::{PerfEventContext, ProbeContext, RetProbeContext};
use aya_ebpf::EbpfContext;
use profiler_common::{Event, ProgramState, STACK_DUMP_SIZE, MAX_CPI_DEPTH};

#[map]
static TARGET_PID: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

#[map]
static PROGRAM_STATE: PerCpuArray<ProgramState> = PerCpuArray::with_max_entries(1, 0);

fn check_pid(_pid: u32) -> bool {
    // PID filtering moved to userspace — BPF Array comparison
    // doesn't work reliably on WSL2 kernels
    true
}

// vm::execute entry — marks "in sBPF execution"
#[uprobe]
pub fn vm_entry(ctx: ProbeContext) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !check_pid(pid) {
        return;
    }

    if let Some(ptr) = PROGRAM_STATE.get_ptr_mut(0) {
        unsafe {
            (*ptr).in_sbf = 1;
        }
    }
}

// vm::execute exit — clears "in sBPF execution"
#[uretprobe]
pub fn vm_exit(ctx: RetProbeContext) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !check_pid(pid) {
        return;
    }

    if let Some(ptr) = PROGRAM_STATE.get_ptr_mut(0) {
        unsafe {
            // Only clear if depth is back to 0 (handles CPI nesting)
            if (*ptr).depth == 0 {
                (*ptr).in_sbf = 0;
                (*ptr).program_id = [0u8; 32];
            }
        }
    }
}

// stable_log::program_invoke — extract program_id from 2nd arg (&Pubkey)
#[uprobe]
pub fn program_enter(ctx: ProbeContext) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !check_pid(pid) {
        return;
    }

    // 2nd arg (index 1) is &Pubkey pointer (rsi on x86_64, x1 on aarch64)
    let pubkey_ptr: u64 = match ctx.arg::<u64>(1) {
        Some(v) => v,
        None => return,
    };

    if let Some(ptr) = PROGRAM_STATE.get_ptr_mut(0) {
        unsafe {
            let depth = (*ptr).depth as usize;
            if depth < MAX_CPI_DEPTH {
                // Read 32-byte Pubkey from userspace
                let dst = core::ptr::addr_of_mut!((*ptr).ids[depth]) as *mut core::ffi::c_void;
                let ret = call_bpf_probe_read_user(dst, 32, pubkey_ptr as *const core::ffi::c_void);
                if ret == 0 {
                    // Copy to current program_id for perf_event to read
                    (*ptr).program_id = (*ptr).ids[depth];
                }
            }
            (*ptr).depth = (depth + 1).min(MAX_CPI_DEPTH) as u32;
            (*ptr).in_sbf = 1;
        }
    }
}

// stable_log::program_success — pop CPI stack
#[uprobe]
pub fn program_exit_ok(ctx: ProbeContext) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !check_pid(pid) {
        return;
    }

    if let Some(ptr) = PROGRAM_STATE.get_ptr_mut(0) {
        unsafe {
            pop_program_state(ptr);
        }
    }
}

// stable_log::program_failure — same as program_exit_ok
#[uprobe]
pub fn program_exit_err(ctx: ProbeContext) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !check_pid(pid) {
        return;
    }

    if let Some(ptr) = PROGRAM_STATE.get_ptr_mut(0) {
        unsafe {
            pop_program_state(ptr);
        }
    }
}

/// Pop the CPI stack. Uses explicit match on depth to satisfy the BPF verifier's
/// bounds checking (the verifier can't track array index arithmetic).
#[inline(always)]
unsafe fn pop_program_state(ptr: *mut ProgramState) {
    if (*ptr).depth > 0 {
        (*ptr).depth -= 1;
    }
    let depth = (*ptr).depth;
    match depth {
        1 => (*ptr).program_id = (*ptr).ids[0],
        2 => (*ptr).program_id = (*ptr).ids[1],
        3 => (*ptr).program_id = (*ptr).ids[2],
        4 => (*ptr).program_id = (*ptr).ids[3],
        _ => {
            (*ptr).program_id = [0u8; 32];
            if depth == 0 {
                (*ptr).in_sbf = 0;
            }
        }
    }
}

#[perf_event]
pub fn profile_cpu(ctx: PerfEventContext) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !check_pid(pid) {
        return;
    }

    let data = unsafe { &*ctx.as_ptr().cast::<aya_ebpf::bindings::bpf_perf_event_data>() };
    let cycles = data.sample_period;

    #[cfg(bpf_target_arch = "aarch64")]
    let (pc, sp, fp, lr) = unsafe {
        (data.regs.pc, data.regs.sp, data.regs.regs[29], data.regs.regs[30])
    };

    #[cfg(bpf_target_arch = "x86_64")]
    let (pc, sp, fp, lr) = unsafe {
        (data.regs.rip, data.regs.rsp, data.regs.rbp, 0u64)
    };

    // Read current program state
    let program_id = if let Some(state) = PROGRAM_STATE.get(0) {
        if state.in_sbf != 0 {
            state.program_id
        } else {
            [0u8; 32]
        }
    } else {
        [0u8; 32]
    };

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            (*ptr).pid = pid;
            (*ptr)._pad = 0;
            (*ptr).cpu_cycles = cycles;
            (*ptr).pc = pc;
            (*ptr).sp = sp;
            (*ptr).fp = fp;
            (*ptr).lr = lr;
            (*ptr).program_id = program_id;

            let stack_dst = core::ptr::addr_of_mut!((*ptr).stack_data) as *mut core::ffi::c_void;
            let ret = call_bpf_probe_read_user(
                stack_dst,
                STACK_DUMP_SIZE as u32,
                sp as *const core::ffi::c_void,
            );
            if ret == 0 {
                (*ptr).stack_size = STACK_DUMP_SIZE as u64;
            } else {
                (*ptr).stack_size = 0;
            }
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
