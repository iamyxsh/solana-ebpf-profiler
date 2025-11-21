use aya::maps::{RingBuf, StackTraceMap};
use aya::programs::perf_event::{
    PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
};
use profiler_common::Event;
use tokio::io::unix::AsyncFd;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        eprintln!("failed to increase RLIMIT_MEMLOCK: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/profiler"
    )))?;

    let program: &mut PerfEvent = ebpf.program_mut("profile_cpu").unwrap().try_into()?;
    program.load()?;

    let cpus = aya::util::online_cpus().map_err(|(_, e)| e)?;
    for cpu in &cpus {
        program.attach(
            PerfEventConfig::Software(SoftwareEvent::CpuClock),
            PerfEventScope::AllProcessesOneCpu { cpu: *cpu },
            SamplePolicy::Period(100_000),
            true,
        )?;
    }

    let stacks = StackTraceMap::try_from(ebpf.take_map("STACKS").unwrap())?;
    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    println!("sampling CPU cycles on {} cores...", cpus.len());

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("detaching...");
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let rb: &mut RingBuf<_> = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() >= core::mem::size_of::<Event>() {
                        let event = unsafe { &*(item.as_ptr() as *const Event) };
                        if event.stack_id >= 0 {
                            if let Ok(trace) = stacks.get(&(event.stack_id as u32), 0) {
                                let addrs: Vec<u64> = trace.frames()
                                    .iter()
                                    .take_while(|f| f.ip != 0)
                                    .map(|f| f.ip)
                                    .collect();
                                println!(
                                    "pid={} cycles={} stack={:x?}",
                                    event.pid, event.cpu_cycles, addrs
                                );
                            }
                        }
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
