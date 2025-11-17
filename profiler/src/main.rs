use aya::maps::RingBuf;
use aya::programs::UProbe;
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

    let program: &mut UProbe = ebpf.program_mut("uprobe_readline").unwrap().try_into()?;
    program.load()?;
    program.attach("readline", "/bin/bash", None::<u32>)?;

    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    println!("uprobe attached, polling ring buffer...");

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
                        println!("uprobe hit: pid={}", event.pid);
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
