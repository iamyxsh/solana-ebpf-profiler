use aya::programs::UProbe;
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

    println!("uprobe attached to /bin/bash:readline");
    println!("run: sudo cat /sys/kernel/debug/tracing/trace_pipe");
    signal::ctrl_c().await?;
    println!("detaching...");

    Ok(())
}
