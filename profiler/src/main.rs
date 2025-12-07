#[allow(dead_code)]
mod unwind;
mod dashboard;
mod demo;
mod programs;
mod symbols;

use aya::maps::{Array, HashMap as BpfHashMap, RingBuf};
use aya::programs::perf_event::{
    PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
};
use aya::programs::UProbe;
use inferno::flamegraph;
use profiler_common::Event;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::BufWriter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::signal;
use unwind::DwarfUnwinder;

use dashboard::{compute_stats, SharedState};
use programs::{build_known_programs, display_program, is_zero, slug_program};
use symbols::{find_symbol, parse_maps, resolve_addr, SymbolResolver};

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .map(|i| args[i + 1].clone())
}

fn detect_validator() -> anyhow::Result<(u32, String)> {
    let names = ["agave-validator", "solana-test-validator"];
    for entry in fs::read_dir("/proc")?.flatten() {
        let pid_str = entry.file_name();
        let Ok(pid) = pid_str.to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(exe) = fs::read_link(format!("/proc/{}/exe", pid)) else {
            continue;
        };
        let name = exe
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if names.iter().any(|n| name == *n) {
            return Ok((pid, exe.to_string_lossy().to_string()));
        }
    }
    anyhow::bail!(
        "no running agave-validator or solana-test-validator found.\n\
         start one, or pass --pid and --validator-binary manually."
    )
}

fn read_invoke_counts(
    map: &BpfHashMap<&aya::maps::MapData, [u8; 32], u64>,
) -> HashMap<[u8; 32], u64> {
    let mut counts = HashMap::new();
    for res in map.iter() {
        if let Ok((key, val)) = res {
            counts.insert(key, val);
        }
    }
    counts
}

fn write_flamegraph(
    folded: &HashMap<String, u64>,
    output: &str,
    title: &str,
) -> anyhow::Result<()> {
    let mut lines: Vec<String> = folded
        .iter()
        .map(|(stack, count)| format!("{} {}", stack, count))
        .collect();
    lines.sort();

    let folded_text = lines.join("\n");
    let reader = folded_text.as_bytes();

    let f = fs::File::create(output)?;
    let writer = BufWriter::new(f);

    let mut opts = flamegraph::Options::default();
    opts.title = title.to_string();
    flamegraph::from_reader(&mut opts, reader, writer)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn print_help() {
    println!(
        r#"solana-ebpf-profiler — eBPF-based per-program CPU profiler for Solana validators

USAGE:
    profiler [OPTIONS]

OPTIONS:
    --pid <PID>                Target process ID (auto-detected if omitted)
    --validator-binary <PATH>  Path to agave-validator binary (auto-detected)
    --binary <PATH>            Binary for symbol resolution
    --duration <SECS>          Stop after N seconds
    --period <N>               Perf sample period (default: 100000, lower = more samples)
    --port <PORT>              Dashboard HTTP port (default: 3000)
    --output <FILE>            Flamegraph output file (default: flamegraph.svg)
    --output-dir <DIR>         Directory for per-program flamegraphs
    --programs <FILE>          JSON file with program IDs and names (see programs.json)
    --demo                     Run with simulated mainnet data (no sudo needed)
    --help                     Print this help message

PROGRAMS FILE FORMAT (--programs):
    {{
      "programs": [
        {{ "pubkey": "base58...", "name": "Human Name" }},
        ...
      ]
    }}

EXAMPLES:
    profiler                                      # auto-detect validator, profile until Ctrl+C
    profiler --duration 60 --period 50000         # 60 seconds, aggressive sampling
    profiler --programs my-programs.json          # custom program list
    profiler --demo --port 8080                   # simulated demo on port 8080"#
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }

    if args.iter().any(|a| a == "--demo") {
        let port: u16 = get_arg(&args, "--port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(3000);
        let programs_file = get_arg(&args, "--programs");
        return demo::run_demo(port, programs_file.as_deref()).await;
    }

    let output = get_arg(&args, "--output").unwrap_or_else(|| "flamegraph.svg".to_string());
    let mut output_dir = get_arg(&args, "--output-dir");
    let port: u16 = get_arg(&args, "--port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let duration: Option<u64> = get_arg(&args, "--duration").and_then(|s| s.parse().ok());
    let sample_period_arg: Option<u64> = get_arg(&args, "--period").and_then(|s| s.parse().ok());
    let programs_file = get_arg(&args, "--programs");

    let known_programs = build_known_programs(programs_file.as_deref());

    let pid_arg = get_arg(&args, "--pid");
    let vbin_arg = get_arg(&args, "--validator-binary");
    let bin_arg = get_arg(&args, "--binary");

    let (target_pid, validator_pid, validator_binary, binary) = match (&pid_arg, &vbin_arg) {
        (None, None) => {
            println!("no --pid or --validator-binary specified, auto-detecting...");
            match detect_validator() {
                Ok((pid, binary_path)) => {
                    println!("detected validator: pid={}, binary={}", pid, binary_path);
                    let bin = bin_arg.unwrap_or_else(|| binary_path.clone());
                    (pid, Some(pid), Some(binary_path), Some(bin))
                }
                Err(e) => {
                    eprintln!("auto-detection failed: {}", e);
                    (0u32, None, None, bin_arg)
                }
            }
        }
        (Some(pid_str), Some(vbin)) => {
            let pid: u32 = pid_str.parse().expect("--pid must be a number");
            let bin = bin_arg.unwrap_or_else(|| vbin.clone());
            (pid, Some(pid), Some(vbin.clone()), Some(bin))
        }
        (Some(pid_str), None) => {
            let pid: u32 = pid_str.parse().expect("--pid must be a number");
            (pid, None, None, bin_arg)
        }
        (None, Some(vbin)) => {
            let vpid = detect_validator().map(|(p, _)| p).ok();
            let bin = bin_arg.unwrap_or_else(|| vbin.clone());
            (0, vpid, Some(vbin.clone()), Some(bin))
        }
    };

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

    let mut pid_map: Array<_, u32> =
        Array::try_from(ebpf.map_mut("TARGET_PID").unwrap())?;
    pid_map.set(0, target_pid, 0)?;

    // Attach perf_event
    let program: &mut PerfEvent = ebpf.program_mut("profile_cpu").unwrap().try_into()?;
    program.load()?;

    let cpus = aya::util::online_cpus().map_err(|(_, e)| e)?;
    let sample_period = sample_period_arg.unwrap_or(100_000);
    for cpu in &cpus {
        program.attach(
            PerfEventConfig::Software(SoftwareEvent::CpuClock),
            PerfEventScope::AllProcessesOneCpu { cpu: *cpu },
            SamplePolicy::Period(sample_period),
            true,
        )?;
    }

    // Attach uprobes to validator binary if provided
    let mut has_program_ids = false;
    if let Some(ref vbin) = validator_binary {
        let pid_opt = validator_pid;

        let invoke_syms = find_symbol(vbin, &["program_invoke"])?;
        let success_syms = find_symbol(vbin, &["program_success"])?;
        let failure_syms = find_symbol(vbin, &["program_failure"])?;

        if !invoke_syms.is_empty() && !success_syms.is_empty() {
            let uprobe: &mut UProbe =
                ebpf.program_mut("program_enter").unwrap().try_into()?;
            uprobe.load()?;
            uprobe.attach(invoke_syms[0].as_str(), vbin, pid_opt)?;
            println!("attached uprobe to {}", invoke_syms[0]);

            let exit_ok: &mut UProbe =
                ebpf.program_mut("program_exit_ok").unwrap().try_into()?;
            exit_ok.load()?;
            exit_ok.attach(success_syms[0].as_str(), vbin, pid_opt)?;
            println!("attached uprobe to {}", success_syms[0]);

            if !failure_syms.is_empty() {
                let exit_err: &mut UProbe =
                    ebpf.program_mut("program_exit_err").unwrap().try_into()?;
                exit_err.load()?;
                for sym in &failure_syms {
                    match exit_err.attach(sym.as_str(), vbin, pid_opt) {
                        Ok(_) => println!("attached uprobe to {}", sym),
                        Err(e) => eprintln!("warning: failed to attach to {}: {}", sym, e),
                    }
                }
            }

            has_program_ids = true;
            if output_dir.is_none() {
                output_dir = Some("flamegraphs".to_string());
            }
            println!("per-program attribution enabled via stable_log uprobes");
        } else {
            println!("stable_log symbols not found (may be inlined in release build)");
        }

        let execute_syms = find_symbol(vbin, &["program_runtime", "execute"])?;
        if let Some(sym) = execute_syms.first() {
            let vm_entry: &mut UProbe =
                ebpf.program_mut("vm_entry").unwrap().try_into()?;
            vm_entry.load()?;
            vm_entry.attach(sym.as_str(), vbin, pid_opt)?;
            println!("attached uprobe to vm::execute ({})", sym);

            let vm_exit: &mut UProbe =
                ebpf.program_mut("vm_exit").unwrap().try_into()?;
            vm_exit.load()?;
            vm_exit.attach(sym.as_str(), vbin, pid_opt)?;
            println!("attached uretprobe to vm::execute");
        } else {
            eprintln!("warning: could not find vm::execute symbol");
        }
    }

    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut async_fd = AsyncFd::new(ring_buf)?;
    let invoke_map: BpfHashMap<_, [u8; 32], u64> =
        BpfHashMap::try_from(ebpf.map("INVOKE_COUNTS").unwrap())?;

    let mut resolvers: HashMap<String, SymbolResolver> = HashMap::new();
    if let Some(ref bin_path) = binary {
        if let Ok(r) = SymbolResolver::from_binary(bin_path) {
            resolvers.insert(bin_path.to_string(), r);
        }
    }
    if let Some(ref vbin) = validator_binary {
        if binary.as_deref() != Some(vbin.as_str()) {
            if let Ok(r) = SymbolResolver::from_binary(vbin) {
                resolvers.insert(vbin.to_string(), r);
            }
        }
    }

    let mut maps_cache: HashMap<u32, Vec<(u64, u64, u64, String)>> = HashMap::new();
    let mut folded: HashMap<String, u64> = HashMap::new();
    let mut per_program_folded: HashMap<[u8; 32], HashMap<String, u64>> = HashMap::new();
    let mut sample_count: u64 = 0;
    let mut total_cycles: u64 = 0;
    let mut unwinder = DwarfUnwinder::new();

    let target_tids: HashSet<u32> = if target_pid > 0 {
        let mut tids = HashSet::new();
        tids.insert(target_pid);
        let task_dir = format!("/proc/{}/task", target_pid);
        if let Ok(entries) = fs::read_dir(&task_dir) {
            for entry in entries.flatten() {
                if let Ok(tid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    tids.insert(tid);
                }
            }
        }
        println!(
            "profiling pid {} ({} threads) on {} cores...",
            target_pid,
            tids.len(),
            cpus.len()
        );
        tids
    } else {
        println!("profiling all processes on {} cores...", cpus.len());
        HashSet::new()
    };

    if let Some(dur) = duration {
        println!("will stop after {} seconds", dur);
    }
    println!("press Ctrl+C to stop");

    // Start dashboard server
    let shared_state: SharedState = dashboard::new_shared_state();
    {
        let state = shared_state.clone();
        tokio::spawn(async move {
            dashboard::run_http_server(port, state).await;
        });
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        r.store(false, Ordering::Relaxed);
    });

    let start = std::time::Instant::now();
    let mut last_stats_update = std::time::Instant::now();

    while running.load(Ordering::Relaxed) {
        if let Some(dur) = duration {
            if start.elapsed().as_secs() >= dur {
                break;
            }
        }

        let mut guard = async_fd.readable_mut().await?;
        let rb: &mut RingBuf<_> = guard.get_inner_mut();
        let mut batch = 0u32;
        while let Some(item) = rb.next() {
            batch += 1;
            if batch % 1000 == 0 {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(dur) = duration {
                    if start.elapsed().as_secs() >= dur {
                        running.store(false, Ordering::Relaxed);
                        break;
                    }
                }
                // Update dashboard stats periodically
                if last_stats_update.elapsed().as_secs() >= 1 {
                    let ic = read_invoke_counts(&invoke_map);
                    let prev = { shared_state.lock().unwrap().prev_cpu.clone() };
                    let state = compute_stats(
                        &per_program_folded,
                        &ic,
                        sample_count,
                        total_cycles,
                        &known_programs,
                        start.elapsed().as_secs(),
                        &prev,
                    );
                    *shared_state.lock().unwrap() = state;
                    last_stats_update = std::time::Instant::now();
                }
            }
            if item.len() >= core::mem::size_of::<Event>() {
                let event = unsafe { &*(item.as_ptr() as *const Event) };
                if !target_tids.is_empty() && !target_tids.contains(&event.pid) {
                    continue;
                }
                let maps = maps_cache
                    .entry(event.pid)
                    .or_insert_with(|| parse_maps(event.pid));

                let stack_data = if event.stack_size > 0 {
                    &event.stack_data[..event.stack_size as usize]
                } else {
                    &[]
                };

                let addrs = unwinder.unwind(
                    event.pc, event.sp, event.fp, event.lr, stack_data, event.sp, maps,
                );

                if !addrs.is_empty() {
                    let names: Vec<String> = addrs
                        .iter()
                        .rev()
                        .map(|a| resolve_addr(*a, maps, &resolvers))
                        .collect();
                    let func_stack = names.join(";");

                    let stack_str = if has_program_ids && !is_zero(&event.program_id) {
                        let name = display_program(&event.program_id, &known_programs);
                        format!("{};{}", name, func_stack)
                    } else if validator_binary.is_some() && !is_zero(&event.program_id) {
                        format!("[sbf];{}", func_stack)
                    } else if validator_binary.is_some() {
                        format!("[validator];{}", func_stack)
                    } else {
                        func_stack.clone()
                    };

                    *folded.entry(stack_str).or_insert(0) += event.cpu_cycles;
                    sample_count += 1;
                    total_cycles += event.cpu_cycles;

                    if has_program_ids && !is_zero(&event.program_id) {
                        let program_stacks =
                            per_program_folded.entry(event.program_id).or_default();
                        *program_stacks.entry(func_stack).or_insert(0) += event.cpu_cycles;
                    }
                }
            }
        }
        guard.clear_ready();

        // Update dashboard stats every second
        if last_stats_update.elapsed().as_secs() >= 1 {
            let ic = read_invoke_counts(&invoke_map);
            let prev = { shared_state.lock().unwrap().prev_cpu.clone() };
            let state = compute_stats(
                &per_program_folded,
                &ic,
                sample_count,
                total_cycles,
                &known_programs,
                start.elapsed().as_secs(),
                &prev,
            );
            *shared_state.lock().unwrap() = state;
            last_stats_update = std::time::Instant::now();
        }
    }
    let invoke_counts = read_invoke_counts(&invoke_map);
    let total_invocations: u64 = invoke_counts.values().sum();
    println!("detaching...");
    println!(
        "collected {} samples, {} program invocations in {}s",
        sample_count,
        total_invocations,
        start.elapsed().as_secs()
    );

    // Print summary table
    if sample_count > 0 || total_invocations > 0 {
        println!(
            "\n{:<28} {:>10} {:>8} {:>7} {:>14}",
            "Program", "Invocations", "Samples", "CPU%", "Cycles"
        );
        println!("{}", "\u{2500}".repeat(72));
        let prev = { shared_state.lock().unwrap().prev_cpu.clone() };
        let final_state = compute_stats(
            &per_program_folded,
            &invoke_counts,
            sample_count,
            total_cycles,
            &known_programs,
            start.elapsed().as_secs(),
            &prev,
        );
        for p in &final_state.programs {
            println!(
                "{:<28} {:>10} {:>8} {:>6.1}% {:>14}",
                p.name, p.invocations, p.samples, p.cpu_pct, p.cycles
            );
        }
        println!("{}", "\u{2500}".repeat(72));
        println!(
            "{:<28} {:>10} {:>8} {:>7} {:>14}",
            "Total", total_invocations, sample_count, "100.0%", total_cycles
        );
    }

    if folded.is_empty() {
        println!("no samples collected, skipping flame graph");
        return Ok(());
    }

    write_flamegraph(&folded, &output, "solana-ebpf-profiler")?;
    println!("\nwrote {}", output);

    if !per_program_folded.is_empty() {
        if let Some(ref dir) = output_dir {
            fs::create_dir_all(dir)?;
        }
        for (program_id, stacks) in &per_program_folded {
            let name = display_program(program_id, &known_programs);
            let slug = slug_program(program_id, &known_programs);

            let filename = if let Some(ref dir) = output_dir {
                format!("{}/{}.svg", dir, slug)
            } else {
                format!("{}-{}.svg", output.trim_end_matches(".svg"), slug)
            };

            let title = format!("solana-ebpf-profiler: {}", name);
            write_flamegraph(stacks, &filename, &title)?;
            let total_cycles: u64 = stacks.values().sum();
            println!(
                "  {} \u{2014} {} stacks, {} cycles",
                filename,
                stacks.len(),
                total_cycles
            );
        }
    }

    Ok(())
}
