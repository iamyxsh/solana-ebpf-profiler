#[allow(dead_code)]
mod unwind;

use aya::maps::{Array, RingBuf};
use aya::programs::perf_event::{
    PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
};
use aya::programs::UProbe;
use inferno::flamegraph;
use object::{Object, ObjectSymbol, SymbolKind};
use profiler_common::Event;
use std::collections::HashMap;
use std::fs;
use std::io::BufWriter;
use tokio::io::unix::AsyncFd;
use tokio::signal;
use unwind::DwarfUnwinder;

struct SymbolResolver {
    symbols: Vec<(u64, u64, String)>,
}

impl SymbolResolver {
    fn from_binary(path: &str) -> anyhow::Result<Self> {
        let data = fs::read(path)?;
        let file = object::File::parse(&*data)?;
        let mut symbols: Vec<(u64, u64, String)> = file
            .symbols()
            .filter(|s| s.kind() == SymbolKind::Text && s.size() > 0)
            .map(|s| {
                (
                    s.address(),
                    s.size(),
                    s.name().unwrap_or("??").to_string(),
                )
            })
            .collect();
        symbols.sort_by_key(|s| s.0);
        println!("loaded {} symbols from {}", symbols.len(), path);
        Ok(Self { symbols })
    }

    fn resolve(&self, addr: u64) -> &str {
        match self.symbols.binary_search_by_key(&addr, |s| s.0) {
            Ok(i) => &self.symbols[i].2,
            Err(i) if i > 0 => {
                let s = &self.symbols[i - 1];
                if addr < s.0 + s.1 {
                    &s.2
                } else {
                    "??"
                }
            }
            _ => "??",
        }
    }
}

fn parse_maps(pid: u32) -> Vec<(u64, u64, u64, String)> {
    let path = format!("/proc/{}/maps", pid);
    let Ok(content) = fs::read_to_string(&path) else {
        return vec![];
    };
    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 || !parts[1].contains('x') {
                return None;
            }
            let addrs: Vec<&str> = parts[0].split('-').collect();
            let start = u64::from_str_radix(addrs[0], 16).ok()?;
            let end = u64::from_str_radix(addrs[1], 16).ok()?;
            let offset = u64::from_str_radix(parts[2], 16).ok()?;
            let path = parts[5].to_string();
            Some((start, end, offset, path))
        })
        .collect()
}

fn resolve_addr(
    addr: u64,
    maps: &[(u64, u64, u64, String)],
    resolvers: &HashMap<String, SymbolResolver>,
) -> String {
    for (start, end, offset, path) in maps {
        if addr >= *start && addr < *end {
            if let Some(resolver) = resolvers.get(path) {
                let file_offset = addr - start + offset;
                let name = resolver.resolve(file_offset);
                if name != "??" {
                    return name.to_string();
                }
            }
            return format!("{path}+0x{:x}", addr - start);
        }
    }
    format!("0x{addr:x}")
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .map(|i| args[i + 1].clone())
}

/// Scan an ELF binary for a symbol whose demangled-ish name contains all the given fragments.
/// Returns the raw (mangled) symbol name.
fn find_symbol(binary_path: &str, fragments: &[&str]) -> anyhow::Result<Vec<String>> {
    let data = fs::read(binary_path)?;
    let file = object::File::parse(&*data)?;
    let mut matches = Vec::new();
    for sym in file.symbols() {
        if sym.kind() != SymbolKind::Text || sym.size() == 0 {
            continue;
        }
        if let Ok(name) = sym.name() {
            if fragments.iter().all(|f| name.contains(f)) {
                matches.push(name.to_string());
            }
        }
    }
    Ok(matches)
}

fn format_program_id(id: &[u8; 32]) -> String {
    bs58::encode(id).into_string()
}

fn is_zero(id: &[u8; 32]) -> bool {
    id.iter().all(|b| *b == 0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let binary = get_arg(&args, "--binary");
    let validator_binary = get_arg(&args, "--validator-binary");
    let target_pid: u32 = get_arg(&args, "--pid")
        .map(|s| s.parse().expect("--pid must be a number"))
        .unwrap_or(0);
    let output = get_arg(&args, "--output").unwrap_or_else(|| "flamegraph.svg".to_string());
    let output_dir = get_arg(&args, "--output-dir");

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

    // Attach perf_event to all CPUs
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

    // Attach uprobes to validator binary if provided
    let mut has_program_ids = false;
    if let Some(ref vbin) = validator_binary {
        let pid_opt = if target_pid > 0 {
            Some(target_pid)
        } else {
            None
        };

        // Strategy 1: Try stable_log::program_invoke for full per-program attribution
        let invoke_syms = find_symbol(vbin, &["program_invoke"])?;
        let success_syms = find_symbol(vbin, &["program_success"])?;
        let failure_syms = find_symbol(vbin, &["program_failure"])?;

        if !invoke_syms.is_empty() && !success_syms.is_empty() {
            // Attach program_enter to program_invoke
            let uprobe: &mut UProbe =
                ebpf.program_mut("program_enter").unwrap().try_into()?;
            uprobe.load()?;
            uprobe.attach(invoke_syms[0].as_str(), vbin, pid_opt)?;
            println!("attached uprobe to {}", invoke_syms[0]);

            // Attach program_exit_ok to program_success
            let exit_ok: &mut UProbe =
                ebpf.program_mut("program_exit_ok").unwrap().try_into()?;
            exit_ok.load()?;
            exit_ok.attach(success_syms[0].as_str(), vbin, pid_opt)?;
            println!("attached uprobe to {}", success_syms[0]);

            // Attach program_exit_err to all program_failure monomorphizations
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
            println!("per-program attribution enabled via stable_log uprobes");
        } else {
            println!("stable_log symbols not found (may be inlined in release build)");
        }

        // Strategy 2: Always attach to vm::execute for [sbf]/[validator] tracking
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
            eprintln!("warning: could not find vm::execute symbol in {}", vbin);
        }
    }

    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    let mut resolvers: HashMap<String, SymbolResolver> = HashMap::new();
    // Load symbols from --binary
    if let Some(ref bin_path) = binary {
        match SymbolResolver::from_binary(bin_path) {
            Ok(r) => {
                resolvers.insert(bin_path.to_string(), r);
            }
            Err(e) => eprintln!("warning: could not load symbols from {}: {}", bin_path, e),
        }
    }
    // Also load symbols from --validator-binary if different
    if let Some(ref vbin) = validator_binary {
        if binary.as_deref() != Some(vbin.as_str()) {
            match SymbolResolver::from_binary(vbin) {
                Ok(r) => {
                    resolvers.insert(vbin.to_string(), r);
                }
                Err(e) => eprintln!("warning: could not load symbols from {}: {}", vbin, e),
            }
        }
    }

    let mut maps_cache: HashMap<u32, Vec<(u64, u64, u64, String)>> = HashMap::new();
    let mut folded: HashMap<String, u64> = HashMap::new();
    let mut per_program_folded: HashMap<[u8; 32], HashMap<String, u64>> = HashMap::new();
    let mut sample_count: u64 = 0;
    let mut unwinder = DwarfUnwinder::new();

    if target_pid > 0 {
        println!("profiling pid {} on {} cores...", target_pid, cpus.len());
    } else {
        println!("profiling all processes on {} cores...", cpus.len());
    }
    println!("press Ctrl+C to stop and generate {}", output);

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
                        let maps = maps_cache
                            .entry(event.pid)
                            .or_insert_with(|| parse_maps(event.pid));

                        let stack_data = if event.stack_size > 0 {
                            &event.stack_data[..event.stack_size as usize]
                        } else {
                            &[]
                        };

                        let addrs = unwinder.unwind(
                            event.pc,
                            event.sp,
                            event.fp,
                            event.lr,
                            stack_data,
                            event.sp,
                            maps,
                        );

                        if !addrs.is_empty() {
                            let names: Vec<String> = addrs
                                .iter()
                                .rev()
                                .map(|a| resolve_addr(*a, maps, &resolvers))
                                .collect();

                            let func_stack = names.join(";");

                            // Build the full stack string with program context prefix
                            let stack_str = if has_program_ids && !is_zero(&event.program_id) {
                                let pid_str = format_program_id(&event.program_id);
                                format!("{};{}", pid_str, func_stack)
                            } else if validator_binary.is_some() && !is_zero(&event.program_id) {
                                // in_sbf flag set but no program_id
                                format!("[sbf];{}", func_stack)
                            } else if validator_binary.is_some() {
                                format!("[validator];{}", func_stack)
                            } else {
                                func_stack.clone()
                            };

                            *folded.entry(stack_str).or_insert(0) += event.cpu_cycles;
                            sample_count += 1;

                            // Track per-program stacks
                            if has_program_ids && !is_zero(&event.program_id) {
                                let program_stacks =
                                    per_program_folded.entry(event.program_id).or_default();
                                *program_stacks.entry(func_stack).or_insert(0) +=
                                    event.cpu_cycles;
                            }
                        }
                    }
                }
                guard.clear_ready();
            }
        }
    }

    println!("collected {} samples", sample_count);

    if folded.is_empty() {
        println!("no samples collected, skipping flame graph");
        return Ok(());
    }

    // Generate combined flame graph
    write_flamegraph(&folded, &output, "solana-ebpf-profiler")?;
    println!("wrote {}", output);

    // Generate per-program flame graphs if we have program IDs
    if !per_program_folded.is_empty() {
        if let Some(ref dir) = output_dir {
            fs::create_dir_all(dir)?;
        }
        for (program_id, stacks) in &per_program_folded {
            let pid_str = format_program_id(program_id);
            let total_cycles: u64 = stacks.values().sum();
            let sample_cnt = stacks.len();
            let short_id = &pid_str[..pid_str.len().min(12)];

            let filename = if let Some(ref dir) = output_dir {
                format!("{}/{}.svg", dir, pid_str)
            } else {
                format!(
                    "{}-{}.svg",
                    output.trim_end_matches(".svg"),
                    short_id
                )
            };

            let title = format!("solana-ebpf-profiler: {}", short_id);
            write_flamegraph(stacks, &filename, &title)?;
            println!(
                "  {} — {} stacks, {} cycles",
                filename, sample_cnt, total_cycles
            );
        }
    }

    Ok(())
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
