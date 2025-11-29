use aya::maps::{Array, RingBuf, StackTraceMap};
use aya::programs::perf_event::{
    PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
};
use inferno::flamegraph;
use object::{Object, ObjectSymbol, SymbolKind};
use profiler_common::Event;
use std::collections::HashMap;
use std::fs;
use std::io::BufWriter;
use tokio::io::unix::AsyncFd;
use tokio::signal;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let binary = get_arg(&args, "--binary");
    let target_pid: u32 = get_arg(&args, "--pid")
        .map(|s| s.parse().expect("--pid must be a number"))
        .unwrap_or(0);
    let output = get_arg(&args, "--output").unwrap_or_else(|| "flamegraph.svg".to_string());

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

    let mut resolvers: HashMap<String, SymbolResolver> = HashMap::new();
    if let Some(ref bin_path) = binary {
        match SymbolResolver::from_binary(bin_path) {
            Ok(r) => {
                resolvers.insert(bin_path.to_string(), r);
            }
            Err(e) => eprintln!("warning: could not load symbols from {}: {}", bin_path, e),
        }
    }

    let mut maps_cache: HashMap<u32, Vec<(u64, u64, u64, String)>> = HashMap::new();
    let mut folded: HashMap<String, u64> = HashMap::new();
    let mut sample_count: u64 = 0;

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
                        if event.stack_id >= 0 {
                            if let Ok(trace) = stacks.get(&(event.stack_id as u32), 0) {
                                let maps = maps_cache
                                    .entry(event.pid)
                                    .or_insert_with(|| parse_maps(event.pid));

                                let frames: Vec<_> = trace
                                    .frames()
                                    .iter()
                                    .take_while(|f| f.ip != 0)
                                    .collect();
                                let names: Vec<String> = frames
                                    .iter()
                                    .rev()
                                    .map(|f| resolve_addr(f.ip, maps, &resolvers))
                                    .collect();

                                if !names.is_empty() {
                                    let stack_str = names.join(";");
                                    *folded.entry(stack_str).or_insert(0) += event.cpu_cycles;
                                    sample_count += 1;
                                }
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

    let mut lines: Vec<String> = folded
        .iter()
        .map(|(stack, count)| format!("{} {}", stack, count))
        .collect();
    lines.sort();

    let folded_text = lines.join("\n");
    let reader = folded_text.as_bytes();

    let f = fs::File::create(&output)?;
    let writer = BufWriter::new(f);

    let mut opts = flamegraph::Options::default();
    opts.title = "solana-ebpf-profiler".to_string();
    flamegraph::from_reader(&mut opts, reader, writer)?;

    println!("wrote {}", output);
    Ok(())
}
