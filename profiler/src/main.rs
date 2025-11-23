use aya::maps::{RingBuf, StackTraceMap};
use aya::programs::perf_event::{
    PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
};
use object::{Object, ObjectSymbol, SymbolKind};
use profiler_common::Event;
use std::collections::HashMap;
use std::fs;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let binary = args.iter().position(|a| a == "--binary").map(|i| &args[i + 1]);

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

    let mut resolvers: HashMap<String, SymbolResolver> = HashMap::new();
    if let Some(bin_path) = binary {
        match SymbolResolver::from_binary(bin_path) {
            Ok(r) => {
                resolvers.insert(bin_path.to_string(), r);
            }
            Err(e) => eprintln!("warning: could not load symbols from {}: {}", bin_path, e),
        }
    }

    let mut maps_cache: HashMap<u32, Vec<(u64, u64, u64, String)>> = HashMap::new();

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
                                let maps = maps_cache
                                    .entry(event.pid)
                                    .or_insert_with(|| parse_maps(event.pid));

                                let names: Vec<String> = trace
                                    .frames()
                                    .iter()
                                    .take_while(|f| f.ip != 0)
                                    .map(|f| resolve_addr(f.ip, maps, &resolvers))
                                    .collect();

                                println!(
                                    "pid={} cycles={} stack={}",
                                    event.pid,
                                    event.cpu_cycles,
                                    names.join(";")
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
