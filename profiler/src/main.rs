#[allow(dead_code)]
mod unwind;

use aya::maps::{Array, HashMap as BpfHashMap, RingBuf};
use aya::programs::perf_event::{
    PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
};
use aya::programs::UProbe;
use inferno::flamegraph;
use object::{Object, ObjectSymbol, SymbolKind};
use profiler_common::Event;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::BufWriter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::unix::AsyncFd;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::signal;
use unwind::DwarfUnwinder;

// ---------------------------------------------------------------------------
// Known program registry
// ---------------------------------------------------------------------------

fn build_known_programs() -> HashMap<[u8; 32], &'static str> {
    let entries: &[(&str, &str)] = &[
        ("11111111111111111111111111111111", "System Program"),
        ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "Token Program"),
        ("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "Associated Token"),
        ("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "Token-2022"),
        ("BPFLoaderUpgradeab1e11111111111111111111111", "BPF Loader"),
        ("BPFLoader2111111111111111111111111111111111", "BPF Loader v2"),
        ("ComputeBudget111111111111111111111111111111", "Compute Budget"),
        ("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "Memo v2"),
        ("Memo1UhkJBfCR1MNHSiotXyZdXFbczgWE7sXJdg3RX", "Memo v1"),
        ("AddressLookupTab1e1111111111111111111111111", "Address Lookup Table"),
        ("Vote111111111111111111111111111111111111111", "Vote Program"),
        ("Stake11111111111111111111111111111111111111", "Stake Program"),
        ("Config1111111111111111111111111111111111111", "Config Program"),
        ("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", "Raydium AMM v4"),
        ("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "Jupiter v6"),
        ("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", "Serum DEX v3"),
    ];
    let mut map = HashMap::new();
    for (b58, name) in entries {
        if let Ok(bytes) = bs58::decode(b58).into_vec() {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                map.insert(key, *name);
            }
        }
    }
    map
}

fn display_program(id: &[u8; 32], names: &HashMap<[u8; 32], &str>) -> String {
    if let Some(name) = names.get(id) {
        name.to_string()
    } else {
        let b58 = bs58::encode(id).into_string();
        format!("{}...{}", &b58[..4], &b58[b58.len() - 4..])
    }
}

fn slug_program(id: &[u8; 32], names: &HashMap<[u8; 32], &str>) -> String {
    if let Some(name) = names.get(id) {
        name.to_lowercase().replace(' ', "-")
    } else {
        bs58::encode(id).into_string()
    }
}

// ---------------------------------------------------------------------------
// Shared stats for the dashboard
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ProgramStat {
    name: String,
    pubkey: String,
    samples: u64,
    cpu_pct: f64,
    cycles: u64,
    invocations: u64,
}

struct DashboardState {
    programs: Vec<ProgramStat>,
    total_samples: u64,
    total_invocations: u64,
    uptime_secs: u64,
}

type SharedState = Arc<Mutex<DashboardState>>;

fn compute_stats(
    per_program: &HashMap<[u8; 32], HashMap<String, u64>>,
    invoke_counts: &HashMap<[u8; 32], u64>,
    total_samples: u64,
    total_cycles: u64,
    names: &HashMap<[u8; 32], &str>,
    uptime_secs: u64,
) -> DashboardState {
    // Merge per_program (from perf samples) with invoke_counts (from uprobes)
    let mut all_programs: HashMap<[u8; 32], (u64, u64, u64)> = HashMap::new(); // (cycles, samples, invocations)

    for (id, stacks) in per_program {
        let cycles: u64 = stacks.values().sum();
        let samples: u64 = stacks.values().count() as u64;
        let invocations = invoke_counts.get(id).copied().unwrap_or(0);
        all_programs.insert(*id, (cycles, samples, invocations));
    }

    // Add programs that have invocations but no perf samples
    for (id, count) in invoke_counts {
        all_programs.entry(*id).or_insert((0, 0, *count)).2 = *count;
    }

    let total_invocations: u64 = invoke_counts.values().sum();

    let mut programs: Vec<ProgramStat> = all_programs
        .iter()
        .map(|(id, (cycles, samples, invocations))| {
            let cpu_pct = if total_cycles > 0 {
                (*cycles as f64 / total_cycles as f64) * 100.0
            } else {
                0.0
            };
            ProgramStat {
                name: display_program(id, names),
                pubkey: bs58::encode(id).into_string(),
                samples: *samples,
                cpu_pct,
                cycles: *cycles,
                invocations: *invocations,
            }
        })
        .collect();
    programs.sort_by(|a, b| b.invocations.cmp(&a.invocations));

    // Add validator overhead
    let program_cycles: u64 = all_programs.values().map(|(c, _, _)| c).sum();
    let overhead_cycles = total_cycles.saturating_sub(program_cycles);
    if total_samples > 0 {
        let overhead_samples = total_samples.saturating_sub(programs.iter().map(|p| p.samples).sum::<u64>());
        programs.push(ProgramStat {
            name: "[validator]".to_string(),
            pubkey: "—".to_string(),
            samples: overhead_samples,
            cpu_pct: if total_cycles > 0 {
                (overhead_cycles as f64 / total_cycles as f64) * 100.0
            } else {
                0.0
            },
            cycles: overhead_cycles,
            invocations: 0,
        });
    }

    DashboardState {
        programs,
        total_samples,
        total_invocations,
        uptime_secs,
    }
}

fn read_invoke_counts(map: &BpfHashMap<&aya::maps::MapData, [u8; 32], u64>) -> HashMap<[u8; 32], u64> {
    let mut counts = HashMap::new();
    for res in map.iter() {
        if let Ok((key, val)) = res {
            counts.insert(key, val);
        }
    }
    counts
}

fn stats_to_json(state: &DashboardState) -> String {
    let programs_json: Vec<String> = state
        .programs
        .iter()
        .map(|p| {
            format!(
                r#"{{"name":"{}","pubkey":"{}","samples":{},"cpu_pct":{:.1},"cycles":{},"invocations":{}}}"#,
                p.name, p.pubkey, p.samples, p.cpu_pct, p.cycles, p.invocations
            )
        })
        .collect();
    format!(
        r#"{{"programs":[{}],"total_samples":{},"total_invocations":{},"uptime_secs":{}}}"#,
        programs_json.join(","),
        state.total_samples,
        state.total_invocations,
        state.uptime_secs
    )
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

async fn run_http_server(port: u16, state: SharedState) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind dashboard on {}: {}", addr, e);
            return;
        }
    };
    println!("dashboard: http://localhost:{}", port);

    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let Ok(n) = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await else {
                return;
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let first_line = request.lines().next().unwrap_or("");

            let (status, content_type, body) = if first_line.starts_with("GET /api/stats") {
                let s = state.lock().unwrap();
                let json = stats_to_json(&s);
                ("200 OK", "application/json", json)
            } else if first_line.starts_with("GET / ") || first_line == "GET / HTTP/1.1" || first_line.starts_with("GET /index") {
                ("200 OK", "text/html", DASHBOARD_HTML.to_string())
            } else {
                ("404 Not Found", "text/plain", "not found".to_string())
            };

            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                status,
                content_type,
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

// ---------------------------------------------------------------------------
// Dashboard HTML (React via CDN, no build step)
// ---------------------------------------------------------------------------

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Solana Validator Profiler</title>
<script src="https://unpkg.com/react@18/umd/react.production.min.js" crossorigin></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js" crossorigin></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;padding:24px}
h1{font-size:20px;font-weight:600;margin-bottom:4px;color:#f0f6fc}
.subtitle{color:#8b949e;font-size:13px;margin-bottom:24px}
.stats-row{display:flex;gap:16px;margin-bottom:24px}
.stat-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;min-width:140px}
.stat-card .label{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px}
.stat-card .value{font-size:28px;font-weight:600;color:#58a6ff;margin-top:4px}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
th{text-align:left;padding:10px 16px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #30363d;background:#0d1117}
td{padding:10px 16px;border-bottom:1px solid #21262d;font-size:14px}
tr:last-child td{border-bottom:none}
.bar-cell{width:40%}
.bar-bg{background:#21262d;border-radius:4px;height:22px;position:relative;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .5s ease}
.bar-label{position:absolute;right:8px;top:3px;font-size:12px;color:#c9d1d9;font-weight:500}
.program-name{font-weight:500;color:#f0f6fc}
.pubkey{font-size:11px;color:#484f58;font-family:monospace}
.validator-row{color:#8b949e;font-style:italic}
</style>
</head>
<body>
<div id="root"></div>
<script>
const e=React.createElement;
const COLORS=['#58a6ff','#3fb950','#d29922','#f85149','#bc8cff','#79c0ff','#56d364','#e3b341','#ff7b72','#d2a8ff'];

function App(){
  const[data,setData]=React.useState(null);
  React.useEffect(()=>{
    const poll=()=>fetch('/api/stats').then(r=>r.json()).then(setData).catch(()=>{});
    poll();
    const id=setInterval(poll,1000);
    return()=>clearInterval(id);
  },[]);
  if(!data)return e('div',null,'connecting...');
  const progs=data.programs||[];
  const maxPct=100;
  return e('div',null,
    e('h1',null,'Solana Validator Profiler'),
    e('div',{className:'subtitle'},'Live per-program CPU usage'),
    e('div',{className:'stats-row'},
      e('div',{className:'stat-card'},
        e('div',{className:'label'},'Total Samples'),
        e('div',{className:'value'},data.total_samples.toLocaleString())
      ),
      e('div',{className:'stat-card'},
        e('div',{className:'label'},'Uptime'),
        e('div',{className:'value'},formatTime(data.uptime_secs))
      ),
      e('div',{className:'stat-card'},
        e('div',{className:'label'},'Invocations'),
        e('div',{className:'value'},(data.total_invocations||0).toLocaleString())
      ),
      e('div',{className:'stat-card'},
        e('div',{className:'label'},'Programs'),
        e('div',{className:'value'},progs.filter(p=>p.name!=='[validator]').length)
      )
    ),
    e('table',null,
      e('thead',null,e('tr',null,
        e('th',null,'Program'),
        e('th',null,'Invocations'),
        e('th',null,'CPU %'),
        e('th',{className:'bar-cell'},''),
        e('th',null,'Samples'),
        e('th',null,'Cycles')
      )),
      e('tbody',null,progs.map((p,i)=>
        e('tr',{key:i,className:p.name==='[validator]'?'validator-row':''},
          e('td',null,
            e('div',{className:'program-name'},p.name),
            p.pubkey!=='—'?e('div',{className:'pubkey'},p.pubkey.slice(0,16)+'...'):null
          ),
          e('td',null,(p.invocations||0).toLocaleString()),
          e('td',null,p.cpu_pct.toFixed(1)+'%'),
          e('td',{className:'bar-cell'},
            e('div',{className:'bar-bg'},
              e('div',{className:'bar-fill',style:{width:(p.cpu_pct/maxPct*100)+'%',background:COLORS[i%COLORS.length]}}),
              e('span',{className:'bar-label'},p.cpu_pct.toFixed(1)+'%')
            )
          ),
          e('td',null,p.samples.toLocaleString()),
          e('td',null,p.cycles.toLocaleString())
        )
      ))
    )
  );
}
function formatTime(s){
  if(s<60)return s+'s';
  if(s<3600)return Math.floor(s/60)+'m '+s%60+'s';
  return Math.floor(s/3600)+'h '+Math.floor(s%3600/60)+'m';
}
ReactDOM.createRoot(document.getElementById('root')).render(e(App));
</script>
</body>
</html>"##;

// ---------------------------------------------------------------------------
// Symbol resolution (unchanged)
// ---------------------------------------------------------------------------

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

fn is_zero(id: &[u8; 32]) -> bool {
    id.iter().all(|b| *b == 0)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Demo mode — simulates a mainnet validator with popular programs
// ---------------------------------------------------------------------------

async fn run_demo(port: u16) -> anyhow::Result<()> {
    let known = build_known_programs();

    // Simulated mainnet program profiles (name, base invocations/s, cpu_pct)
    let programs: Vec<(&str, f64, f64)> = vec![
        ("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", 320.0, 18.5),
        ("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", 280.0, 14.2),
        ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", 1200.0, 8.7),
        ("11111111111111111111111111111111", 2400.0, 5.3),
        ("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", 600.0, 3.1),
        ("ComputeBudget111111111111111111111111111111", 3800.0, 1.8),
        ("Vote111111111111111111111111111111111111111", 150.0, 6.4),
        ("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", 85.0, 2.9),
        ("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", 45.0, 1.6),
        ("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", 190.0, 0.4),
    ];

    let validator_cpu_pct: f64 = 100.0 - programs.iter().map(|(_, _, c)| c).sum::<f64>();

    let state: SharedState = Arc::new(Mutex::new(DashboardState {
        programs: vec![],
        total_samples: 0,
        total_invocations: 0,
        uptime_secs: 0,
    }));

    {
        let s = state.clone();
        tokio::spawn(async move { run_http_server(port, s).await });
    }

    println!("demo mode: simulating mainnet validator");
    println!("dashboard: http://localhost:{}", port);

    let start = std::time::Instant::now();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        r.store(false, Ordering::Relaxed);
    });

    while running.load(Ordering::Relaxed) {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let elapsed = start.elapsed().as_secs();
        let jitter = || 0.85 + (elapsed % 7) as f64 * 0.05; // subtle variation

        let total_samples = (elapsed as f64 * 160.0 * jitter()) as u64;
        let total_cycles = total_samples * 100_000;

        let mut stats: Vec<ProgramStat> = programs
            .iter()
            .map(|(b58, base_inv, cpu)| {
                let bytes = bs58::decode(b58).into_vec().unwrap();
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                let invocations = (elapsed as f64 * base_inv * jitter()) as u64;
                let samples = (total_samples as f64 * cpu / 100.0) as u64;
                ProgramStat {
                    name: display_program(&key, &known),
                    pubkey: b58.to_string(),
                    samples,
                    cpu_pct: *cpu * jitter() / jitter(),
                    cycles: samples * 100_000,
                    invocations,
                }
            })
            .collect();

        stats.sort_by(|a, b| b.invocations.cmp(&a.invocations));

        let program_samples: u64 = stats.iter().map(|p| p.samples).sum();
        stats.push(ProgramStat {
            name: "[validator]".to_string(),
            pubkey: "—".to_string(),
            samples: total_samples.saturating_sub(program_samples),
            cpu_pct: validator_cpu_pct,
            cycles: (total_cycles as f64 * validator_cpu_pct / 100.0) as u64,
            invocations: 0,
        });

        let total_inv = stats.iter().map(|p| p.invocations).sum();

        *state.lock().unwrap() = DashboardState {
            programs: stats,
            total_samples,
            total_invocations: total_inv,
            uptime_secs: elapsed,
        };
    }

    println!("demo stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--demo") {
        let port: u16 = get_arg(&args, "--port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(3000);
        return run_demo(port).await;
    }

    let output = get_arg(&args, "--output").unwrap_or_else(|| "flamegraph.svg".to_string());
    let mut output_dir = get_arg(&args, "--output-dir");
    let port: u16 = get_arg(&args, "--port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let duration: Option<u64> = get_arg(&args, "--duration").and_then(|s| s.parse().ok());
    let sample_period_arg: Option<u64> = get_arg(&args, "--period").and_then(|s| s.parse().ok());

    let known_programs = build_known_programs();

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
        println!("profiling pid {} ({} threads) on {} cores...", target_pid, tids.len(), cpus.len());
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
    let shared_state: SharedState = Arc::new(Mutex::new(DashboardState {
        programs: vec![],
        total_samples: 0,
        total_invocations: 0,
        uptime_secs: 0,
    }));
    {
        let state = shared_state.clone();
        tokio::spawn(async move {
            run_http_server(port, state).await;
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
                    let state = compute_stats(
                        &per_program_folded, &ic, sample_count, total_cycles,
                        &known_programs, start.elapsed().as_secs(),
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
                    event.pc, event.sp, event.fp, event.lr,
                    stack_data, event.sp, maps,
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
            let state = compute_stats(
                &per_program_folded, &ic, sample_count, total_cycles,
                &known_programs, start.elapsed().as_secs(),
            );
            *shared_state.lock().unwrap() = state;
            last_stats_update = std::time::Instant::now();
        }
    }
    let invoke_counts = read_invoke_counts(&invoke_map);
    let total_invocations: u64 = invoke_counts.values().sum();
    println!("detaching...");
    println!("collected {} samples, {} program invocations in {}s", sample_count, total_invocations, start.elapsed().as_secs());

    // Print summary table
    if sample_count > 0 || total_invocations > 0 {
        println!("\n{:<28} {:>10} {:>8} {:>7} {:>14}", "Program", "Invocations", "Samples", "CPU%", "Cycles");
        println!("{}", "─".repeat(72));
        let final_state = compute_stats(&per_program_folded, &invoke_counts, sample_count, total_cycles, &known_programs, start.elapsed().as_secs());
        for p in &final_state.programs {
            println!("{:<28} {:>10} {:>8} {:>6.1}% {:>14}", p.name, p.invocations, p.samples, p.cpu_pct, p.cycles);
        }
        println!("{}", "─".repeat(72));
        println!("{:<28} {:>10} {:>8} {:>7} {:>14}", "Total", total_invocations, sample_count, "100.0%", total_cycles);
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
            println!("  {} — {} stacks, {} cycles", filename, stacks.len(), total_cycles);
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
