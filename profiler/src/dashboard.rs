use crate::programs::display_program;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct ProgramStat {
    pub name: String,
    pub pubkey: String,
    pub samples: u64,
    pub cpu_pct: f64,
    pub cycles: u64,
    pub invocations: u64,
    pub inv_per_sec: f64,
    pub avg_cu_per_inv: f64,
    pub cpu_pct_delta: f64,
}

pub struct DashboardState {
    pub programs: Vec<ProgramStat>,
    pub total_samples: u64,
    pub total_invocations: u64,
    pub uptime_secs: u64,
    pub samples_per_sec: f64,
    pub tps: f64,
    pub prev_cpu: HashMap<String, f64>,
}

pub type SharedState = Arc<Mutex<DashboardState>>;

pub fn new_shared_state() -> SharedState {
    Arc::new(Mutex::new(DashboardState {
        programs: vec![],
        total_samples: 0,
        total_invocations: 0,
        uptime_secs: 0,
        samples_per_sec: 0.0,
        tps: 0.0,
        prev_cpu: HashMap::new(),
    }))
}

pub fn compute_stats(
    per_program: &HashMap<[u8; 32], HashMap<String, u64>>,
    invoke_counts: &HashMap<[u8; 32], u64>,
    total_samples: u64,
    total_cycles: u64,
    names: &HashMap<[u8; 32], String>,
    uptime_secs: u64,
    prev_cpu: &HashMap<String, f64>,
) -> DashboardState {
    let mut all_programs: HashMap<[u8; 32], (u64, u64, u64)> = HashMap::new();

    for (id, stacks) in per_program {
        let cycles: u64 = stacks.values().sum();
        let samples: u64 = stacks.values().count() as u64;
        let invocations = invoke_counts.get(id).copied().unwrap_or(0);
        all_programs.insert(*id, (cycles, samples, invocations));
    }

    for (id, count) in invoke_counts {
        all_programs.entry(*id).or_insert((0, 0, *count)).2 = *count;
    }

    let total_invocations: u64 = invoke_counts.values().sum();
    let elapsed = if uptime_secs > 0 { uptime_secs as f64 } else { 1.0 };
    let tps = total_invocations as f64 / elapsed;
    let samples_per_sec = total_samples as f64 / elapsed;

    let mut programs: Vec<ProgramStat> = all_programs
        .iter()
        .map(|(id, (cycles, samples, invocations))| {
            let cpu_pct = if total_cycles > 0 {
                (*cycles as f64 / total_cycles as f64) * 100.0
            } else {
                0.0
            };
            let name = display_program(id, names);
            let inv_per_sec = *invocations as f64 / elapsed;
            let avg_cu_per_inv = if *invocations > 0 {
                *cycles as f64 / *invocations as f64
            } else {
                0.0
            };
            let cpu_pct_delta = cpu_pct - prev_cpu.get(&name).copied().unwrap_or(cpu_pct);
            ProgramStat {
                name,
                pubkey: bs58::encode(id).into_string(),
                samples: *samples,
                cpu_pct,
                cycles: *cycles,
                invocations: *invocations,
                inv_per_sec,
                avg_cu_per_inv,
                cpu_pct_delta,
            }
        })
        .collect();
    programs.sort_by(|a, b| b.invocations.cmp(&a.invocations));

    // Add validator overhead
    let program_cycles: u64 = all_programs.values().map(|(c, _, _)| c).sum();
    let overhead_cycles = total_cycles.saturating_sub(program_cycles);
    if total_samples > 0 {
        let overhead_samples =
            total_samples.saturating_sub(programs.iter().map(|p| p.samples).sum::<u64>());
        let overhead_pct = if total_cycles > 0 {
            (overhead_cycles as f64 / total_cycles as f64) * 100.0
        } else {
            0.0
        };
        let delta =
            overhead_pct - prev_cpu.get("[validator]").copied().unwrap_or(overhead_pct);
        programs.push(ProgramStat {
            name: "[validator]".to_string(),
            pubkey: "\u{2014}".to_string(),
            samples: overhead_samples,
            cpu_pct: overhead_pct,
            cycles: overhead_cycles,
            invocations: 0,
            inv_per_sec: 0.0,
            avg_cu_per_inv: 0.0,
            cpu_pct_delta: delta,
        });
    }

    let new_prev: HashMap<String, f64> =
        programs.iter().map(|p| (p.name.clone(), p.cpu_pct)).collect();

    DashboardState {
        programs,
        total_samples,
        total_invocations,
        uptime_secs,
        samples_per_sec,
        tps,
        prev_cpu: new_prev,
    }
}

pub fn stats_to_json(state: &DashboardState) -> String {
    let programs_json: Vec<String> = state
        .programs
        .iter()
        .map(|p| {
            format!(
                r#"{{"name":"{}","pubkey":"{}","samples":{},"cpu_pct":{:.2},"cycles":{},"invocations":{},"inv_per_sec":{:.1},"avg_cu":{:.0},"cpu_delta":{:.2}}}"#,
                p.name, p.pubkey, p.samples, p.cpu_pct, p.cycles, p.invocations,
                p.inv_per_sec, p.avg_cu_per_inv, p.cpu_pct_delta
            )
        })
        .collect();
    format!(
        r#"{{"programs":[{}],"total_samples":{},"total_invocations":{},"uptime_secs":{},"samples_per_sec":{:.1},"tps":{:.1}}}"#,
        programs_json.join(","),
        state.total_samples,
        state.total_invocations,
        state.uptime_secs,
        state.samples_per_sec,
        state.tps
    )
}

pub async fn run_http_server(port: u16, state: SharedState) {
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

            let (status, content_type, body) =
                if first_line.starts_with("GET /api/stats") {
                    let s = state.lock().unwrap();
                    let json = stats_to_json(&s);
                    ("200 OK", "application/json", json)
                } else if first_line.starts_with("GET / ")
                    || first_line == "GET / HTTP/1.1"
                    || first_line.starts_with("GET /index")
                {
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

pub const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
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
.stats-row{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
.stat-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;min-width:130px;flex:1}
.stat-card .label{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px}
.stat-card .value{font-size:26px;font-weight:600;color:#58a6ff;margin-top:4px;font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
th{text-align:left;padding:10px 16px;font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #30363d;background:#0d1117;position:sticky;top:0}
td{padding:10px 16px;border-bottom:1px solid #21262d;font-size:14px;font-variant-numeric:tabular-nums}
tr:last-child td{border-bottom:none}
tr:hover{background:#1c2128}
.bar-cell{width:30%}
.bar-bg{background:#21262d;border-radius:4px;height:22px;position:relative;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .5s ease}
.bar-label{position:absolute;right:8px;top:3px;font-size:12px;color:#c9d1d9;font-weight:500}
.program-name{font-weight:500;color:#f0f6fc}
.pubkey{font-size:11px;color:#484f58;font-family:monospace}
.validator-row{color:#8b949e;font-style:italic}
.trend-up{color:#f85149}
.trend-down{color:#3fb950}
.trend-flat{color:#484f58}
.rank{color:#484f58;font-size:12px;width:30px}
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
        e('div',{className:'label'},'TPS'),
        e('div',{className:'value'},(data.tps||0).toFixed(1))
      ),
      e('div',{className:'stat-card'},
        e('div',{className:'label'},'Samples/sec'),
        e('div',{className:'value'},(data.samples_per_sec||0).toFixed(1))
      ),
      e('div',{className:'stat-card'},
        e('div',{className:'label'},'Programs'),
        e('div',{className:'value'},progs.filter(p=>p.name!=='[validator]').length)
      )
    ),
    e('table',null,
      e('thead',null,e('tr',null,
        e('th',{style:{width:'30px'}},'#'),
        e('th',null,'Program'),
        e('th',null,'Inv/sec'),
        e('th',null,'CPU %'),
        e('th',{className:'bar-cell'},''),
        e('th',null,'Avg CU'),
        e('th',null,'Trend')
      )),
      e('tbody',null,progs.map((p,i)=>
        e('tr',{key:i,className:p.name==='[validator]'?'validator-row':''},
          e('td',{className:'rank'},p.name==='[validator]'?'':i+1),
          e('td',null,
            e('div',{className:'program-name'},p.name),
            p.pubkey!=='\u2014'?e('div',{className:'pubkey'},p.pubkey.slice(0,16)+'...'):null
          ),
          e('td',null,(p.inv_per_sec||0).toFixed(1)),
          e('td',null,p.cpu_pct.toFixed(2)+'%'),
          e('td',{className:'bar-cell'},
            e('div',{className:'bar-bg'},
              e('div',{className:'bar-fill',style:{width:(p.cpu_pct)+'%',background:COLORS[i%COLORS.length]}}),
              e('span',{className:'bar-label'},p.cpu_pct.toFixed(1)+'%')
            )
          ),
          e('td',null,p.avg_cu?(p.avg_cu>=1e6?(p.avg_cu/1e6).toFixed(1)+'M':p.avg_cu>=1e3?(p.avg_cu/1e3).toFixed(1)+'K':p.avg_cu.toFixed(0)):'\u2014'),
          e('td',null,trendIcon(p.cpu_delta||0))
        )
      ))
    )
  );
}
function trendIcon(d){
  if(d>0.1)return e('span',{className:'trend-up'},'\u25b2 +'+d.toFixed(2)+'%');
  if(d<-0.1)return e('span',{className:'trend-down'},'\u25bc '+d.toFixed(2)+'%');
  return e('span',{className:'trend-flat'},'\u2014');
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
