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
    per_program_samples: &HashMap<[u8; 32], u64>,
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
        let samples: u64 = per_program_samples.get(id).copied().unwrap_or(0);
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

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

pub fn stats_to_json(state: &DashboardState) -> String {
    let programs_json: Vec<String> = state
        .programs
        .iter()
        .map(|p| {
            format!(
                r#"{{"name":"{}","pubkey":"{}","samples":{},"cpu_pct":{:.2},"cycles":{},"invocations":{},"inv_per_sec":{:.1},"avg_cu":{:.0},"cpu_delta":{:.2}}}"#,
                json_escape(&p.name), json_escape(&p.pubkey), p.samples, p.cpu_pct, p.cycles, p.invocations,
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
<title>SolProf — Solana Validator Profiler</title>
<script src="https://unpkg.com/react@18/umd/react.production.min.js" crossorigin></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js" crossorigin></script>
<style>
:root{
  --bg-primary:#080b12;--bg-card:#0f1319;--bg-card-hover:#141920;--bg-header:#0a0e16;
  --border:#1a1f2e;--border-light:#242b3d;
  --text-primary:#e8ecf4;--text-secondary:#8891a4;--text-muted:#505972;
  --accent-purple:#9945ff;--accent-green:#14f195;
  --grad-start:#9945ff;--grad-end:#14f195;
  --red:#ef4444;--green:#22c55e;--yellow:#eab308;--blue:#3b82f6;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg-primary);color:var(--text-primary);font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh}
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* Header */
.header{background:var(--bg-header);border-bottom:1px solid var(--border);padding:0 32px;height:56px;display:flex;align-items:center;justify-content:space-between}
.header-left{display:flex;align-items:center;gap:16px}
.logo{font-size:18px;font-weight:700;background:linear-gradient(135deg,var(--grad-start),var(--grad-end));-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:-.5px}
.logo-sub{font-size:12px;color:var(--text-muted);font-weight:400;margin-left:2px}
.header-right{display:flex;align-items:center;gap:20px}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--green);display:inline-block;animation:pulse 2s ease-in-out infinite;margin-right:6px}
.live-label{font-size:12px;color:var(--text-secondary);font-weight:500;display:flex;align-items:center}
.uptime-badge{font-size:12px;color:var(--text-muted);font-family:'JetBrains Mono',monospace;background:var(--bg-card);padding:4px 10px;border-radius:6px;border:1px solid var(--border)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

/* Main layout */
.main{padding:24px 32px;max-width:1440px;margin:0 auto}

/* Stat cards */
.stats-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:28px}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px;transition:border-color .2s}
.stat-card:hover{border-color:var(--border-light)}
.stat-label{font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px}
.stat-value{font-size:28px;font-weight:700;font-family:'JetBrains Mono',monospace;font-variant-numeric:tabular-nums;color:var(--text-primary);line-height:1}
.stat-value.accent{background:linear-gradient(135deg,var(--grad-start),var(--grad-end));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat-sub{font-size:11px;color:var(--text-muted);margin-top:6px;font-family:'JetBrains Mono',monospace}

/* Content grid */
.content-grid{display:grid;grid-template-columns:1fr 320px;gap:24px;align-items:start}
@media(max-width:1100px){.content-grid{grid-template-columns:1fr}.sidebar{order:-1}}

/* Table */
.table-wrap{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.table-header{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.table-title{font-size:14px;font-weight:600;color:var(--text-primary)}
.table-count{font-size:12px;color:var(--text-muted);background:var(--bg-primary);padding:2px 8px;border-radius:4px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 16px;font-size:10px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid var(--border);background:var(--bg-header)}
th.right,td.right{text-align:right}
td{padding:12px 16px;border-bottom:1px solid rgba(26,31,46,.5);font-size:13px;font-variant-numeric:tabular-nums;transition:background .15s}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--bg-card-hover)}
.rank{color:var(--text-muted);font-size:11px;font-weight:500;width:36px;font-family:'JetBrains Mono',monospace}
.prog-cell{display:flex;align-items:center;gap:10px}
.prog-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;flex-shrink:0}
.prog-info{}
.prog-name{font-weight:600;color:var(--text-primary);font-size:13px;line-height:1.3}
.prog-key{font-size:10px;color:var(--text-muted);font-family:'JetBrains Mono',monospace;line-height:1.3}
.cpu-cell{display:flex;align-items:center;gap:8px}
.cpu-bar-track{flex:1;height:6px;background:var(--bg-primary);border-radius:3px;overflow:hidden;min-width:60px}
.cpu-bar-fill{height:100%;border-radius:3px;transition:width .6s cubic-bezier(.4,0,.2,1)}
.cpu-val{font-weight:600;font-family:'JetBrains Mono',monospace;font-size:12px;min-width:52px;text-align:right}
.inv-val{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-secondary)}
.cu-val{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-secondary)}
.trend-up{color:var(--red);font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace}
.trend-down{color:var(--green);font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace}
.trend-flat{color:var(--text-muted);font-size:11px}
.validator-row td{opacity:.5}
.validator-row:hover td{opacity:.7}

/* Sidebar */
.sidebar{display:flex;flex-direction:column;gap:16px}
.side-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px;overflow:hidden}
.side-card-title{font-size:12px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:16px}

/* Donut chart */
.donut-wrap{position:relative;width:200px;height:200px;margin:0 auto 16px}
.donut{width:100%;height:100%;border-radius:50%}
.donut-hole{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:120px;height:120px;border-radius:50%;background:var(--bg-card);display:flex;flex-direction:column;align-items:center;justify-content:center}
.donut-label{font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px}
.donut-value{font-size:22px;font-weight:700;font-family:'JetBrains Mono',monospace;color:var(--text-primary)}

/* Legend */
.legend{display:flex;flex-direction:column;gap:8px}
.legend-item{display:flex;align-items:center;justify-content:space-between;font-size:12px}
.legend-left{display:flex;align-items:center;gap:8px}
.legend-dot{width:8px;height:8px;border-radius:2px;flex-shrink:0}
.legend-name{color:var(--text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:140px}
.legend-pct{color:var(--text-primary);font-weight:600;font-family:'JetBrains Mono',monospace}

/* Top invocations bar chart */
.bar-chart{display:flex;flex-direction:column;gap:10px}
.bar-row{display:flex;align-items:center;gap:10px}
.bar-name{font-size:11px;color:var(--text-secondary);width:90px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0}
.bar-track{flex:1;height:20px;background:var(--bg-primary);border-radius:4px;overflow:hidden;position:relative}
.bar-fill2{height:100%;border-radius:4px;transition:width .6s cubic-bezier(.4,0,.2,1);min-width:2px}
.bar-val{position:absolute;right:6px;top:2px;font-size:10px;font-weight:600;color:var(--text-primary);font-family:'JetBrains Mono',monospace}

/* Loading */
.loading{display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px}
.spinner{width:32px;height:32px;border:3px solid var(--border);border-top-color:var(--accent-purple);border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.loading-text{font-size:13px;color:var(--text-muted)}
</style>
</head>
<body>
<div id="root"></div>
<script>
const e=React.createElement;
const COLORS=['#9945ff','#14f195','#3b82f6','#f59e0b','#ef4444','#8b5cf6','#06b6d4','#ec4899','#84cc16','#f97316'];

function App(){
  const[data,setData]=React.useState(null);
  const[connected,setConnected]=React.useState(false);
  React.useEffect(()=>{
    const poll=()=>fetch('/api/stats').then(r=>r.json()).then(d=>{setData(d);setConnected(true)}).catch(()=>setConnected(false));
    poll();const id=setInterval(poll,1000);return()=>clearInterval(id);
  },[]);
  if(!data)return e('div',{className:'loading'},e('div',{className:'spinner'}),e('div',{className:'loading-text'},'Connecting to profiler...'));
  const progs=data.programs||[];
  const active=progs.filter(p=>p.name!=='[validator]');
  const validator=progs.find(p=>p.name==='[validator]');
  const top5=active.slice(0,5);
  const programCpu=active.reduce((s,p)=>s+p.cpu_pct,0);
  const maxInv=Math.max(...active.map(p=>p.inv_per_sec||0),1);

  // Donut data
  const donutSegments=[];
  let angle=0;
  top5.forEach((p,i)=>{donutSegments.push(COLORS[i]+' '+angle+'deg '+(angle+p.cpu_pct*3.6)+'deg');angle+=p.cpu_pct*3.6});
  if(validator)donutSegments.push('#1a1f2e '+angle+'deg 360deg');
  const donutBg='conic-gradient('+donutSegments.join(',')+')';

  return e('div',null,
    // Header
    e('div',{className:'header'},
      e('div',{className:'header-left'},
        e('span',{className:'logo'},'SolProf'),
        e('span',{className:'logo-sub'},'Solana Validator Profiler')
      ),
      e('div',{className:'header-right'},
        e('span',{className:'live-label'},e('span',{className:'live-dot',style:{background:connected?'var(--green)':'var(--red)'}}),connected?'Live':'Disconnected'),
        e('span',{className:'uptime-badge'},formatTime(data.uptime_secs))
      )
    ),
    // Main
    e('div',{className:'main'},
      // Stats
      e('div',{className:'stats-grid'},
        statCard('Program TPS',(data.tps||0).toFixed(0),true,'invocations/sec'),
        statCard('CPU (Programs)',programCpu.toFixed(1)+'%',false,active.length+' active'),
        statCard('Samples',(data.total_samples||0).toLocaleString(),false,(data.samples_per_sec||0).toFixed(0)+'/sec'),
        statCard('Invocations',(data.total_invocations||0).toLocaleString(),false,'total'),
        statCard('Uptime',formatTime(data.uptime_secs),false,'')
      ),
      // Content
      e('div',{className:'content-grid'},
        // Table
        e('div',{className:'table-wrap'},
          e('div',{className:'table-header'},
            e('span',{className:'table-title'},'Program Performance'),
            e('span',{className:'table-count'},active.length+' programs')
          ),
          e('table',null,
            e('thead',null,e('tr',null,
              e('th',null,'#'),
              e('th',null,'Program'),
              e('th',{className:'right'},'Inv/sec'),
              e('th',null,'CPU Usage'),
              e('th',{className:'right'},'Avg CU'),
              e('th',{className:'right'},'Trend')
            )),
            e('tbody',null,
              active.map((p,i)=>programRow(p,i,COLORS[i%COLORS.length])),
              validator?programRow(validator,-1,'#1a1f2e'):null
            )
          )
        ),
        // Sidebar
        e('div',{className:'sidebar'},
          // Donut
          e('div',{className:'side-card'},
            e('div',{className:'side-card-title'},'CPU Distribution'),
            e('div',{className:'donut-wrap'},
              e('div',{className:'donut',style:{background:donutBg}}),
              e('div',{className:'donut-hole'},
                e('div',{className:'donut-label'},'Programs'),
                e('div',{className:'donut-value'},programCpu.toFixed(1)+'%')
              )
            ),
            e('div',{className:'legend'},
              top5.map((p,i)=>e('div',{key:i,className:'legend-item'},
                e('div',{className:'legend-left'},
                  e('div',{className:'legend-dot',style:{background:COLORS[i]}}),
                  e('span',{className:'legend-name'},p.name)
                ),
                e('span',{className:'legend-pct'},p.cpu_pct.toFixed(1)+'%')
              )),
              validator?e('div',{className:'legend-item'},
                e('div',{className:'legend-left'},
                  e('div',{className:'legend-dot',style:{background:'#1a1f2e'}}),
                  e('span',{className:'legend-name'},'Validator')
                ),
                e('span',{className:'legend-pct'},validator.cpu_pct.toFixed(1)+'%')
              ):null
            )
          ),
          // Bar chart
          e('div',{className:'side-card'},
            e('div',{className:'side-card-title'},'Top Invocations'),
            e('div',{className:'bar-chart'},
              active.slice(0,6).map((p,i)=>{
                const pct=((p.inv_per_sec||0)/maxInv*100);
                return e('div',{key:i,className:'bar-row'},
                  e('div',{className:'bar-name'},p.name),
                  e('div',{className:'bar-track'},
                    e('div',{className:'bar-fill2',style:{width:pct+'%',background:COLORS[i%COLORS.length]}}),
                    e('span',{className:'bar-val'},(p.inv_per_sec||0).toFixed(0)+'/s')
                  )
                );
              })
            )
          )
        )
      )
    )
  );
}

function statCard(label,value,isAccent,sub){
  return e('div',{className:'stat-card'},
    e('div',{className:'stat-label'},label),
    e('div',{className:'stat-value'+(isAccent?' accent':'')},value),
    sub?e('div',{className:'stat-sub'},sub):null
  );
}

function programRow(p,i,color){
  const isValidator=p.name==='[validator]';
  const initial=p.name.replace(/[\[\]]/g,'').charAt(0).toUpperCase();
  return e('tr',{key:isValidator?'v':i,className:isValidator?'validator-row':''},
    e('td',{className:'rank'},isValidator?'':i+1),
    e('td',null,
      e('div',{className:'prog-cell'},
        e('div',{className:'prog-icon',style:{background:isValidator?'#1a1f2e':color+'22',color:isValidator?'#505972':color}},initial),
        e('div',{className:'prog-info'},
          e('div',{className:'prog-name'},p.name),
          !isValidator&&p.pubkey!=='\u2014'?e('div',{className:'prog-key'},p.pubkey.slice(0,8)+'\u2026'+p.pubkey.slice(-4)):null
        )
      )
    ),
    e('td',{className:'right'},e('span',{className:'inv-val'},(p.inv_per_sec||0).toFixed(0))),
    e('td',null,
      e('div',{className:'cpu-cell'},
        e('div',{className:'cpu-bar-track'},
          e('div',{className:'cpu-bar-fill',style:{width:Math.min(p.cpu_pct,100)+'%',background:isValidator?'#1a1f2e':color}})
        ),
        e('span',{className:'cpu-val',style:{color:isValidator?'var(--text-muted)':p.cpu_pct>10?color:'var(--text-primary)'}},p.cpu_pct.toFixed(1)+'%')
      )
    ),
    e('td',{className:'right'},e('span',{className:'cu-val'},fmtCU(p.avg_cu))),
    e('td',{className:'right'},trendBadge(p.cpu_delta||0))
  );
}

function trendBadge(d){
  if(d>0.05)return e('span',{className:'trend-up'},'\u25b2+'+d.toFixed(2));
  if(d<-0.05)return e('span',{className:'trend-down'},'\u25bc'+d.toFixed(2));
  return e('span',{className:'trend-flat'},'\u2014');
}
function fmtCU(v){if(!v)return'\u2014';if(v>=1e6)return(v/1e6).toFixed(1)+'M';if(v>=1e3)return(v/1e3).toFixed(1)+'K';return v.toFixed(0)}
function formatTime(s){if(!s)return'0s';if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m '+s%60+'s';return Math.floor(s/3600)+'h '+Math.floor(s%3600/60)+'m'}
ReactDOM.createRoot(document.getElementById('root')).render(e(App));
</script>
</body>
</html>"##;
