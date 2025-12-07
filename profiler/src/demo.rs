use crate::dashboard::{self, DashboardState, ProgramStat, SharedState};
use crate::programs::{build_known_programs, display_program};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal;

pub async fn run_demo(port: u16, programs_file: Option<&str>) -> anyhow::Result<()> {
    let known = build_known_programs(programs_file);

    // Simulated mainnet program profiles (b58, base invocations/s, cpu_pct)
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

    let state: SharedState = dashboard::new_shared_state();

    {
        let s = state.clone();
        tokio::spawn(async move { dashboard::run_http_server(port, s).await });
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
        let jitter = || 0.85 + (elapsed % 7) as f64 * 0.05;

        let total_samples = (elapsed as f64 * 160.0 * jitter()) as u64;
        let total_cycles = total_samples * 100_000;
        let elapsed_f = if elapsed > 0 { elapsed as f64 } else { 1.0 };

        let prev_cpu = { state.lock().unwrap().prev_cpu.clone() };

        let mut stats: Vec<ProgramStat> = programs
            .iter()
            .map(|(b58, base_inv, cpu)| {
                let bytes = bs58::decode(b58).into_vec().unwrap();
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                let invocations = (elapsed as f64 * base_inv * jitter()) as u64;
                let samples = (total_samples as f64 * cpu / 100.0) as u64;
                let name = display_program(&key, &known);
                let cpu_pct = *cpu * jitter() / jitter();
                let cpu_pct_delta = cpu_pct - prev_cpu.get(&name).copied().unwrap_or(cpu_pct);
                ProgramStat {
                    name,
                    pubkey: b58.to_string(),
                    samples,
                    cpu_pct,
                    cycles: samples * 100_000,
                    invocations,
                    inv_per_sec: invocations as f64 / elapsed_f,
                    avg_cu_per_inv: if invocations > 0 {
                        (samples * 100_000) as f64 / invocations as f64
                    } else {
                        0.0
                    },
                    cpu_pct_delta,
                }
            })
            .collect();

        stats.sort_by(|a, b| b.invocations.cmp(&a.invocations));

        let program_samples: u64 = stats.iter().map(|p| p.samples).sum();
        let overhead_pct = validator_cpu_pct;
        let delta = overhead_pct - prev_cpu.get("[validator]").copied().unwrap_or(overhead_pct);
        stats.push(ProgramStat {
            name: "[validator]".to_string(),
            pubkey: "\u{2014}".to_string(),
            samples: total_samples.saturating_sub(program_samples),
            cpu_pct: overhead_pct,
            cycles: (total_cycles as f64 * validator_cpu_pct / 100.0) as u64,
            invocations: 0,
            inv_per_sec: 0.0,
            avg_cu_per_inv: 0.0,
            cpu_pct_delta: delta,
        });

        let total_inv: u64 = stats.iter().map(|p| p.invocations).sum();
        let new_prev = stats.iter().map(|p| (p.name.clone(), p.cpu_pct)).collect();

        *state.lock().unwrap() = DashboardState {
            programs: stats,
            total_samples,
            total_invocations: total_inv,
            uptime_secs: elapsed,
            samples_per_sec: total_samples as f64 / elapsed_f,
            tps: total_inv as f64 / elapsed_f,
            prev_cpu: new_prev,
        };
    }

    println!("demo stopped");
    Ok(())
}
