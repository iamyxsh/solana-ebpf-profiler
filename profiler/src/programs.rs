use std::collections::HashMap;
use std::fs;

/// Built-in program registry — used when no --programs file is provided.
fn default_programs() -> Vec<(&'static str, &'static str)> {
    vec![
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
    ]
}

fn b58_to_key(b58: &str) -> Option<[u8; 32]> {
    let bytes = bs58::decode(b58).into_vec().ok()?;
    if bytes.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Some(key)
    } else {
        None
    }
}

/// Load programs from a JSON file. Format:
/// ```json
/// { "programs": [ { "pubkey": "base58...", "name": "Human Name" }, ... ] }
/// ```
/// Minimal parser — no serde dependency.
pub fn load_programs_from_json(path: &str) -> anyhow::Result<HashMap<[u8; 32], String>> {
    let content = fs::read_to_string(path)?;
    let mut map = HashMap::new();

    // Find each { "pubkey": "...", "name": "..." } block
    let mut pos = 0;
    while let Some(start) = content[pos..].find("\"pubkey\"") {
        let start = pos + start;
        // Extract pubkey value
        let pubkey = extract_string_value(&content[start..])
            .ok_or_else(|| anyhow::anyhow!("malformed pubkey at position {}", start))?;

        // Find the name field near this pubkey
        let block_end = content[start..].find('}').map(|i| start + i).unwrap_or(content.len());
        let name = if let Some(name_start) = content[start..block_end].find("\"name\"") {
            extract_string_value(&content[start + name_start..]).unwrap_or_default()
        } else {
            String::new()
        };

        if let Some(key) = b58_to_key(&pubkey) {
            let display_name = if name.is_empty() {
                if pubkey.len() >= 8 {
                    format!("{}...{}", &pubkey[..4], &pubkey[pubkey.len() - 4..])
                } else {
                    pubkey.clone()
                }
            } else {
                name
            };
            map.insert(key, display_name);
        } else {
            eprintln!("warning: invalid base58 pubkey: {}", pubkey);
        }

        pos = block_end;
    }

    if map.is_empty() {
        anyhow::bail!("no valid programs found in {}", path);
    }

    println!("loaded {} programs from {}", map.len(), path);
    Ok(map)
}

/// Extract the string value after a "key": "value" pattern
fn extract_string_value(s: &str) -> Option<String> {
    let colon = s.find(':')?;
    let after_colon = s.get(colon + 1..)?;
    let quote_start = after_colon.find('"')?;
    let value_start = quote_start + 1;
    let rest = after_colon.get(value_start..)?;
    let quote_end = rest.find('"')?;
    Some(rest[..quote_end].to_string())
}

pub fn build_known_programs(programs_file: Option<&str>) -> HashMap<[u8; 32], String> {
    // Try loading from file first
    if let Some(path) = programs_file {
        match load_programs_from_json(path) {
            Ok(map) => return map,
            Err(e) => {
                eprintln!("warning: failed to load {}: {}, using defaults", path, e);
            }
        }
    }

    // Fall back to built-in defaults
    let mut map = HashMap::new();
    for (b58, name) in default_programs() {
        if let Some(key) = b58_to_key(b58) {
            map.insert(key, name.to_string());
        }
    }
    map
}

pub fn display_program(id: &[u8; 32], names: &HashMap<[u8; 32], String>) -> String {
    if let Some(name) = names.get(id) {
        name.clone()
    } else {
        let b58 = bs58::encode(id).into_string();
        format!("{}...{}", &b58[..4], &b58[b58.len() - 4..])
    }
}

pub fn slug_program(id: &[u8; 32], names: &HashMap<[u8; 32], String>) -> String {
    if let Some(name) = names.get(id) {
        name.to_lowercase().replace(' ', "-")
    } else {
        bs58::encode(id).into_string()
    }
}

pub fn is_zero(id: &[u8; 32]) -> bool {
    id.iter().all(|b| *b == 0)
}
