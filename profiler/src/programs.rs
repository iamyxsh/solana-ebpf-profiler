use std::collections::HashMap;

pub fn build_known_programs() -> HashMap<[u8; 32], &'static str> {
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

pub fn display_program(id: &[u8; 32], names: &HashMap<[u8; 32], &str>) -> String {
    if let Some(name) = names.get(id) {
        name.to_string()
    } else {
        let b58 = bs58::encode(id).into_string();
        format!("{}...{}", &b58[..4], &b58[b58.len() - 4..])
    }
}

pub fn slug_program(id: &[u8; 32], names: &HashMap<[u8; 32], &str>) -> String {
    if let Some(name) = names.get(id) {
        name.to_lowercase().replace(' ', "-")
    } else {
        bs58::encode(id).into_string()
    }
}

pub fn is_zero(id: &[u8; 32]) -> bool {
    id.iter().all(|b| *b == 0)
}
