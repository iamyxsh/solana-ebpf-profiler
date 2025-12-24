use object::{Object, ObjectSymbol, SymbolKind};
use std::collections::HashMap;
use std::fs;

pub struct SymbolResolver {
    symbols: Vec<(u64, u64, String)>,
}

impl SymbolResolver {
    pub fn from_binary(path: &str) -> anyhow::Result<Self> {
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

    pub fn resolve(&self, addr: u64) -> &str {
        if self.symbols.is_empty() {
            return "??";
        }
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

pub fn parse_maps(pid: u32) -> Vec<(u64, u64, u64, String)> {
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

pub fn resolve_addr(
    addr: u64,
    maps: &[(u64, u64, u64, String)],
    resolvers: &HashMap<String, SymbolResolver>,
    cache: &mut HashMap<u64, String>,
) -> String {
    if let Some(cached) = cache.get(&addr) {
        return cached.clone();
    }
    let result = resolve_addr_uncached(addr, maps, resolvers);
    cache.insert(addr, result.clone());
    result
}

fn resolve_addr_uncached(
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

pub fn find_symbol(binary_path: &str, fragments: &[&str]) -> anyhow::Result<Vec<String>> {
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
