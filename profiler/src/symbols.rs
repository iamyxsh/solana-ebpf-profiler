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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_resolver(syms: Vec<(u64, u64, &str)>) -> SymbolResolver {
        let mut symbols: Vec<(u64, u64, String)> = syms
            .into_iter()
            .map(|(addr, size, name)| (addr, size, name.to_string()))
            .collect();
        symbols.sort_by_key(|s| s.0);
        SymbolResolver { symbols }
    }

    // --- SymbolResolver::resolve ---

    #[test]
    fn resolve_exact_match() {
        let r = make_resolver(vec![(0x1000, 100, "main"), (0x2000, 50, "helper")]);
        assert_eq!(r.resolve(0x1000), "main");
        assert_eq!(r.resolve(0x2000), "helper");
    }

    #[test]
    fn resolve_within_symbol_range() {
        let r = make_resolver(vec![(0x1000, 100, "main")]);
        assert_eq!(r.resolve(0x1050), "main");
        assert_eq!(r.resolve(0x1063), "main"); // 0x1000 + 99 = 0x1063
    }

    #[test]
    fn resolve_outside_symbol_range() {
        let r = make_resolver(vec![(0x1000, 100, "main")]);
        assert_eq!(r.resolve(0x1064), "??"); // one past end
        assert_eq!(r.resolve(0x5000), "??");
    }

    #[test]
    fn resolve_before_first_symbol() {
        let r = make_resolver(vec![(0x1000, 100, "main")]);
        assert_eq!(r.resolve(0x500), "??");
    }

    #[test]
    fn resolve_empty_resolver() {
        let r = make_resolver(vec![]);
        assert_eq!(r.resolve(0x1000), "??");
    }

    #[test]
    fn resolve_between_symbols() {
        let r = make_resolver(vec![(0x1000, 10, "a"), (0x2000, 10, "b")]);
        assert_eq!(r.resolve(0x100A), "??"); // past "a", before "b"
        assert_eq!(r.resolve(0x1500), "??");
    }

    #[test]
    fn resolve_adjacent_symbols() {
        let r = make_resolver(vec![(0x1000, 0x100, "a"), (0x1100, 0x100, "b")]);
        assert_eq!(r.resolve(0x10FF), "a");
        assert_eq!(r.resolve(0x1100), "b");
    }

    // --- resolve_addr / resolve_addr_uncached ---

    #[test]
    fn resolve_addr_with_map_hit() {
        let resolver = make_resolver(vec![(0x5000, 100, "my_func")]);
        let mut resolvers = HashMap::new();
        resolvers.insert("/usr/bin/test".to_string(), resolver);
        let maps = vec![(0x400000u64, 0x500000u64, 0x0u64, "/usr/bin/test".to_string())];
        let mut cache = HashMap::new();
        // addr 0x405000 maps to file offset: 0x405000 - 0x400000 + 0 = 0x5000
        let result = resolve_addr(0x405000, &maps, &resolvers, &mut cache);
        assert_eq!(result, "my_func");
    }

    #[test]
    fn resolve_addr_caches_result() {
        let resolver = make_resolver(vec![(0x5000, 100, "cached_fn")]);
        let mut resolvers = HashMap::new();
        resolvers.insert("/bin/x".to_string(), resolver);
        let maps = vec![(0x400000u64, 0x500000u64, 0x0u64, "/bin/x".to_string())];
        let mut cache = HashMap::new();
        let r1 = resolve_addr(0x405000, &maps, &resolvers, &mut cache);
        assert_eq!(r1, "cached_fn");
        assert!(cache.contains_key(&0x405000));
        // Second call should hit cache
        let r2 = resolve_addr(0x405000, &maps, &resolvers, &mut cache);
        assert_eq!(r2, "cached_fn");
    }

    #[test]
    fn resolve_addr_no_matching_map() {
        let maps: Vec<(u64, u64, u64, String)> = vec![];
        let mut cache = HashMap::new();
        let result = resolve_addr(0xDEAD, &maps, &HashMap::new(), &mut cache);
        assert_eq!(result, "0xdead");
    }

    #[test]
    fn resolve_addr_map_hit_but_no_resolver() {
        let maps = vec![(0x1000u64, 0x2000u64, 0x0u64, "/lib/unknown.so".to_string())];
        let mut cache = HashMap::new();
        let result = resolve_addr(0x1500, &maps, &HashMap::new(), &mut cache);
        assert_eq!(result, "/lib/unknown.so+0x500");
    }

    #[test]
    fn resolve_addr_map_hit_symbol_miss() {
        let resolver = make_resolver(vec![(0x100, 10, "other_fn")]);
        let mut resolvers = HashMap::new();
        resolvers.insert("/bin/app".to_string(), resolver);
        let maps = vec![(0x1000u64, 0x2000u64, 0x0u64, "/bin/app".to_string())];
        let mut cache = HashMap::new();
        // offset = 0x1800 - 0x1000 = 0x800, no symbol at 0x800
        let result = resolve_addr(0x1800, &maps, &resolvers, &mut cache);
        assert_eq!(result, "/bin/app+0x800");
    }

    #[test]
    fn resolve_addr_with_offset() {
        let resolver = make_resolver(vec![(0x1000, 100, "offset_fn")]);
        let mut resolvers = HashMap::new();
        resolvers.insert("/bin/y".to_string(), resolver);
        // map has offset 0x500, so file_offset = addr - start + offset
        let maps = vec![(0x400000u64, 0x500000u64, 0x500u64, "/bin/y".to_string())];
        let mut cache = HashMap::new();
        // file_offset = 0x400B00 - 0x400000 + 0x500 = 0x1000
        let result = resolve_addr(0x400B00, &maps, &resolvers, &mut cache);
        assert_eq!(result, "offset_fn");
    }
}
