//! R3V3R53//F0RG3 — Native Rust Zero-Copy FLIRT CRC-16, Wildcard Pattern Scanner & CWE Auditor (`scanner.rs`)
//! Executes single-pass masked byte pattern scans, IDA FLIRT X.25 CRC-16 hashing, and CWE sink
//! discovery over `&[u8]` buffers at native machine-code speed.

#[derive(Debug, Clone)]
pub struct RustPatternHit {
    pub file_offset: usize,
    pub rule_name: &'static str,
    pub category: &'static str,
}

/// IDA FLIRT-compatible X.25 reflected CRC-16 (`0x8408` polynomial) in native Rust
#[inline]
pub fn compute_flirt_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// FNV-1a 64-bit ultra-fast block hash for basic-block similarity & BinDiffing
#[inline]
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Zero-copy wildcard byte pattern scanner (`Some(byte)` = exact match, `None` = `??` wildcard)
pub fn scan_wildcard_pattern(data: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
    let mut hits = Vec::new();
    let plen = pattern.len();
    if plen == 0 || data.len() < plen {
        return hits;
    }
    let limit = data.len() - plen;
    let first_concrete = pattern[0];

    let mut pos = 0usize;
    while pos <= limit {
        if let Some(fb) = first_concrete {
            match data[pos..=limit].iter().position(|&b| b == fb) {
                Some(rel) => pos += rel,
                None => break,
            }
        }
        let mut matched = true;
        for (k, &expected) in pattern.iter().enumerate() {
            if let Some(eb) = expected {
                if data[pos + k] != eb {
                    matched = false;
                    break;
                }
            }
        }
        if matched {
            hits.push(pos);
            pos += plen;
        } else {
            pos += 1;
        }
    }
    hits
}

/// Built-in FLIRT & CWE dangerous sink scanner over `&[u8]`
pub fn scan_builtin_signatures(data: &[u8]) -> Vec<RustPatternHit> {
    let mut out = Vec::new();

    // 1. GLIBC _start (endbr64; xor ebp, ebp; mov r9, rdx)
    let glibc_start: &[Option<u8>] = &[
        Some(0xF3), Some(0x0F), Some(0x1E), Some(0xFA),
        Some(0x31), Some(0xED), Some(0x49), Some(0x89), Some(0xD1),
    ];
    for off in scan_wildcard_pattern(data, glibc_start) {
        out.push(RustPatternHit {
            file_offset: off,
            rule_name: "GLIBC_CRT::_start",
            category: "FLIRT_RUNTIME",
        });
    }

    // 2. MSVC x64 __security_init_cookie
    let msvc_cookie: &[Option<u8>] = &[
        Some(0x48), Some(0x89), Some(0x5C), Some(0x24), None,
        Some(0x57), Some(0x48), Some(0x83), Some(0xEC), Some(0x20),
    ];
    for off in scan_wildcard_pattern(data, msvc_cookie) {
        out.push(RustPatternHit {
            file_offset: off,
            rule_name: "MSVC_CRT::__security_init_cookie",
            category: "FLIRT_RUNTIME",
        });
    }

    // 3. CWE memory-corruption & command-injection sink strings
    let cwe_sinks: &[(&[u8], &'static str, &'static str)] = &[
        (b"strcpy\0", "CWE-120:strcpy", "VULN_BUFFER_OVERFLOW"),
        (b"gets\0", "CWE-120:gets", "VULN_BUFFER_OVERFLOW"),
        (b"sprintf\0", "CWE-787:sprintf", "VULN_BUFFER_OVERFLOW"),
        (b"system\0", "CWE-78:system", "VULN_COMMAND_INJECTION"),
        (b"VirtualAlloc\0", "CAPA:VirtualAlloc", "CAPABILITY_MEMORY_ALLOC"),
    ];
    for &(needle, name, cat) in cwe_sinks {
        if needle.len() <= data.len() {
            let mut pos = 0usize;
            while let Some(rel) = data[pos..].windows(needle.len()).position(|w| w == needle) {
                let hit_off = pos + rel;
                out.push(RustPatternHit {
                    file_offset: hit_off,
                    rule_name: name,
                    category: cat,
                });
                pos = hit_off + needle.len();
            }
        }
    }

    out
}
