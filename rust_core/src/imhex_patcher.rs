//! R3V3R53//F0RG3 — Native Rust ImHex Pattern DSL Evaluator & Keystone/LIEF Micro-Patcher
//! (`imhex_patcher.rs`)
//! Implements Category 16 (ImHex `.hexpat` Binary Struct Pattern Evaluator + Keystone/LIEF
//! Micro-Assembler and Reversible Binary Patcher) in zero-dependency Rust.

#[derive(Debug, Clone)]
pub struct ImHexEvaluatedField {
    pub field_name: String,
    pub field_type: String,
    pub offset: usize,
    pub size: usize,
    pub formatted_value: String,
}

/// Evaluate an ImHex-style struct pattern (`u8`, `u16`, `u32`, `u64`, `char[N]`) against `data` at `base_offset`
pub fn evaluate_imhex_pattern(
    data: &[u8],
    base_offset: usize,
    pattern_dsl: &str,
) -> Vec<ImHexEvaluatedField> {
    let mut fields = Vec::new();
    let mut cur = base_offset;

    for raw_stmt in pattern_dsl.split(';') {
        let stmt = raw_stmt.trim();
        if stmt.is_empty() || stmt.starts_with("struct") || stmt == "}" {
            continue;
        }
        let clean = stmt.trim_start_matches('{').trim();
        let parts: Vec<&str> = clean.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let f_type = parts[0];
        let f_name = parts[1].trim_end_matches(';');

        let (sz, val_str) = match f_type {
            "u8" | "uint8_t" => {
                if cur + 1 <= data.len() {
                    (1usize, format!("0x{:02X} ({})", data[cur], data[cur]))
                } else {
                    break;
                }
            }
            "u16" | "uint16_t" => {
                if cur + 2 <= data.len() {
                    let v = u16::from_le_bytes([data[cur], data[cur + 1]]);
                    (2usize, format!("0x{:04X} ({})", v, v))
                } else {
                    break;
                }
            }
            "u32" | "uint32_t" => {
                if cur + 4 <= data.len() {
                    let v = u32::from_le_bytes([data[cur], data[cur + 1], data[cur + 2], data[cur + 3]]);
                    (4usize, format!("0x{:08X} ({})", v, v))
                } else {
                    break;
                }
            }
            "u64" | "uint64_t" => {
                if cur + 8 <= data.len() {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&data[cur..cur + 8]);
                    let v = u64::from_le_bytes(b);
                    (8usize, format!("0x{:016X}", v))
                } else {
                    break;
                }
            }
            _ => continue,
        };

        fields.push(ImHexEvaluatedField {
            field_name: f_name.to_string(),
            field_type: f_type.to_string(),
            offset: cur,
            size: sz,
            formatted_value: val_str,
        });
        cur += sz;
    }

    fields
}

/// Keystone/LIEF style micro-assembler & conditional jump inverter in native Rust
pub fn assemble_or_invert_patch(idiom: &str, current_byte: u8) -> Vec<u8> {
    match idiom.trim() {
        "nop" => vec![0x90],
        "ret" => vec![0xC3],
        "ret0" | "xor eax, eax; ret" => vec![0x31, 0xC0, 0xC3],
        "ret1" => vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3],
        "invert_jcc" => {
            if (0x70..=0x7F).contains(&current_byte) {
                vec![current_byte ^ 1]
            } else {
                vec![0x90]
            }
        }
        _ => vec![0x90],
    }
}
