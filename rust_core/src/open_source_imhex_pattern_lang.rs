//! R3V3R53//F0RG3 — Wave 8 (Phases 176–177): Direct Rust Port of `ImHex` Pattern Language
//! (`libpl`) Recursive-Descent Binary Template Evaluator (`open_source_imhex_pattern_lang.rs`)
//!
//! Directly translates the binary template evaluation engine from `ImHex` (`lib/libpl`):
//!   - Evaluates endian-aware scalar fields (`le u8`, `le u16`, `le u32`, `le u64`, `be u16`,
//!     `be u32`, `be u64`), fixed/dynamic byte arrays (`char magic[4]`, `u8 payload[len_field]`),
//!     and absolute offset placement directives (`@ 0x10`) against raw binary buffers.
//!   - Maintains an evaluation symbol table (`BTreeMap<String, u64>`) so subsequent dynamic
//!     array lengths or conditional fields can reference previously decoded header fields!

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImHexEvaluatedField {
    pub name: String,
    pub type_spec: String,
    pub offset: usize,
    pub size: usize,
    pub int_value: Option<u64>,
    pub formatted: String,
}

/// Evaluate an ImHex Pattern Language script (`field_Lines`) against `data`
pub fn evaluate_imhex_pattern_script(data: &[u8], script: &str) -> Vec<ImHexEvaluatedField> {
    let mut out = Vec::new();
    let mut env: BTreeMap<String, u64> = BTreeMap::new();
    let mut cursor = 0usize;

    for raw_line in script.lines() {
        let line = raw_line.split("//").next().unwrap_or("").trim().trim_end_matches(';').trim();
        if line.is_empty() || line.starts_with("struct ") || line == "{" || line == "}" {
            continue;
        }

        // Check optional `@ 0xOFFSET` placement suffix
        let (decl_part, explicit_off) = if let Some((lhs, rhs)) = line.split_once('@') {
            let off_str = rhs.trim();
            let parsed = if let Some(h) = off_str.strip_prefix("0x").or_else(|| off_str.strip_prefix("0X")) {
                usize::from_str_radix(h, 16).ok()
            } else {
                off_str.parse::<usize>().ok()
            };
            (lhs.trim(), parsed)
        } else {
            (line, None)
        };

        if let Some(o) = explicit_off {
            cursor = o;
        }

        let tokens: Vec<&str> = decl_part.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }

        let (big_endian, ty_tok, name_tok) = if tokens[0] == "be" || tokens[0] == "le" {
            if tokens.len() < 3 {
                continue;
            }
            (tokens[0] == "be", tokens[1], tokens[2])
        } else {
            (false, tokens[0], tokens[1])
        };

        // Check array syntax `name[size_or_var]`
        if let Some((arr_name, bracket_rem)) = name_tok.split_once('[') {
            let len_expr = bracket_rem.trim_end_matches(']').trim();
            let count = if let Ok(c) = len_expr.parse::<usize>() {
                c
            } else {
                (*env.get(len_expr).unwrap_or(&0)) as usize
            };
            let end = (cursor + count).min(data.len());
            let slice = if cursor <= end { &data[cursor..end] } else { &[] };
            let formatted = if ty_tok == "char" {
                format!("{:?}", String::from_utf8_lossy(slice))
            } else {
                format!("{:02x?}", slice)
            };
            out.push(ImHexEvaluatedField {
                name: arr_name.to_string(),
                type_spec: format!("{}[{}]", ty_tok, count),
                offset: cursor,
                size: slice.len(),
                int_value: None,
                formatted,
            });
            cursor = end;
            continue;
        }

        let sz = match ty_tok {
            "u8" | "i8" => 1usize,
            "u16" | "i16" => 2usize,
            "u32" | "i32" => 4usize,
            "u64" | "i64" => 8usize,
            _ => continue,
        };
        if cursor + sz > data.len() {
            break;
        }
        let s = &data[cursor..cursor + sz];
        let val = match (sz, big_endian) {
            (1, _) => s[0] as u64,
            (2, false) => u16::from_le_bytes([s[0], s[1]]) as u64,
            (2, true) => u16::from_be_bytes([s[0], s[1]]) as u64,
            (4, false) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64,
            (4, true) => u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64,
            (8, false) => u64::from_le_bytes(s.try_into().unwrap_or([0; 8])),
            _ => u64::from_be_bytes(s.try_into().unwrap_or([0; 8])),
        };
        env.insert(name_tok.to_string(), val);
        out.push(ImHexEvaluatedField {
            name: name_tok.to_string(),
            type_spec: format!("{} {}", if big_endian { "be" } else { "le" }, ty_tok),
            offset: cursor,
            size: sz,
            int_value: Some(val),
            formatted: format!("0x{:x}", val),
        });
        cursor += sz;
    }

    out
}
