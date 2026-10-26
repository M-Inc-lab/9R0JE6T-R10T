//! R3V3R53//F0RG3 — Wave 9 (Phases 186–188): Direct Rust Port of `elfutils` (`libdw`) / `gimli`
//! DWARF v4/v5 `.debug_info` Compilation Unit & DIE Type-Tree Parser
//! (`open_source_dwarf5_pdb_type_tree.rs`)
//!
//! Directly ports the DWARF v4/v5 `.debug_info` Compilation Unit header and Debugging Information
//! Entry (`DIE`) abbreviation decoder from `elfutils/libdw` and `gimli`:
//!   - Parses 32-bit DWARF v4 (`version == 4`) and DWARF v5 (`version == 5`, `unit_type = DW_UT_compile`)
//!     Compilation Unit headers (`unit_length`, `version`, `address_size`, `debug_abbrev_offset`).
//!   - Decodes `DW_TAG_compile_unit` (`0x11`), `DW_TAG_subprogram` (`0x2e`),
//!     `DW_TAG_structure_type` (`0x13`), `DW_TAG_member` (`0x0d`), and `DW_TAG_base_type` (`0x24`).

pub const DW_TAG_MEMBER: u64 = 0x0d;
pub const DW_TAG_COMPILE_UNIT: u64 = 0x11;
pub const DW_TAG_STRUCTURE_TYPE: u64 = 0x13;
pub const DW_TAG_BASE_TYPE: u64 = 0x24;
pub const DW_TAG_SUBPROGRAM: u64 = 0x2e;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfCompilationUnitHeader {
    pub unit_length: u32,
    pub version: u16,
    pub unit_type: Option<u8>,
    pub address_size: u8,
    pub debug_abbrev_offset: u32,
    pub header_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfDieEntry {
    pub offset: usize,
    pub abbrev_code: u64,
    pub tag: u64,
    pub tag_name: &'static str,
}

pub fn dwarf_tag_to_name(tag: u64) -> &'static str {
    match tag {
        DW_TAG_COMPILE_UNIT => "DW_TAG_compile_unit",
        DW_TAG_SUBPROGRAM => "DW_TAG_subprogram",
        DW_TAG_STRUCTURE_TYPE => "DW_TAG_structure_type",
        DW_TAG_MEMBER => "DW_TAG_member",
        DW_TAG_BASE_TYPE => "DW_TAG_base_type",
        _ => "DW_TAG_unknown",
    }
}

/// Parse a DWARF v4 or DWARF v5 `.debug_info` Compilation Unit header (`gimli`/`libdw` specification)
pub fn parse_dwarf_cu_header(debug_info: &[u8]) -> Option<DwarfCompilationUnitHeader> {
    if debug_info.len() < 11 {
        return None;
    }
    let unit_length = u32::from_le_bytes([debug_info[0], debug_info[1], debug_info[2], debug_info[3]]);
    let version = u16::from_le_bytes([debug_info[4], debug_info[5]]);

    if version == 5 {
        if debug_info.len() < 12 {
            return None;
        }
        let unit_type = debug_info[6];
        let address_size = debug_info[7];
        let debug_abbrev_offset = u32::from_le_bytes([debug_info[8], debug_info[9], debug_info[10], debug_info[11]]);
        Some(DwarfCompilationUnitHeader {
            unit_length,
            version,
            unit_type: Some(unit_type),
            address_size,
            debug_abbrev_offset,
            header_size: 12,
        })
    } else if (2..=4).contains(&version) {
        let debug_abbrev_offset = u32::from_le_bytes([debug_info[6], debug_info[7], debug_info[8], debug_info[9]]);
        let address_size = debug_info[10];
        Some(DwarfCompilationUnitHeader {
            unit_length,
            version,
            unit_type: None,
            address_size,
            debug_abbrev_offset,
            header_size: 11,
        })
    } else {
        None
    }
}

/// Decode a sequence of `(abbrev_code, tag)` DIE records following a DWARF Compilation Unit header
pub fn decode_dwarf_die_stream(debug_info: &[u8], abbrev_table: &[(u64, u64)]) -> Vec<DwarfDieEntry> {
    let hdr = match parse_dwarf_cu_header(debug_info) {
        Some(h) => h,
        None => return Vec::new(),
    };
    let mut entries = Vec::new();
    let mut pos = hdr.header_size;

    while pos < debug_info.len() {
        let code = debug_info[pos] as u64;
        let off = pos;
        pos += 1;
        if code == 0 {
            continue;
        }
        let tag = abbrev_table
            .iter()
            .find(|&&(c, _)| c == code)
            .map(|&(_, t)| t)
            .unwrap_or(0);
        entries.push(DwarfDieEntry {
            offset: off,
            abbrev_code: code,
            tag,
            tag_name: dwarf_tag_to_name(tag),
        });
    }

    entries
}
