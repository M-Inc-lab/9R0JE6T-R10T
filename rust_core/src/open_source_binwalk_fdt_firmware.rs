//! R3V3R53//F0RG3 — Wave 8 (Phases 174–175): Direct Rust Port of `Binwalk` / `libfdt` / `FACT`
//! Flattened Device Tree (`.dtb`), CPIO (`newc`) Archive Extractor & SquashFS 4.0 Superblock Parser
//! (`open_source_binwalk_fdt_firmware.rs`)
//!
//! Directly ports the embedded firmware structure parsers from `Binwalk`, `dtc` (`libfdt`), and `FACT`:
//!   - `parse_fdt_dtb_header`: Parses big-endian Flattened Device Tree (`0xD00DFEED`) headers
//!     (`totalsize`, `off_dt_struct`, `off_dt_strings`, `version`, `boot_cpuid_phys`).
//!   - `extract_cpio_newc_entries`: Parses SVR4 portable ASCII `cpio` (`070701` / `070702`) headers,
//!     extracting filenames, file sizes, permissions (`c_mode`), and payload offsets until `TRAILER!!!`.
//!   - `parse_squashfs_superblock`: Parses SquashFS 4.0 (`hsqs` `0x73717368`) superblocks (`inodes`,
//!     `bytes_used`, `block_size`, `compression_id`).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdtHeaderInfo {
    pub magic: u32,
    pub total_size: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpioNewcEntry {
    pub name: String,
    pub mode: u32,
    pub file_size: usize,
    pub data_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquashFsSuperblock {
    pub magic: u32,
    pub inode_count: u32,
    pub block_size: u32,
    pub compression_id: u16,
    pub bytes_used: u64,
}

/// Parse a Flattened Device Tree (`.dtb` `0xD00DFEED`) header (`libfdt/fdt.c`)
pub fn parse_fdt_dtb_header(data: &[u8]) -> Option<FdtHeaderInfo> {
    if data.len() < 28 {
        return None;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != 0xD00D_FEED {
        return None;
    }
    let total_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let off_dt_struct = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let off_dt_strings = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let version = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
    Some(FdtHeaderInfo {
        magic,
        total_size,
        off_dt_struct,
        off_dt_strings,
        version,
    })
}

fn parse_hex8(slice: &[u8]) -> u32 {
    let s = std::str::from_utf8(slice).unwrap_or("0");
    u32::from_str_radix(s, 16).unwrap_or(0)
}

const fn align4(v: usize) -> usize {
    (v + 3) & !3
}

/// Extract file entries from an SVR4 ASCII `cpio` (`070701` / `070702` `newc`) initramfs archive
pub fn extract_cpio_newc_entries(data: &[u8]) -> Vec<CpioNewcEntry> {
    let mut entries = Vec::new();
    let mut off = 0usize;

    while off + 110 <= data.len() {
        let magic = &data[off..off + 6];
        if magic != b"070701" && magic != b"070702" {
            break;
        }
        let mode = parse_hex8(&data[off + 14..off + 22]);
        let filesize = parse_hex8(&data[off + 54..off + 62]) as usize;
        let namesize = parse_hex8(&data[off + 94..off + 102]) as usize;

        let name_start = off + 110;
        let name_end = (name_start + namesize).min(data.len());
        let raw_name = &data[name_start..name_end];
        let clean_len = raw_name.iter().position(|&b| b == 0).unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..clean_len]).to_string();

        let data_offset = align4(name_start + namesize);
        if name == "TRAILER!!!" {
            break;
        }
        entries.push(CpioNewcEntry {
            name,
            mode,
            file_size: filesize,
            data_offset,
        });
        off = align4(data_offset + filesize);
    }

    entries
}

/// Parse a SquashFS 4.0 (`hsqs` = `0x73717368`) superblock
pub fn parse_squashfs_superblock(data: &[u8]) -> Option<SquashFsSuperblock> {
    if data.len() < 48 {
        return None;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != 0x7371_7368 {
        return None;
    }
    let inode_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let block_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let compression_id = u16::from_le_bytes([data[20], data[21]]);
    let bytes_used = u64::from_le_bytes(data[40..48].try_into().unwrap_or([0; 8]));
    Some(SquashFsSuperblock {
        magic,
        inode_count,
        block_size,
        compression_id,
        bytes_used,
    })
}
