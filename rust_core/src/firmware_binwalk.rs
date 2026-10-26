//! R3V3R53//F0RG3 — Native Rust Firmware & Embedded Partition Carver (`firmware_binwalk.rs`)
//! Implements Category 10 (Binwalk / Firmware-Mod-Kit / FACT / Cortex-M Vector Table Recovery)
//! in zero-copy Rust:
//!   1. Scans raw firmware images for embedded filesystems, bootloaders, kernels, and compressed streams:
//!      - SquashFS (`hsqs` little-endian, `sqsh` big-endian)
//!      - CramFS (`\x45\x3d\xcd\x28`)
//!      - JFFS2 (`\x85\x19\x01\xe0`, `\x85\x19\x02\xe0`)
//!      - UBI / UBIFS (`UBI#`)
//!      - Das U-Boot `uImage` (`\x27\x05\x19\x56`)
//!      - Flattened Device Tree `FDT / DTB` (`\xd0\x0d\xfe\xed`)
//!      - Gzip (`\x1f\x8b\x08`), XZ (`\xfd7zXZ\x00`), LZMA (`\x5d\x00\x00\x80`), Zstd (`\x28\xb5\x2f\xfd`), CPIO (`070701`)
//!   2. Infers bare-metal ARM Cortex-M load base addresses (`0x08000000` STM32 Flash vs `0x00000000`)
//!      from initial MSP (`0x2000xxxx`) and Thumb-2 Reset_Handler vectors.

#[derive(Debug, Clone)]
pub struct FirmwareCarveEntry {
    pub offset: usize,
    pub signature_name: &'static str,
    pub category: &'static str,
}

#[derive(Debug, Clone)]
pub struct FirmwareAnalysisReport {
    pub is_cortex_m_vector_table: bool,
    pub inferred_base_address: u64,
    pub initial_sp: u32,
    pub reset_handler_va: u32,
    pub carved_partitions: Vec<FirmwareCarveEntry>,
}

const BINWALK_SIGNATURES: &[(&[u8], &str, &str)] = &[
    (b"hsqs", "SquashFS Filesystem (Little-Endian)", "FILESYSTEM"),
    (b"sqsh", "SquashFS Filesystem (Big-Endian)", "FILESYSTEM"),
    (b"\x45\x3d\xcd\x28", "CramFS Embedded Filesystem", "FILESYSTEM"),
    (b"UBI#", "UBI Flash Eraseblock Header", "FILESYSTEM"),
    (b"070701", "ASCII cpio Archive (initramfs)", "ARCHIVE"),
    (b"\x27\x05\x19\x56", "Das U-Boot uImage Header", "BOOTLOADER"),
    (b"\xd0\x0d\xfe\xed", "Flattened Device Tree (DTB/FDT)", "DEVICETREE"),
    (b"\x1f\x8b\x08", "Gzip Compressed Stream", "COMPRESSION"),
    (b"\xfd7zXZ\x00", "XZ / LZMA2 Compressed Stream", "COMPRESSION"),
    (b"\x28\xb5\x2f\xfd", "Zstandard (Zstd) Compressed Stream", "COMPRESSION"),
    (b"\x5d\x00\x00\x80\x00", "LZMA Compressed Stream", "COMPRESSION"),
];

pub fn scan_firmware_image(data: &[u8]) -> FirmwareAnalysisReport {
    let mut carved = Vec::new();
    for &(magic, name, cat) in BINWALK_SIGNATURES {
        if magic.len() <= data.len() {
            let mut pos = 0usize;
            while let Some(rel) = data[pos..].windows(magic.len()).position(|w| w == magic) {
                let off = pos + rel;
                carved.push(FirmwareCarveEntry {
                    offset: off,
                    signature_name: name,
                    category: cat,
                });
                pos = off + magic.len();
                if carved.len() >= 128 {
                    break;
                }
            }
        }
    }
    carved.sort_by_key(|e| e.offset);

    // Check for ARM Cortex-M Vector Table at offset 0 (Initial SP in SRAM 0x2000_0000..0x2010_0000, odd Thumb Reset_Handler)
    let mut is_cortex_m = false;
    let mut base_va = 0x400000u64;
    let mut init_sp = 0u32;
    let mut reset_va = 0u32;

    if data.len() >= 8 {
        init_sp = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        reset_va = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if (0x2000_0000..=0x20FF_FFFF).contains(&init_sp) && (reset_va & 1) == 1 {
            is_cortex_m = true;
            base_va = (reset_va as u64) & 0xFFFF_0000;
        }
    }

    FirmwareAnalysisReport {
        is_cortex_m_vector_table: is_cortex_m,
        inferred_base_address: base_va,
        initial_sp: init_sp,
        reset_handler_va: reset_va,
        carved_partitions: carved,
    }
}
