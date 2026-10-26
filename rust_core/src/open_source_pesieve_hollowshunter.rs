//! R3V3R53//F0RG3 — Wave 7 (Phases 164–165): Direct Rust Port of `PE-sieve` & `HollowsHunter`
//! (`code_scanner.cpp`, `headers_scanner.cpp`, `iat_scanner.cpp`) In-Memory Hook & Hollowing Detector
//! (`open_source_pesieve_hollowshunter.rs`)
//!
//! Directly translates the disk-vs-memory module integrity scanners from `PE-sieve`:
//!   - `HeadersScanner`: Detects Process Hollowing, PE header wiping (zeroed `MZ`/`PE` magic),
//!     and modified `AddressOfEntryPoint` / `ImageBase`.
//!   - `CodeScanner`: Diffs `.text` code bytes between clean disk image and live memory image,
//!     classifying inline detour hooks (`E9 rel32` JMP, `FF 25 disp32` RIP-indirect JMP,
//!     `68 imm32 C3` PUSH-RET, and `48 B8 imm64 FF E0` MOV RAX-JMP RAX).
//!   - `IatScanner`: Verifies whether live Import Address Table (`IAT`) function pointers reside
//!     inside legitimate loaded export module ranges `[legit_lo, legit_hi)`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeSievePatchKind {
    RelJmpDetourE9,
    RipIndirectJmpFF25,
    PushRetTrampoline68C3,
    MovRaxJmpRax48B8,
    GenericCodeModification,
}

#[derive(Debug, Clone)]
pub struct PeSieveCodePatch {
    pub rva: usize,
    pub length: usize,
    pub kind: PeSievePatchKind,
    pub disk_bytes: Vec<u8>,
    pub mem_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PeSieveScanReport {
    pub header_wiped: bool,
    pub header_modified: bool,
    pub code_patches: Vec<PeSieveCodePatch>,
    pub hijacked_iat_slots: Vec<(usize, u64)>,
    pub is_hollowed_or_hooked: bool,
}

fn classify_inline_patch(mem_slice: &[u8]) -> PeSievePatchKind {
    if !mem_slice.is_empty() && mem_slice[0] == 0xE9 {
        return PeSievePatchKind::RelJmpDetourE9;
    }
    if mem_slice.len() >= 2 && mem_slice[0] == 0xFF && mem_slice[1] == 0x25 {
        return PeSievePatchKind::RipIndirectJmpFF25;
    }
    if mem_slice.len() >= 6 && mem_slice[0] == 0x68 && mem_slice[5] == 0xC3 {
        return PeSievePatchKind::PushRetTrampoline68C3;
    }
    if mem_slice.len() >= 12 && mem_slice[0] == 0x48 && mem_slice[1] == 0xB8 && mem_slice[10] == 0xFF && mem_slice[11] == 0xE0 {
        return PeSievePatchKind::MovRaxJmpRax48B8;
    }
    PeSievePatchKind::GenericCodeModification
}

/// Run PE-sieve `HeadersScanner` + `CodeScanner` + `IatScanner` comparing `disk_img` vs `mem_img`
pub fn scan_module_pesieve_integrity(
    disk_img: &[u8],
    mem_img: &[u8],
    code_start: usize,
    code_end: usize,
    iat_pointers: &[(usize, u64)],
    legit_module_range: (u64, u64),
) -> PeSieveScanReport {
    let min_len = disk_img.len().min(mem_img.len());
    let hdr_len = min_len.min(0x200);

    let header_wiped = mem_img.len() >= 2 && &mem_img[0..2] == b"\0\0";
    let header_modified = hdr_len >= 2 && disk_img[..hdr_len] != mem_img[..hdr_len];

    let mut code_patches = Vec::new();
    let end = code_end.min(min_len);
    let mut i = code_start.min(end);

    while i < end {
        if disk_img[i] != mem_img[i] {
            let patch_start = i;
            while i < end && disk_img[i] != mem_img[i] {
                i += 1;
            }
            let lookahead_end = (patch_start + 14).min(end);
            let kind = classify_inline_patch(&mem_img[patch_start..lookahead_end]);
            code_patches.push(PeSieveCodePatch {
                rva: patch_start,
                length: i - patch_start,
                kind,
                disk_bytes: disk_img[patch_start..i].to_vec(),
                mem_bytes: mem_img[patch_start..i].to_vec(),
            });
        } else {
            i += 1;
        }
    }

    let mut hijacked_iat_slots = Vec::new();
    for &(slot_rva, target_va) in iat_pointers {
        if target_va < legit_module_range.0 || target_va >= legit_module_range.1 {
            hijacked_iat_slots.push((slot_rva, target_va));
        }
    }

    let is_hollowed_or_hooked = header_wiped || header_modified || !code_patches.is_empty() || !hijacked_iat_slots.is_empty();

    PeSieveScanReport {
        header_wiped,
        header_modified,
        code_patches,
        hijacked_iat_slots,
        is_hollowed_or_hooked,
    }
}
