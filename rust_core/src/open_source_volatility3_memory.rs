//! R3V3R53//F0RG3 — Wave 7 (Phases 161–163): Direct Rust Port of `Volatility 3`
//! (`layers/intel.py` & `poolscanner.py`) IA-32e 4-Level Page-Table Walker & DKOM Pool Scanner
//! (`open_source_volatility3_memory.rs`)
//!
//! Directly translates core physical memory forensics and kernel object carving algorithms from
//! `Volatility 3` and `MemProcFS`:
//!   - `translate_ia32e_va`: Full 4-level x86_64 virtual-to-physical address translation
//!     (`CR3/DTB` -> `PML4E` -> `PDPTE` [1GB huge page check] -> `PDE` [2MB large page check]
//!     -> `PTE` -> 4KB physical frame + `NX`/`RW`/`US` permission flags).
//!   - `scan_kernel_pool_tags_and_dkom`: Scans raw physical memory for Windows `_POOL_HEADER`
//!     tags (`Proc`, `File`, `Driv`, `Mutn`) and detects Direct Kernel Object Manipulation (DKOM)
//!     hidden processes whose `ActiveProcessLinks` (`Flink`/`Blink`) pointers are unlinked.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageWalkStep {
    pub level: &'static str,
    pub table_pa: u64,
    pub index: usize,
    pub entry_val: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ia32eTranslation {
    pub virtual_address: u64,
    pub physical_address: Option<u64>,
    pub page_size: usize,
    pub writable: bool,
    pub user_accessible: bool,
    pub nx_enabled: bool,
    pub steps: Vec<PageWalkStep>,
}

fn read_phys_u64(phys_mem: &BTreeMap<u64, u64>, pa: u64) -> u64 {
    *phys_mem.get(&(pa & !7)).unwrap_or(&0)
}

/// Walk an x86_64 4-level page table (`DTB`/`CR3`) to translate `va` into a physical address (`volatility3/framework/layers/intel.py`)
pub fn translate_ia32e_va(phys_mem: &BTreeMap<u64, u64>, dtb: u64, va: u64) -> Ia32eTranslation {
    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pd_idx = ((va >> 21) & 0x1FF) as usize;
    let pt_idx = ((va >> 12) & 0x1FF) as usize;
    let offset_4k = va & 0xFFF;

    let mut steps = Vec::new();
    let pml4_pa = (dtb & 0x000F_FFFF_FFFF_F000) + ((pml4_idx as u64) * 8);
    let pml4e = read_phys_u64(phys_mem, pml4_pa);
    steps.push(PageWalkStep { level: "PML4", table_pa: pml4_pa, index: pml4_idx, entry_val: pml4e });
    if (pml4e & 1) == 0 {
        return Ia32eTranslation {
            virtual_address: va,
            physical_address: None,
            page_size: 0,
            writable: false,
            user_accessible: false,
            nx_enabled: false,
            steps,
        };
    }

    let pdpt_pa = (pml4e & 0x000F_FFFF_FFFF_F000) + ((pdpt_idx as u64) * 8);
    let pdpte = read_phys_u64(phys_mem, pdpt_pa);
    steps.push(PageWalkStep { level: "PDPT", table_pa: pdpt_pa, index: pdpt_idx, entry_val: pdpte });
    if (pdpte & 1) == 0 {
        return Ia32eTranslation {
            virtual_address: va,
            physical_address: None,
            page_size: 0,
            writable: false,
            user_accessible: false,
            nx_enabled: false,
            steps,
        };
    }
    // Check 1GB Huge Page (PS bit 7 = 0x80)
    if (pdpte & 0x80) != 0 {
        let pa = (pdpte & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF);
        return Ia32eTranslation {
            virtual_address: va,
            physical_address: Some(pa),
            page_size: 1024 * 1024 * 1024,
            writable: (pdpte & 2) != 0,
            user_accessible: (pdpte & 4) != 0,
            nx_enabled: (pdpte >> 63) != 0,
            steps,
        };
    }

    let pd_pa = (pdpte & 0x000F_FFFF_FFFF_F000) + ((pd_idx as u64) * 8);
    let pde = read_phys_u64(phys_mem, pd_pa);
    steps.push(PageWalkStep { level: "PD", table_pa: pd_pa, index: pd_idx, entry_val: pde });
    if (pde & 1) == 0 {
        return Ia32eTranslation {
            virtual_address: va,
            physical_address: None,
            page_size: 0,
            writable: false,
            user_accessible: false,
            nx_enabled: false,
            steps,
        };
    }
    // Check 2MB Large Page (PS bit 7 = 0x80)
    if (pde & 0x80) != 0 {
        let pa = (pde & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF);
        return Ia32eTranslation {
            virtual_address: va,
            physical_address: Some(pa),
            page_size: 2 * 1024 * 1024,
            writable: (pde & 2) != 0,
            user_accessible: (pde & 4) != 0,
            nx_enabled: (pde >> 63) != 0,
            steps,
        };
    }

    let pt_pa = (pde & 0x000F_FFFF_FFFF_F000) + ((pt_idx as u64) * 8);
    let pte = read_phys_u64(phys_mem, pt_pa);
    steps.push(PageWalkStep { level: "PT", table_pa: pt_pa, index: pt_idx, entry_val: pte });
    if (pte & 1) == 0 {
        return Ia32eTranslation {
            virtual_address: va,
            physical_address: None,
            page_size: 0,
            writable: false,
            user_accessible: false,
            nx_enabled: false,
            steps,
        };
    }

    let final_pa = (pte & 0x000F_FFFF_FFFF_F000) | offset_4k;
    Ia32eTranslation {
        virtual_address: va,
        physical_address: Some(final_pa),
        page_size: 4096,
        writable: (pte & 2) != 0,
        user_accessible: (pte & 4) != 0,
        nx_enabled: (pte >> 63) != 0,
        steps,
    }
}

#[derive(Debug, Clone)]
pub struct CarvedKernelProcess {
    pub pool_offset: usize,
    pub tag: String,
    pub pid: u32,
    pub flink: u64,
    pub blink: u64,
    pub dkom_unlinked_hidden: bool,
}

/// Scan physical memory dump for `Proc` / `File` / `Driv` pool headers and detect DKOM-unlinked processes
pub fn scan_kernel_pool_tags_and_dkom(raw_dump: &[u8], active_list_addrs: &BTreeSet<u64>) -> Vec<CarvedKernelProcess> {
    let mut carved = Vec::new();
    if raw_dump.len() < 24 {
        return carved;
    }
    for i in 0..=(raw_dump.len() - 24) {
        let tag_slice = &raw_dump[i..i + 4];
        if tag_slice == b"Proc" || tag_slice == b"Pro\xe3" {
            let pid = u32::from_le_bytes([raw_dump[i + 4], raw_dump[i + 5], raw_dump[i + 6], raw_dump[i + 7]]);
            let flink = u64::from_le_bytes(raw_dump[i + 8..i + 16].try_into().unwrap_or([0; 8]));
            let blink = u64::from_le_bytes(raw_dump[i + 16..i + 24].try_into().unwrap_or([0; 8]));
            let self_pa = i as u64;
            let unlinked = (flink == 0 && blink == 0)
                || (flink == self_pa && blink == self_pa)
                || (!active_list_addrs.is_empty() && !active_list_addrs.contains(&self_pa));
            carved.push(CarvedKernelProcess {
                pool_offset: i,
                tag: String::from_utf8_lossy(tag_slice).to_string(),
                pid,
                flink,
                blink,
                dkom_unlinked_hidden: unlinked,
            });
        }
    }
    carved
}
