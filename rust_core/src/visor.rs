//! R3V3R53//F0RG3 — Native Rust Under-Constrained CPU Micro-Visor (`visor.rs`)
//! Executes x64 instruction streams with stack-allocated registers and a lazy page-table
//! (`BTreeMap<u64, [u8; 4096]>`) that allocates shadow pages on demand (<64 KB RAM footprint).

use std::collections::BTreeMap;
use crate::disasm::decode_x64_one;

#[derive(Debug, Clone)]
pub struct RustVisorResult {
    pub steps_executed: usize,
    pub auto_paged_faults: usize,
    pub final_rax: u64,
    pub final_rip: u64,
    pub halt_reason: &'static str,
}

pub struct RustMicroVisor {
    pub regs: [u64; 16],
    pub rip: u64,
    pub zf: bool,
    pub pages: BTreeMap<u64, Box<[u8; 4096]>>,
    pub auto_paged_faults: usize,
}

impl RustMicroVisor {
    pub fn new(entry_va: u64) -> Self {
        let mut regs = [0u64; 16];
        regs[4] = 0x7FFF_8000; // rsp
        regs[5] = 0x7FFF_9000; // rbp
        regs[1] = 0x6000_1000; // rcx shadow struct pointer
        regs[2] = 0x6000_2000; // rdx shadow struct pointer
        regs[6] = 0x6000_3000; // rsi shadow struct pointer
        regs[7] = 0x6000_4000; // rdi shadow struct pointer
        Self {
            regs,
            rip: entry_va,
            zf: false,
            pages: BTreeMap::new(),
            auto_paged_faults: 0,
        }
    }

    #[inline]
    fn ensure_page(&mut self, addr: u64, is_fault_check: bool) -> (&mut [u8; 4096], usize) {
        let page_base = addr & !0xFFF;
        let page_off = (addr & 0xFFF) as usize;
        if !self.pages.contains_key(&page_base) {
            if is_fault_check {
                self.auto_paged_faults += 1;
            }
            self.pages.insert(page_base, Box::new([0u8; 4096]));
        }
        (self.pages.get_mut(&page_base).unwrap(), page_off)
    }

    pub fn map_code(&mut self, base_va: u64, code: &[u8]) {
        for (i, &b) in code.iter().enumerate() {
            let va = base_va + (i as u64);
            let (page, off) = self.ensure_page(va, false);
            page[off] = b;
        }
    }

    pub fn read_u64(&mut self, addr: u64) -> u64 {
        let mut buf = [0u8; 8];
        for i in 0..8 {
            let (page, off) = self.ensure_page(addr + i, true);
            buf[i as usize] = page[off];
        }
        u64::from_le_bytes(buf)
    }

    pub fn write_u64(&mut self, addr: u64, val: u64, is_fault_check: bool) {
        let bytes = val.to_le_bytes();
        for i in 0..8 {
            let (page, off) = self.ensure_page(addr + i, is_fault_check);
            page[off] = bytes[i as usize];
        }
    }

    pub fn execute(&mut self, base_va: u64, code: &[u8], max_steps: usize) -> RustVisorResult {
        self.map_code(base_va, code);
        // Push sentinel return address 0xDEAD_0000
        self.regs[4] -= 8;
        self.write_u64(self.regs[4], 0xDEAD_0000, false);

        let mut steps = 0usize;
        let mut halt_reason = "MAX_STEPS_REACHED";

        while steps < max_steps {
            if self.rip == 0xDEAD_0000 {
                halt_reason = "FUNCTION_RETURNED_CLEANLY";
                break;
            }
            let mut ins_buf = [0u8; 16];
            for i in 0..16 {
                let (page, off) = self.ensure_page(self.rip + (i as u64), false);
                ins_buf[i] = page[off];
            }
            let ins = match decode_x64_one(&ins_buf, 0, self.rip) {
                Some(i) => i,
                None => {
                    halt_reason = "DECODE_HALT";
                    break;
                }
            };
            if ins.mnemonic == "db" {
                halt_reason = "DATA_OR_UNMAPPED_OPCODE";
                break;
            }

            steps += 1;
            let next_rip = self.rip + (ins.size as u64);
            let dst = (ins.dst_reg as usize) & 15;
            let src = (ins.src_reg as usize) & 15;

            match ins.mnemonic {
                "nop" | "endbr64" => {}
                "push" => {
                    let v = self.regs[src];
                    self.regs[4] = self.regs[4].wrapping_sub(8);
                    self.write_u64(self.regs[4], v, false);
                }
                "pop" => {
                    let v = self.read_u64(self.regs[4]);
                    self.regs[4] = self.regs[4].wrapping_add(8);
                    self.regs[dst] = v;
                }
                "leave" => {
                    self.regs[4] = self.regs[5];
                    self.regs[5] = self.read_u64(self.regs[4]);
                    self.regs[4] = self.regs[4].wrapping_add(8);
                }
                "ret" => {
                    let ret_va = self.read_u64(self.regs[4]);
                    self.regs[4] = self.regs[4].wrapping_add(8);
                    self.rip = ret_va;
                    if ret_va == 0xDEAD_0000 {
                        halt_reason = "FUNCTION_RETURNED_CLEANLY";
                        break;
                    }
                    continue;
                }
                "mov" => {
                    if ins.is_mem_src {
                        let ea = (self.regs[src] as i64).wrapping_add(ins.imm_or_disp) as u64;
                        self.regs[dst] = self.read_u64(ea);
                    } else if ins.is_mem_dst {
                        let ea = (self.regs[dst] as i64).wrapping_add(ins.imm_or_disp) as u64;
                        self.write_u64(ea, self.regs[src], true);
                    } else {
                        self.regs[dst] = self.regs[src];
                    }
                }
                "mov_imm" | "movabs" => {
                    self.regs[dst] = ins.imm_or_disp as u64;
                }
                "add" => {
                    self.regs[dst] = self.regs[dst].wrapping_add(self.regs[src]);
                    self.zf = self.regs[dst] == 0;
                }
                "add_imm" => {
                    self.regs[dst] = (self.regs[dst] as i64).wrapping_add(ins.imm_or_disp) as u64;
                    self.zf = self.regs[dst] == 0;
                }
                "sub" => {
                    self.regs[dst] = self.regs[dst].wrapping_sub(self.regs[src]);
                    self.zf = self.regs[dst] == 0;
                }
                "sub_imm" => {
                    self.regs[dst] = (self.regs[dst] as i64).wrapping_sub(ins.imm_or_disp) as u64;
                    self.zf = self.regs[dst] == 0;
                }
                "xor" => {
                    self.regs[dst] ^= self.regs[src];
                    self.zf = self.regs[dst] == 0;
                }
                "cmp_imm" => {
                    self.zf = (self.regs[dst] as i64) == ins.imm_or_disp;
                }
                "je" => {
                    if self.zf {
                        self.rip = ins.imm_or_disp as u64;
                        continue;
                    }
                }
                "jne" => {
                    if !self.zf {
                        self.rip = ins.imm_or_disp as u64;
                        continue;
                    }
                }
                _ => {}
            }

            self.rip = next_rip;
        }

        RustVisorResult {
            steps_executed: steps,
            auto_paged_faults: self.auto_paged_faults,
            final_rax: self.regs[0],
            final_rip: self.rip,
            halt_reason,
        }
    }
}
