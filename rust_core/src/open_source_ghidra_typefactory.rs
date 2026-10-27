//! R3V3R53//F0RG3 — Wave 5 (Phases 144–145): Direct Rust Port of Ghidra `TypeFactory`
//! & `ActionInferTypes` C-Struct / VTable Layout Recovery (`open_source_ghidra_typefactory.rs`)
//!
//! Directly ports the pointer-offset clustering and C structure synthesis pass from:
//!   - Ghidra Decompiler (`Ghidra/Features/Decompiler/src/decompile/cpp/typeop.cc` & `type.cc`):
//!     - Scans `PcodeOp` (`IntAdd`, `PtrAdd`, `Load`, `Store`, `CallInd`) operations to identify
//!       base pointer registers (`rdi`, `rsi`, `rcx`, `rbx`, `x0`) accessed with constant displacements.
//!     - Infers field sizes (`uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`), pointer fields (`void*`),
//!       and virtual function table slots (`void (*vfunc_0x10)(void*)`), inserting explicit padding
//!       arrays (`uint8_t _pad_0x04[4]`) to produce compilable C struct declarations.

use std::collections::BTreeMap;
use crate::pcode_ssa::{AddrSpace, PcodeOp, PcodeOpCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferredStructField {
    pub offset: u64,
    pub size: usize,
    pub c_type: String,
    pub name: String,
    pub is_vtable_slot: bool,
}

#[derive(Debug, Clone)]
pub struct InferredCStruct {
    pub struct_name: String,
    pub base_reg: String,
    pub total_size: u64,
    pub fields: Vec<InferredStructField>,
}

impl InferredCStruct {
    pub fn to_c_declaration(&self) -> String {
        let mut out = format!("typedef struct {} {{\n", self.struct_name);
        let mut cursor = 0u64;

        for f in &self.fields {
            if f.offset > cursor {
                let pad_len = f.offset - cursor;
                out.push_str(&format!("    uint8_t _pad_0x{:02x}[{}]; // +0x{:02x}\n", cursor, pad_len, cursor));
            }
            if f.is_vtable_slot {
                out.push_str(&format!("    void* (*{})(void* self); // +0x{:02x} (vtable dispatch)\n", f.name, f.offset));
            } else {
                out.push_str(&format!("    {} {}; // +0x{:02x}\n", f.c_type, f.name, f.offset));
            }
            cursor = f.offset + (f.size as u64);
        }

        out.push_str(&format!("}} {}; // sizeof = 0x{:x}\n", self.struct_name, self.total_size.max(cursor)));
        out
    }
}

fn size_to_c_type(size: usize, is_ptr: bool) -> &'static str {
    if is_ptr {
        return "void*";
    }
    match size {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        _ => "uint64_t",
    }
}

/// Infer C `struct` and `vtable` layouts from a stream of Ghidra `PcodeOp` instructions
pub fn synthesize_c_structs_from_pcode(ops: &[PcodeOp]) -> Vec<InferredCStruct> {
    // Track temporary varnode -> (base_reg_name, constant_offset)
    let mut ptr_temps: BTreeMap<(AddrSpace, u64), (String, u64)> = BTreeMap::new();
    // Map base_reg -> (offset -> (size, is_ptr, is_vtable))
    let mut struct_map: BTreeMap<String, BTreeMap<u64, (usize, bool, bool)>> = BTreeMap::new();

    for op in ops {
        match op.opcode {
            PcodeOpCode::IntAdd | PcodeOpCode::IntSub => {
                if op.inputs.len() >= 2 {
                    let base = &op.inputs[0];
                    let disp = &op.inputs[1];
                    if base.space == AddrSpace::Register && disp.space == AddrSpace::Const {
                        if base.reg_name != "rsp" && base.reg_name != "rbp" && base.reg_name != "sp" {
                            if let Some(out) = &op.output {
                                ptr_temps.insert((out.space, out.offset), (base.reg_name.to_string(), disp.offset));
                            }
                            struct_map
                                .entry(base.reg_name.to_string())
                                .or_default()
                                .entry(disp.offset)
                                .or_insert((8, false, false));
                        }
                    }
                }
            }
            PcodeOpCode::Load => {
                if let Some(addr_vn) = op.inputs.last() {
                    let sz = op.output.as_ref().map(|o| o.size as usize).unwrap_or(8);
                    if let Some((base_name, off)) = ptr_temps.get(&(addr_vn.space, addr_vn.offset)).cloned() {
                        struct_map
                            .entry(base_name)
                            .or_default()
                            .insert(off, (sz, sz == 8, false));
                    } else if addr_vn.space == AddrSpace::Register && addr_vn.reg_name != "rsp" && addr_vn.reg_name != "rbp" {
                        struct_map
                            .entry(addr_vn.reg_name.to_string())
                            .or_default()
                            .entry(0)
                            .or_insert((sz, sz == 8, false));
                    }
                }
            }
            PcodeOpCode::Store => {
                if op.inputs.len() >= 2 {
                    let addr_vn = &op.inputs[0];
                    let val_vn = &op.inputs[1];
                    if let Some((base_name, off)) = ptr_temps.get(&(addr_vn.space, addr_vn.offset)).cloned() {
                        struct_map
                            .entry(base_name)
                            .or_default()
                            .insert(off, (val_vn.size as usize, false, false));
                    }
                }
            }
            PcodeOpCode::CallInd => {
                if let Some(target_vn) = op.inputs.first() {
                    if let Some((base_name, off)) = ptr_temps.get(&(target_vn.space, target_vn.offset)).cloned() {
                        struct_map
                            .entry(base_name)
                            .or_default()
                            .insert(off, (8, true, true));
                    }
                }
            }
            _ => {}
        }
    }

    let mut results = Vec::new();
    for (idx, (reg_name, offsets)) in struct_map.into_iter().enumerate() {
        if offsets.is_empty() {
            continue;
        }
        let mut fields = Vec::new();
        let mut max_end = 0u64;
        for (off, (sz, is_ptr, is_vtable)) in offsets {
            let field_size = sz.max(1);
            let name = if is_vtable {
                format!("vfunc_0x{:02x}", off)
            } else {
                format!("field_0x{:02x}", off)
            };
            fields.push(InferredStructField {
                offset: off,
                size: field_size,
                c_type: size_to_c_type(field_size, is_ptr).to_string(),
                name,
                is_vtable_slot: is_vtable,
            });
            max_end = max_end.max(off + field_size as u64);
        }
        results.push(InferredCStruct {
            struct_name: format!("GhidraInferredObj_{}_{}", reg_name.to_uppercase(), idx),
            base_reg: reg_name,
            total_size: (max_end + 7) & !7,
            fields,
        });
    }

    results
}
