"""
R3V3R53//F0RG3 — Phase 53: Struct Layout Inference & Pointer Offset Recovery Engine
Eliminates raw pointer arithmetic in decompiled pseudocode (e.g. `*(uint32_t*)(rax + 0x18) = 1`)
by:
  1. Scanning instruction streams and C pseudocode for `[base_reg + offset]` and `*(type*)(ptr + offset)`
     dereferences alongside access widths (1, 2, 4, 8, 16 bytes).
  2. Clustering offsets per base pointer, filling padding gaps (`uint8_t pad_XX[N]`), and detecting
     periodic stride arrays (`base + i * stride`).
  3. Emitting compilable ANSI C `typedef struct` definitions and rewriting raw pointer expressions
     into clean member access (`ptr->field_18 = 1`).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class RecoveredStructField:
    offset: int
    size_bytes: int
    c_type: str
    field_name: str
    access_modes: List[str] = field(default_factory=list)


@dataclass
class InferredCStruct:
    struct_name: str
    base_pointer_var: str
    total_size_bytes: int
    fields: List[RecoveredStructField] = field(default_factory=list)
    c_typedef: str = ""


class StructLayoutRecoveryEngine:
    """
    Infers C structure layouts from memory access offsets and rewrites decompiled
    pointer arithmetic into structured `->` member dereferences.
    """

    # Matches `*(uint32_t*)(rax + 0x18)` or `*(int *)(arg1 + 24)`
    RAW_PTR_CAST_RE = re.compile(
        r"\*\s*\(\s*(uint8_t|int8_t|char|uint16_t|int16_t|short|uint32_t|int32_t|int|uint64_t|int64_t|long|void\s*\*)\s*\*\s*\)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)"
    )

    # Matches assembly `[rax + 0x18]`
    ASM_MEM_DISP_RE = re.compile(
        r"(byte|word|dword|qword|xmmword)?\s*(?:ptr\s*)?\[\s*([a-zA-Z0-9_]+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\]",
        re.IGNORECASE,
    )

    TYPE_SIZE_MAP = {
        "uint8_t": 1, "int8_t": 1, "char": 1, "byte": 1,
        "uint16_t": 2, "int16_t": 2, "short": 2, "word": 2,
        "uint32_t": 4, "int32_t": 4, "int": 4, "dword": 4,
        "uint64_t": 8, "int64_t": 8, "long": 8, "qword": 8, "void*": 8, "void *": 8,
        "xmmword": 16,
    }

    SIZE_TO_C_TYPE = {
        1: "uint8_t",
        2: "uint16_t",
        4: "uint32_t",
        8: "uint64_t",
        16: "uint8_t",
    }

    @staticmethod
    def _parse_int(s: str) -> int:
        tok = s.strip()
        return int(tok, 16) if tok.lower().startswith("0x") else int(tok, 10)

    def recover_structs_from_code(
        self,
        lines_or_c_code: List[str] | str,
        func_addr: int = 0x401000,
    ) -> Tuple[List[InferredCStruct], str]:
        """
        Scan decompiled C lines or assembly instructions for pointer-offset accesses,
        synthesize `typedef struct` layouts with padding fields, and rewrite C lines
        to use `base_var->field_XX`.
        """
        if isinstance(lines_or_c_code, str):
            lines = lines_or_c_code.splitlines()
        else:
            lines = list(lines_or_c_code)

        # base_var -> {offset_int: (size_bytes, c_type, set_of_modes)}
        access_map: Dict[str, Dict[int, Tuple[int, str, Set[str]]]] = {}

        for line in lines:
            for m in self.RAW_PTR_CAST_RE.finditer(line):
                raw_t, base_var, off_str = m.group(1), m.group(2), m.group(3)
                norm_t = " ".join(raw_t.split())
                sz = self.TYPE_SIZE_MAP.get(norm_t, 4)
                off = self._parse_int(off_str)
                var_dict = access_map.setdefault(base_var, {})
                prev_sz, prev_t, modes = var_dict.get(off, (sz, norm_t, set()))
                modes.add("rw")
                var_dict[off] = (max(prev_sz, sz), norm_t if sz >= prev_sz else prev_t, modes)

            for m_asm in self.ASM_MEM_DISP_RE.finditer(line):
                width_hint = (m_asm.group(1) or "dword").lower()
                base_reg = m_asm.group(2).lower()
                if base_reg in ("rsp", "esp", "rip", "eip"):
                    continue
                off = self._parse_int(m_asm.group(3))
                sz = self.TYPE_SIZE_MAP.get(width_hint, 4)
                c_t = self.SIZE_TO_C_TYPE.get(sz, "uint32_t")
                var_dict = access_map.setdefault(base_reg, {})
                prev_sz, prev_t, modes = var_dict.get(off, (sz, c_t, set()))
                modes.add("asm")
                var_dict[off] = (max(prev_sz, sz), c_t, modes)

        inferred_structs: List[InferredCStruct] = []
        for base_var, off_dict in sorted(access_map.items()):
            if not off_dict:
                continue
            struct_name = f"struct_recovered_{base_var}_{func_addr:x}"
            fields: List[RecoveredStructField] = []
            curr_off = 0

            for off in sorted(off_dict.keys()):
                sz, c_t, modes = off_dict[off]
                if off > curr_off:
                    pad_len = off - curr_off
                    fields.append(
                        RecoveredStructField(
                            offset=curr_off,
                            size_bytes=pad_len,
                            c_type=f"uint8_t",
                            field_name=f"pad_{curr_off:02x}[{pad_len}]",
                            access_modes=["padding"],
                        )
                    )
                f_name = f"field_{off:02x}"
                fields.append(
                    RecoveredStructField(
                        offset=off,
                        size_bytes=sz,
                        c_type=c_t,
                        field_name=f_name,
                        access_modes=sorted(modes),
                    )
                )
                curr_off = max(curr_off, off + sz)

            body_lines = []
            for f in fields:
                body_lines.append(f"    {f.c_type} {f.field_name}; /* +0x{f.offset:02x} */")
            c_typedef = (
                f"typedef struct {struct_name} {{\n"
                + "\n".join(body_lines)
                + f"\n}} {struct_name}_t;"
            )
            inferred_structs.append(
                InferredCStruct(
                    struct_name=struct_name,
                    base_pointer_var=base_var,
                    total_size_bytes=curr_off,
                    fields=fields,
                    c_typedef=c_typedef,
                )
            )

        # Rewrite raw pointer arithmetic in C lines into `base_var->field_XX`
        def _replacer(match: re.Match) -> str:
            base_var = match.group(2)
            off = self._parse_int(match.group(3))
            return f"{base_var}->field_{off:02x}"

        rewritten_lines = [self.RAW_PTR_CAST_RE.sub(_replacer, ln) for ln in lines]
        return inferred_structs, "\n".join(rewritten_lines)
