"""
R3V3R53//F0RG3 — Cross-Architecture Unified Intermediate Language (UIL) Lifter (§25)
Standardizes x86/x64, ARM64 (AArch64), and MIPS/RISC-V assembly into a single
platform-independent intermediate representation for analysis, decompilation, and taint tracking.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class UILInstruction:
    opcode: str                 # ASSIGN, LOAD, STORE, ADD, SUB, MUL, AND, OR, XOR, SHL, SHR, CALL, JUMP, CJUMP, RET, NOP
    dest: Optional[str] = None
    src1: Optional[str] = None
    src2: Optional[str] = None
    offset: int = 0
    size_bytes: int = 4
    raw_assembly: str = ""


class UnifiedILLifter:
    """Lifts heterogeneous architectures into a standardized intermediate representation."""

    # Register normalization across architectures
    RET_REG_MAP = {
        "x86": "rax", "x64": "rax",
        "arm64": "x0", "aarch64": "x0",
        "mips": "v0", "riscv": "a0",
    }

    def __init__(self, target_arch: str = "x64"):
        self.target_arch = target_arch.lower()

    def lift_instruction(self, mnemonic: str, operands: List[str], raw_text: str = "") -> UILInstruction:
        """Translates an architecture-specific mnemonic + operands into UILInstruction."""
        op = mnemonic.strip().lower()
        cleaned_ops = [p.strip().rstrip(",") for p in operands if p.strip().rstrip(",")]
        raw = raw_text or f"{mnemonic} {', '.join(operands)}"

        # -------------------------------------------------------------
        # 1. ARM64 (AArch64) Instruction Lifting
        # -------------------------------------------------------------
        if self.target_arch in ("arm64", "aarch64"):
            if op in ("mov", "mvn") and len(cleaned_ops) >= 2:
                return UILInstruction(opcode="ASSIGN", dest=cleaned_ops[0], src1=cleaned_ops[1], raw_assembly=raw)
            if op in ("ldr", "ldrb", "ldrh", "ldur") and len(cleaned_ops) >= 2:
                dest = cleaned_ops[0]
                base, off = self._parse_bracket_mem(cleaned_ops[1])
                return UILInstruction(opcode="LOAD", dest=dest, src1=base, offset=off, raw_assembly=raw)
            if op in ("str", "strb", "strh", "stur") and len(cleaned_ops) >= 2:
                src = cleaned_ops[0]
                base, off = self._parse_bracket_mem(cleaned_ops[1])
                return UILInstruction(opcode="STORE", dest=base, src1=src, offset=off, raw_assembly=raw)
            if op in ("add", "adds") and len(cleaned_ops) >= 3:
                return UILInstruction(opcode="ADD", dest=cleaned_ops[0], src1=cleaned_ops[1], src2=cleaned_ops[2], raw_assembly=raw)
            if op in ("sub", "subs") and len(cleaned_ops) >= 3:
                return UILInstruction(opcode="SUB", dest=cleaned_ops[0], src1=cleaned_ops[1], src2=cleaned_ops[2], raw_assembly=raw)
            if op in ("bl", "blr") and cleaned_ops:
                return UILInstruction(opcode="CALL", dest=cleaned_ops[0], raw_assembly=raw)
            if op == "ret":
                return UILInstruction(opcode="RET", src1="x0", raw_assembly=raw)
            if op == "b" and cleaned_ops:
                return UILInstruction(opcode="JUMP", dest=cleaned_ops[0], raw_assembly=raw)
            if op.startswith("b.") and cleaned_ops:
                return UILInstruction(opcode="CJUMP", dest=cleaned_ops[0], src1="nzcv", raw_assembly=raw)

        # -------------------------------------------------------------
        # 2. MIPS Instruction Lifting
        # -------------------------------------------------------------
        if self.target_arch in ("mips", "mips64"):
            if op in ("move", "li") and len(cleaned_ops) >= 2:
                return UILInstruction(opcode="ASSIGN", dest=cleaned_ops[0], src1=cleaned_ops[1], raw_assembly=raw)
            if op in ("lw", "lb", "lbu", "lh", "lhu") and len(cleaned_ops) >= 2:
                dest = cleaned_ops[0]
                base, off = self._parse_mips_mem(cleaned_ops[1])
                return UILInstruction(opcode="LOAD", dest=dest, src1=base, offset=off, raw_assembly=raw)
            if op in ("sw", "sb", "sh") and len(cleaned_ops) >= 2:
                src = cleaned_ops[0]
                base, off = self._parse_mips_mem(cleaned_ops[1])
                return UILInstruction(opcode="STORE", dest=base, src1=src, offset=off, raw_assembly=raw)
            if op in ("addu", "add", "addi", "addiu") and len(cleaned_ops) >= 3:
                return UILInstruction(opcode="ADD", dest=cleaned_ops[0], src1=cleaned_ops[1], src2=cleaned_ops[2], raw_assembly=raw)
            if op in ("jal", "jalr") and cleaned_ops:
                return UILInstruction(opcode="CALL", dest=cleaned_ops[0], raw_assembly=raw)
            if op in ("jr", "j") and cleaned_ops:
                if cleaned_ops[0] in ("$ra", "ra"):
                    return UILInstruction(opcode="RET", src1="v0", raw_assembly=raw)
                return UILInstruction(opcode="JUMP", dest=cleaned_ops[0], raw_assembly=raw)
            if op in ("beq", "bne", "bgtz", "bltz") and len(cleaned_ops) >= 2:
                return UILInstruction(opcode="CJUMP", dest=cleaned_ops[-1], src1=cleaned_ops[0], src2=cleaned_ops[1] if len(cleaned_ops) > 2 else "0", raw_assembly=raw)

        # -------------------------------------------------------------
        # 3. x86 / x64 Instruction Lifting (Default)
        # -------------------------------------------------------------
        if op in ("mov", "movzx", "movsx") and len(cleaned_ops) >= 2:
            dst, src = cleaned_ops[0], cleaned_ops[1]
            if "[" in dst:
                base, off = self._parse_bracket_mem(dst)
                return UILInstruction(opcode="STORE", dest=base, src1=src, offset=off, raw_assembly=raw)
            elif "[" in src:
                base, off = self._parse_bracket_mem(src)
                return UILInstruction(opcode="LOAD", dest=dst, src1=base, offset=off, raw_assembly=raw)
            return UILInstruction(opcode="ASSIGN", dest=dst, src1=src, raw_assembly=raw)

        if op == "lea" and len(cleaned_ops) >= 2:
            dst, src = cleaned_ops[0], cleaned_ops[1]
            base, off = self._parse_bracket_mem(src)
            return UILInstruction(opcode="ADD", dest=dst, src1=base, src2=str(off), raw_assembly=raw)

        if op in ("add", "sub", "imul", "and", "or", "xor", "shl", "shr") and len(cleaned_ops) >= 2:
            op_map = {
                "add": "ADD", "sub": "SUB", "imul": "MUL",
                "and": "AND", "or": "OR", "xor": "XOR",
                "shl": "SHL", "shr": "SHR"
            }
            dst, src = cleaned_ops[0], cleaned_ops[1]
            return UILInstruction(opcode=op_map[op], dest=dst, src1=dst, src2=src, raw_assembly=raw)

        if op in ("call",) and cleaned_ops:
            return UILInstruction(opcode="CALL", dest=cleaned_ops[0], raw_assembly=raw)

        if op in ("ret", "retn"):
            return UILInstruction(opcode="RET", src1="rax", raw_assembly=raw)

        if op == "jmp" and cleaned_ops:
            return UILInstruction(opcode="JUMP", dest=cleaned_ops[0], raw_assembly=raw)

        if op in ("je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jb") and cleaned_ops:
            return UILInstruction(opcode="CJUMP", dest=cleaned_ops[0], src1="eflags", raw_assembly=raw)

        return UILInstruction(opcode="NOP", raw_assembly=raw)

    def lift_block(self, instructions: List[Tuple[str, List[str]]]) -> List[UILInstruction]:
        """Lift a sequence of instructions into standardized UIL representation."""
        return [self.lift_instruction(mnem, ops) for mnem, ops in instructions]

    def _parse_bracket_mem(self, mem_str: str) -> Tuple[str, int]:
        """Parses memory operand like [rbp-0x10], [x1, #16], [x0] -> ('rbp', -16)."""
        inner = mem_str.strip("[]* ")
        # Handle ARM64 style: x1, #16 or x1, #-8
        if "#" in inner:
            parts = inner.split("#")
            base = parts[0].strip().rstrip(",")
            try:
                off = int(parts[1].strip(), 0)
            except ValueError:
                off = 0
            return base, off

        # Handle x86 style: rbp - 0x10 or rdi + 8
        m = re.match(r"([a-zA-Z0-9_]+)\s*([\+\-])\s*(0x[0-9a-fA-F]+|\d+)", inner)
        if m:
            base = m.group(1)
            sign = -1 if m.group(2) == "-" else 1
            try:
                val = int(m.group(3), 0)
            except ValueError:
                val = 0
            return base, sign * val

        return inner.strip(), 0

    def _parse_mips_mem(self, mem_str: str) -> Tuple[str, int]:
        """Parses MIPS memory operand like 16($sp), -4($fp) -> ('$sp', 16)."""
        m = re.match(r"([\+\-]?(?:0x[0-9a-fA-F]+|\d+))\s*\(([^)]+)\)", mem_str.strip())
        if m:
            off_str, base = m.group(1), m.group(2).strip()
            try:
                off = int(off_str, 0)
            except ValueError:
                off = 0
            return base, off
        return mem_str.strip(), 0
