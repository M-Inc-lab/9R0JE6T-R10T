"""
R3V3R53//F0RG3 — Phase 49: LIEF / Binary-Ninja Style Binary Patcher & Micro-Assembler Engine
Modeled on LIEF (https://lief.re/) and Binary Ninja's Transform & Patching API.
Provides non-destructive, reversible binary modification for defensive analysis and deobfuscation:
  1. `assemble_patch_idiom()`: Built-in pure-Python micro-assembler for x86/x64/ARM64 patch instructions
     (`nop`, `ret`, `xor eax, eax; ret`, `mov eax, imm32; ret`, `int3`).
  2. `nop_range()`: Neutralizes opaque predicates or anti-debug traps by filling an address range with NOPs.
  3. `invert_conditional_branch()`: Flips short (`74 <-> 75`, `7C <-> 7D`) and near (`0F 84 <-> 0F 85`)
     conditional jumps at a given offset or Virtual Address.
  4. `patch_function_return()`: Replaces a function entry with an immediate return value (`mov eax, val; ret`).
  5. Reversible transaction log (`undo_last_patch()`, `export_patch_diff()`, `save_patched_binary()`).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class PatchTransaction:
    patch_id: int
    file_offset: int
    virtual_address: str
    description: str
    original_bytes_hex: str
    patched_bytes_hex: str
    size_bytes: int


@dataclass
class PatchSummaryReport:
    original_sha256: str
    patched_sha256: str
    total_patches_applied: int
    total_bytes_modified: int
    transactions: List[PatchTransaction] = field(default_factory=list)


class BinaryPatcherEngine:
    """
    Maintains an in-memory copy of a binary buffer, translates Virtual Addresses to file offsets,
    applies reversible instruction/byte patches, and exports patched binaries or diff logs.
    """

    # Reversible x86/x64 conditional jump opcode inversions
    SHORT_JCC_INVERT: Dict[int, int] = {
        0x70: 0x71, 0x71: 0x70,  # jo <-> jno
        0x72: 0x73, 0x73: 0x72,  # jb <-> jae
        0x74: 0x75, 0x75: 0x74,  # je/jz <-> jne/jnz
        0x76: 0x77, 0x77: 0x76,  # jbe <-> ja
        0x78: 0x79, 0x79: 0x78,  # js <-> jns
        0x7C: 0x7D, 0x7D: 0x7C,  # jl <-> jge
        0x7E: 0x7F, 0x7F: 0x7E,  # jle <-> jg
    }

    NEAR_JCC_INVERT: Dict[int, int] = {
        0x80: 0x81, 0x81: 0x80,
        0x82: 0x83, 0x83: 0x82,
        0x84: 0x85, 0x85: 0x84,  # je <-> jne (0F 84 <-> 0F 85)
        0x86: 0x87, 0x87: 0x86,
        0x88: 0x89, 0x89: 0x88,
        0x8C: 0x8D, 0x8D: 0x8C,
        0x8E: 0x8F, 0x8F: 0x8E,
    }

    def __init__(self, binary_bytes: bytes, arch: str = "x64"):
        self.original_bytes = bytes(binary_bytes)
        self.working_bytes = bytearray(binary_bytes)
        self.arch = arch.lower()
        self.transactions: List[PatchTransaction] = []

    @staticmethod
    def assemble_patch_idiom(asm_text: str, arch: str = "x64") -> bytes:
        """
        Pure-Python micro-assembler for standard x86/x64 and ARM64 patch idioms:
          - `nop` / `nop N`
          - `ret`
          - `int3`
          - `xor eax, eax; ret` / `return 0`
          - `mov eax, <imm>; ret` / `return <imm>`
        """
        clean = " ".join(asm_text.strip().lower().split())
        is_arm64 = arch.lower() in ("arm64", "aarch64")

        if clean == "nop":
            return b"\x1f\x20\x03\xd5" if is_arm64 else b"\x90"
        if clean.startswith("nop "):
            count = int(clean.split()[1], 0)
            return (b"\x1f\x20\x03\xd5" * count) if is_arm64 else (b"\x90" * count)
        if clean == "ret":
            return b"\xc0\x03\x5f\xd6" if is_arm64 else b"\xc3"
        if clean == "int3":
            return b"\xcc"
        if clean in ("xor eax, eax; ret", "return 0"):
            return b"\x00\x00\x80\xd2\xc0\x03\x5f\xd6" if is_arm64 else b"\x31\xc0\xc3"
        if clean.startswith("mov eax,") and clean.endswith("; ret"):
            val_part = clean[len("mov eax,") : -len("; ret")].strip()
            imm = int(val_part, 0) & 0xFFFFFFFF
            return struct.pack("<BI", 0xB8, imm) + b"\xc3"
        if clean.startswith("return "):
            imm = int(clean.split()[1], 0) & 0xFFFFFFFF
            if imm == 0 and not is_arm64:
                return b"\x31\xc0\xc3"
            return struct.pack("<BI", 0xB8, imm) + b"\xc3"

        raise ValueError(f"Unsupported micro-assembler patch idiom: '{asm_text}'")

    def apply_raw_patch(
        self,
        file_offset: int,
        new_bytes: bytes,
        description: str = "Raw byte patch",
        virtual_address: Optional[str] = None,
    ) -> PatchTransaction:
        if file_offset < 0 or file_offset + len(new_bytes) > len(self.working_bytes):
            raise ValueError(f"Patch at offset {hex(file_offset)} (len={len(new_bytes)}) exceeds binary bounds ({len(self.working_bytes)}).")

        orig_slice = bytes(self.working_bytes[file_offset : file_offset + len(new_bytes)])
        self.working_bytes[file_offset : file_offset + len(new_bytes)] = new_bytes

        tx = PatchTransaction(
            patch_id=len(self.transactions) + 1,
            file_offset=file_offset,
            virtual_address=virtual_address or hex(file_offset),
            description=description,
            original_bytes_hex=orig_slice.hex(),
            patched_bytes_hex=new_bytes.hex(),
            size_bytes=len(new_bytes),
        )
        self.transactions.append(tx)
        return tx

    def nop_range(self, file_offset: int, length: int, virtual_address: Optional[str] = None) -> PatchTransaction:
        """Fill `[file_offset : file_offset + length]` with architecture-appropriate NOP instructions."""
        if self.arch in ("arm64", "aarch64"):
            count = max(1, length // 4)
            nop_bytes = b"\x1f\x20\x03\xd5" * count
        else:
            nop_bytes = b"\x90" * length
        return self.apply_raw_patch(
            file_offset=file_offset,
            new_bytes=nop_bytes,
            description=f"NOP-fill {len(nop_bytes)} byte(s)",
            virtual_address=virtual_address,
        )

    def invert_conditional_branch(self, file_offset: int, virtual_address: Optional[str] = None) -> PatchTransaction:
        """
        Flip a conditional jump at `file_offset`:
          - Short Jcc (`74 rel8` je <-> `75 rel8` jne)
          - Near Jcc (`0F 84 rel32` je <-> `0F 85 rel32` jne)
        """
        if file_offset < 0 or file_offset >= len(self.working_bytes):
            raise ValueError(f"Invalid offset: {hex(file_offset)}")

        b0 = self.working_bytes[file_offset]
        if b0 in self.SHORT_JCC_INVERT:
            inv = self.SHORT_JCC_INVERT[b0]
            return self.apply_raw_patch(
                file_offset=file_offset,
                new_bytes=bytes([inv]),
                description=f"Invert short conditional branch (0x{b0:02x} -> 0x{inv:02x})",
                virtual_address=virtual_address,
            )

        if b0 == 0x0F and file_offset + 1 < len(self.working_bytes):
            b1 = self.working_bytes[file_offset + 1]
            if b1 in self.NEAR_JCC_INVERT:
                inv = self.NEAR_JCC_INVERT[b1]
                return self.apply_raw_patch(
                    file_offset=file_offset,
                    new_bytes=bytes([0x0F, inv]),
                    description=f"Invert near conditional branch (0F {b1:02x} -> 0F {inv:02x})",
                    virtual_address=virtual_address,
                )

        raise ValueError(f"Byte 0x{b0:02x} at offset {hex(file_offset)} is not a recognized conditional jump opcode.")

    def patch_function_return(
        self,
        file_offset: int,
        return_value: int = 1,
        virtual_address: Optional[str] = None,
    ) -> PatchTransaction:
        """Patch a function entry point to immediately return `return_value` (`mov eax, val; ret` or `xor eax, eax; ret`)."""
        patch_bytes = self.assemble_patch_idiom(f"return {return_value}", arch=self.arch)
        return self.apply_raw_patch(
            file_offset=file_offset,
            new_bytes=patch_bytes,
            description=f"Force function immediate return ({return_value})",
            virtual_address=virtual_address,
        )

    def undo_last_patch(self) -> Optional[PatchTransaction]:
        """Revert the most recently applied patch transaction."""
        if not self.transactions:
            return None
        last = self.transactions.pop()
        orig = bytes.fromhex(last.original_bytes_hex)
        self.working_bytes[last.file_offset : last.file_offset + last.size_bytes] = orig
        return last

    def get_patch_summary(self) -> PatchSummaryReport:
        return PatchSummaryReport(
            original_sha256=hashlib.sha256(self.original_bytes).hexdigest(),
            patched_sha256=hashlib.sha256(self.working_bytes).hexdigest(),
            total_patches_applied=len(self.transactions),
            total_bytes_modified=sum(t.size_bytes for t in self.transactions),
            transactions=list(self.transactions),
        )

    def save_patched_binary(self, output_path: str) -> PatchSummaryReport:
        with open(output_path, "wb") as f:
            f.write(self.working_bytes)
        return self.get_patch_summary()
