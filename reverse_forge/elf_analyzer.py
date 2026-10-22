import math
import struct
from typing import Dict, Any, List


class ELFAnalyzer:
    """Pure-Python ELF32 and ELF64 header, segment, and section analyzer."""

    def __init__(self, data: bytes):
        self.data = data
        self.length = len(data)

    def analyze(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "is_elf": False,
            "class": "Unknown",
            "endianness": "Unknown",
            "architecture": "Unknown",
            "type": "Unknown",
            "entry_point": 0,
            "entry_file_offset": None,
            "segments": [],
            "sections": [],
            "nx_enabled": None,
            "entropy": self.calculate_entropy(self.data),
            "warnings": []
        }

        if self.length < 16 or self.data[:4] != b"\x7fELF":
            result["warnings"].append("Missing ELF magic signature")
            return result

        result["is_elf"] = True
        ei_class = self.data[4]
        ei_data = self.data[5]

        endian_char = "<" if ei_data == 1 else ">"
        result["endianness"] = "Little-Endian" if ei_data == 1 else "Big-Endian"

        if ei_class == 1:
            result["class"] = "32-bit"
            is_64 = False
        elif ei_class == 2:
            result["class"] = "64-bit"
            is_64 = True
        else:
            result["warnings"].append(f"Invalid ELF class: {ei_class}")
            return result

        types = {
            1: "Relocatable (ET_REL)",
            2: "Executable (ET_EXEC)",
            3: "Shared Object / PIE (ET_DYN)",
            4: "Core Dump (ET_CORE)"
        }
        machines = {
            0x03: "x86 (Intel 80386)",
            0x3E: "x86-64 (AMD64)",
            0x28: "ARM (32-bit)",
            0xB7: "AArch64 (ARM 64-bit)",
            0xF3: "RISC-V",
            0x08: "MIPS"
        }

        if is_64:
            if self.length < 64:
                result["warnings"].append("Truncated ELF64 header")
                return result
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                endian_char + "HHIQQQIHHHHHH", self.data, 16
            )
        else:
            if self.length < 52:
                result["warnings"].append("Truncated ELF32 header")
                return result
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                endian_char + "HHIIIIIHHHHHH", self.data, 16
            )

        result["type"] = types.get(e_type, f"Unknown ({e_type})")
        result["architecture"] = machines.get(e_machine, f"Unknown (0x{e_machine:04X})")
        result["entry_point"] = hex(e_entry)

        p_types = {
            0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP",
            4: "PT_NOTE", 5: "PT_SHLIB", 6: "PT_PHDR", 7: "PT_TLS",
            0x6474E551: "PT_GNU_STACK"
        }

        min_phentsize = 56 if is_64 else 32
        if e_phoff > 0 and e_phnum > 0:
            if e_phentsize < min_phentsize:
                result["warnings"].append(
                    f"Malformed e_phentsize ({e_phentsize} < {min_phentsize}); skipping program headers"
                )
            else:
                for i in range(min(e_phnum, 1024)):
                    cur = e_phoff + (i * e_phentsize)
                    if cur + min_phentsize > self.length or cur + e_phentsize > self.length:
                        result["warnings"].append("Truncated ELF program header table")
                        break
                    if is_64:
                        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                            endian_char + "IIQQQQQQ", self.data, cur
                        )
                    else:
                        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
                            endian_char + "IIIIIIII", self.data, cur
                        )

                    type_name = p_types.get(p_type, f"0x{p_type:08X}")
                    r = bool(p_flags & 4)
                    w = bool(p_flags & 2)
                    x = bool(p_flags & 1)

                    if p_type == 0x6474E551:  # PT_GNU_STACK
                        result["nx_enabled"] = not x

                    if p_type == 1 and p_filesz > 0 and p_vaddr <= e_entry < p_vaddr + p_filesz:
                        mapped_entry = p_offset + (e_entry - p_vaddr)
                        if mapped_entry < self.length:
                            result["entry_file_offset"] = hex(mapped_entry)

                    result["segments"].append({
                        "type": type_name,
                        "offset": hex(p_offset),
                        "virtual_address": hex(p_vaddr),
                        "file_size": p_filesz,
                        "mem_size": p_memsz,
                        "readable": r,
                        "writable": w,
                        "executable": x
                    })

        min_shentsize = 64 if is_64 else 40
        if e_shoff > 0 and e_shnum > 0:
            if e_shentsize < min_shentsize:
                result["warnings"].append(
                    f"Malformed e_shentsize ({e_shentsize} < {min_shentsize}); skipping section headers"
                )
            elif e_shstrndx < e_shnum:
                str_header_offset = e_shoff + (e_shstrndx * e_shentsize)
                if str_header_offset + min_shentsize <= self.length and str_header_offset + e_shentsize <= self.length:
                    if is_64:
                        _, _, _, _, strtab_offset, strtab_size, _, _, _, _ = struct.unpack_from(
                            endian_char + "IIQQQQIIQQ", self.data, str_header_offset
                        )
                    else:
                        _, _, _, _, strtab_offset, strtab_size, _, _, _, _ = struct.unpack_from(
                            endian_char + "IIIIIIIIII", self.data, str_header_offset
                        )
                    strtab_data = (
                        self.data[strtab_offset:strtab_offset + strtab_size]
                        if strtab_offset + strtab_size <= self.length
                        else b""
                    )

                    for i in range(min(e_shnum, 4096)):
                        cur_sh = e_shoff + (i * e_shentsize)
                        if cur_sh + min_shentsize > self.length or cur_sh + e_shentsize > self.length:
                            result["warnings"].append("Truncated ELF section header table")
                            break
                        if is_64:
                            sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                                endian_char + "IIQQQQIIQQ", self.data, cur_sh
                            )
                        else:
                            sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                                endian_char + "IIIIIIIIII", self.data, cur_sh
                            )

                        sec_name = ""
                        if strtab_data and sh_name_idx < len(strtab_data):
                            end_idx = strtab_data.find(b"\x00", sh_name_idx)
                            sec_name = strtab_data[sh_name_idx:end_idx if end_idx != -1 else None].decode(
                                "ascii", errors="replace"
                            )

                        sec_bytes = (
                            self.data[sh_offset:sh_offset + sh_size]
                            if sh_offset + sh_size <= self.length
                            else b""
                        )
                        entropy = self.calculate_entropy(sec_bytes) if sec_bytes else 0.0

                        is_exec = bool(sh_flags & 4)
                        if result["entry_file_offset"] is None and is_exec and sh_size > 0:
                            if sh_addr <= e_entry < sh_addr + sh_size:
                                mapped_off = sh_offset + (e_entry - sh_addr)
                                if mapped_off < self.length:
                                    result["entry_file_offset"] = hex(mapped_off)

                        result["sections"].append({
                            "name": sec_name,
                            "address": hex(sh_addr),
                            "virtual_address": hex(sh_addr),
                            "offset": hex(sh_offset),
                            "raw_offset": hex(sh_offset),
                            "size": sh_size,
                            "raw_size": sh_size,
                            "entropy": round(entropy, 2),
                            "writable": bool(sh_flags & 1),
                            "alloc": bool(sh_flags & 2),
                            "executable": is_exec
                        })

        return result

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        sample = data[:16 * 1024 * 1024]
        entropy = 0.0
        counts = [0] * 256
        for b in sample:
            counts[b] += 1
        total = len(sample)
        for c in counts:
            if c > 0:
                p = c / total
                entropy -= p * math.log2(p)
        return round(entropy, 4)
