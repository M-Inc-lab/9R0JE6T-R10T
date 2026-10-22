import math
import struct
from typing import Dict, Any, List, Optional


class PEAnalyzer:
    """Lightweight pure-Python PE header and section analyzer."""

    def __init__(self, data: bytes):
        self.data = data
        self.length = len(data)

    def analyze(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "is_pe": False,
            "architecture": "Unknown",
            "sections": [],
            "characteristics": [],
            "subsystem": "Unknown",
            "entry_point": 0,
            "entry_file_offset": None,
            "image_base": 0,
            "entropy": self.calculate_entropy(self.data),
            "warnings": []
        }

        if self.length < 64 or self.data[:2] != b"MZ":
            result["warnings"].append("Missing MZ magic signature")
            return result

        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if e_lfanew + 4 > self.length:
            result["warnings"].append("Invalid PE header pointer (e_lfanew exceeds file size)")
            return result

        if self.data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            result["warnings"].append("Missing PE\\0\\0 signature")
            return result

        result["is_pe"] = True
        coff_offset = e_lfanew + 4
        if coff_offset + 20 > self.length:
            result["warnings"].append("Truncated COFF header")
            return result

        machine, num_sections, timedate, symtab, num_syms, opt_hdr_size, characteristics = struct.unpack_from(
            "<HHIIIHH", self.data, coff_offset
        )

        arch_map = {
            0x014C: "x86 (32-bit)",
            0x8664: "x64 (64-bit AMD64)",
            0x01C0: "ARM",
            0xAA64: "ARM64",
        }
        result["architecture"] = arch_map.get(machine, f"Unknown (0x{machine:04X})")
        result["timestamp"] = timedate

        char_flags = [
            (0x0002, "EXECUTABLE_IMAGE"),
            (0x0020, "LARGE_ADDRESS_AWARE"),
            (0x0100, "32BIT_MACHINE"),
            (0x1000, "SYSTEM"),
            (0x2000, "DLL"),
        ]
        result["characteristics"] = [name for bit, name in char_flags if characteristics & bit]

        entry_rva = 0
        opt_offset = coff_offset + 20
        if opt_hdr_size >= 2 and opt_offset + opt_hdr_size <= self.length:
            magic = struct.unpack_from("<H", self.data, opt_offset)[0]
            subsystem = 0
            if magic == 0x10B and opt_hdr_size >= 28 and opt_offset + 28 <= self.length:
                entry_rva, _, image_base = struct.unpack_from("<III", self.data, opt_offset + 16)
                if opt_hdr_size >= 70 and opt_offset + 70 <= self.length:
                    subsystem = struct.unpack_from("<H", self.data, opt_offset + 68)[0]
                result["entry_point"] = hex(entry_rva)
                result["image_base"] = hex(image_base)
            elif magic == 0x20B and opt_hdr_size >= 32 and opt_offset + 32 <= self.length:
                entry_rva = struct.unpack_from("<I", self.data, opt_offset + 16)[0]
                image_base = struct.unpack_from("<Q", self.data, opt_offset + 24)[0]
                if opt_hdr_size >= 70 and opt_offset + 70 <= self.length:
                    subsystem = struct.unpack_from("<H", self.data, opt_offset + 68)[0]
                result["entry_point"] = hex(entry_rva)
                result["image_base"] = hex(image_base)

            subsystems = {
                1: "NATIVE",
                2: "WINDOWS_GUI",
                3: "WINDOWS_CUI",
                7: "POSIX_CUI",
                9: "WINDOWS_CE_GUI",
                10: "EFI_APPLICATION",
            }
            result["subsystem"] = subsystems.get(subsystem, f"Unknown ({subsystem})")

        sec_offset = opt_offset + opt_hdr_size
        for i in range(min(num_sections, 96)):
            cur = sec_offset + (i * 40)
            if cur + 40 > self.length:
                break
            raw_name = self.data[cur:cur + 8]
            name = raw_name.split(b"\x00")[0].decode("ascii", errors="replace").strip()
            vsize, vaddr, raw_size, raw_offset = struct.unpack_from("<IIII", self.data, cur + 8)
            sec_chars = struct.unpack_from("<I", self.data, cur + 36)[0]

            sec_bytes = self.data[raw_offset:raw_offset + raw_size] if raw_offset + raw_size <= self.length else b""
            sec_entropy = self.calculate_entropy(sec_bytes) if sec_bytes else 0.0

            span = max(vsize, raw_size)
            if entry_rva > 0 and vaddr <= entry_rva < vaddr + span:
                mapped_off = raw_offset + (entry_rva - vaddr)
                if mapped_off < self.length:
                    result["entry_file_offset"] = hex(mapped_off)

            result["sections"].append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": hex(vaddr),
                "raw_size": raw_size,
                "raw_offset": hex(raw_offset),
                "offset": hex(raw_offset),
                "entropy": round(sec_entropy, 2),
                "executable": bool(sec_chars & 0x20000000),
                "readable": bool(sec_chars & 0x40000000),
                "writable": bool(sec_chars & 0x80000000),
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
