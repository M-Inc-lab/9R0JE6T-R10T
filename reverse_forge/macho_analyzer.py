import math
import struct
from typing import Dict, Any, List


class MachOAnalyzer:
    """Pure-Python Mach-O (32-bit, 64-bit, and Universal/Fat) analyzer."""

    MH_MAGIC = 0xFEEDFACE
    MH_CIGAM = 0xCEFAEDFE
    MH_MAGIC_64 = 0xFEEDFACF
    MH_CIGAM_64 = 0xCFFAEDFE
    FAT_MAGIC = 0xCAFEBABE
    FAT_CIGAM = 0xBEBAFECA

    VALID_CPU_TYPES = {
        7,                  # CPU_TYPE_X86
        7 | 0x01000000,     # CPU_TYPE_X86_64
        12,                 # CPU_TYPE_ARM
        12 | 0x01000000,    # CPU_TYPE_ARM64
        12 | 0x02000000,    # CPU_TYPE_ARM64_32
        18,                 # CPU_TYPE_POWERPC
        18 | 0x01000000,    # CPU_TYPE_POWERPC64
    }

    def __init__(self, data: bytes):
        self.data = data
        self.length = len(data)

    @classmethod
    def is_fat_macho(cls, data: bytes) -> bool:
        """Distinguish Universal/Fat Mach-O binaries from JVM .class files sharing 0xCAFEBABE."""
        if len(data) < 28:
            return False
        magic = struct.unpack_from(">I", data, 0)[0]
        if magic not in (cls.FAT_MAGIC, cls.FAT_CIGAM):
            return False
        endian = ">" if magic == cls.FAT_MAGIC else "<"
        nfat_arch = struct.unpack_from(endian + "I", data, 4)[0]
        if not (1 <= nfat_arch <= 20):
            return False
        if len(data) < 8 + nfat_arch * 20:
            return False
        cputype, _, slice_offset, slice_size, _ = struct.unpack_from(endian + "IIIII", data, 8)
        if cputype not in cls.VALID_CPU_TYPES:
            return False
        if slice_offset < 8 + nfat_arch * 20 or slice_size == 0:
            return False
        return True

    def analyze(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "is_macho": False,
            "is_fat": False,
            "architecture": "Unknown",
            "file_type": "Unknown",
            "entry_point": 0,
            "entry_file_offset": None,
            "segments": [],
            "sections": [],
            "entropy": self.calculate_entropy(self.data),
            "warnings": []
        }

        if self.length < 4:
            result["warnings"].append("Artifact too small for Mach-O header")
            return result

        magic = struct.unpack_from(">I", self.data, 0)[0]

        if magic in (self.FAT_MAGIC, self.FAT_CIGAM):
            if self.length < 8:
                result["warnings"].append("Truncated Universal/Fat header (< 8 bytes)")
                return result
            if not self.is_fat_macho(self.data):
                result["warnings"].append(
                    "0xCAFEBABE header is a JVM .class file or malformed Fat header, not a Universal Mach-O binary"
                )
                return result
            endian = ">" if magic == self.FAT_MAGIC else "<"
            nfat_arch = struct.unpack_from(endian + "I", self.data, 4)[0]
            result["is_macho"] = True
            result["is_fat"] = True
            result["architecture"] = f"Universal/Fat ({nfat_arch} architectures)"
            return result

        is_64 = magic in (self.MH_MAGIC_64, self.MH_CIGAM_64)
        is_32 = magic in (self.MH_MAGIC, self.MH_CIGAM)

        if not (is_64 or is_32):
            result["warnings"].append("Not a recognized Mach-O binary")
            return result

        hdr_size = 32 if is_64 else 28
        if self.length < hdr_size:
            result["warnings"].append(f"Truncated Mach-O header (length {self.length} < {hdr_size} bytes)")
            return result

        result["is_macho"] = True
        endian = "<" if magic in (self.MH_CIGAM, self.MH_CIGAM_64) else ">"

        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            endian + "IIIIII", self.data, 4
        )

        cpu_map = {
            7: "x86 (Intel)",
            7 | 0x01000000: "x86_64",
            12: "ARM",
            12 | 0x01000000: "ARM64",
        }
        file_types = {
            1: "MH_OBJECT",
            2: "MH_EXECUTE",
            6: "MH_DYLIB",
            7: "MH_DYLINKER",
            8: "MH_BUNDLE"
        }

        result["architecture"] = cpu_map.get(cputype, f"Unknown CPU (0x{cputype:08X})")
        result["file_type"] = file_types.get(filetype, f"Unknown ({filetype})")

        offset = hdr_size
        for _ in range(min(ncmds, 4096)):
            if offset + 8 > self.length:
                result["warnings"].append("Truncated Mach-O load command header")
                break
            cmd, cmdsize = struct.unpack_from(endian + "II", self.data, offset)
            if cmdsize < 8 or offset + cmdsize > self.length:
                result["warnings"].append(f"Invalid Mach-O load command size ({cmdsize}) at offset {offset}")
                break

            if cmd == 0x19 and cmdsize >= 72:  # LC_SEGMENT_64
                segname = self.data[offset + 8:offset + 24].split(b"\x00")[0].decode("ascii", errors="replace")
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _ = struct.unpack_from(
                    endian + "QQQQIIII", self.data, offset + 24
                )
                is_exec = bool(initprot & 4)
                result["segments"].append({
                    "name": segname,
                    "command_size": cmdsize,
                    "virtual_address": hex(vmaddr),
                    "file_offset": hex(fileoff),
                    "file_size": filesize,
                    "executable": is_exec
                })
                if is_exec and filesize > 0:
                    result["sections"].append({
                        "name": segname,
                        "virtual_address": hex(vmaddr),
                        "raw_offset": hex(fileoff),
                        "offset": hex(fileoff),
                        "raw_size": filesize,
                        "executable": True
                    })
            elif cmd == 0x1 and cmdsize >= 56:  # LC_SEGMENT (32-bit)
                segname = self.data[offset + 8:offset + 24].split(b"\x00")[0].decode("ascii", errors="replace")
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _ = struct.unpack_from(
                    endian + "IIIIIIII", self.data, offset + 24
                )
                is_exec = bool(initprot & 4)
                result["segments"].append({
                    "name": segname,
                    "command_size": cmdsize,
                    "virtual_address": hex(vmaddr),
                    "file_offset": hex(fileoff),
                    "file_size": filesize,
                    "executable": is_exec
                })
                if is_exec and filesize > 0:
                    result["sections"].append({
                        "name": segname,
                        "virtual_address": hex(vmaddr),
                        "raw_offset": hex(fileoff),
                        "offset": hex(fileoff),
                        "raw_size": filesize,
                        "executable": True
                    })
            elif cmd == 0x80000028 and cmdsize >= 24:  # LC_MAIN
                entryoff, _ = struct.unpack_from(endian + "QQ", self.data, offset + 8)
                result["entry_point"] = hex(entryoff)
                if entryoff < self.length:
                    result["entry_file_offset"] = hex(entryoff)

            offset += cmdsize

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
