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

    def __init__(self, data: bytes):
        self.data = data
        self.length = len(data)

    def analyze(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "is_macho": False,
            "is_fat": False,
            "architecture": "Unknown",
            "file_type": "Unknown",
            "segments": [],
            "entropy": self.calculate_entropy(self.data),
            "warnings": []
        }

        if self.length < 4:
            result["warnings"].append("Artifact too small for Mach-O header")
            return result

        magic = struct.unpack_from(">I", self.data, 0)[0]

        if magic in (self.FAT_MAGIC, self.FAT_CIGAM):
            result["is_macho"] = True
            result["is_fat"] = True
            endian = ">" if magic == self.FAT_MAGIC else "<"
            nfat_arch = struct.unpack_from(endian + "I", self.data, 4)[0]
            result["architecture"] = f"Universal/Fat ({nfat_arch} architectures)"
            return result

        is_64 = magic in (self.MH_MAGIC_64, self.MH_CIGAM_64)
        is_32 = magic in (self.MH_MAGIC, self.MH_CIGAM)

        if not (is_64 or is_32):
            result["warnings"].append("Not a recognized Mach-O binary")
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

        offset = 32 if is_64 else 28
        for _ in range(ncmds):
            if offset + 8 > self.length:
                break
            cmd, cmdsize = struct.unpack_from(endian + "II", self.data, offset)
            if cmd in (0x1, 0x19):  # LC_SEGMENT or LC_SEGMENT_64
                segname = self.data[offset + 8:offset + 24].split(b"\x00")[0].decode("ascii", errors="replace")
                result["segments"].append({"name": segname, "command_size": cmdsize})
            offset += cmdsize

        return result

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        total = len(data)
        for c in counts:
            if c > 0:
                p = c / total
                entropy -= p * math.log2(p)
        return round(entropy, 4)
