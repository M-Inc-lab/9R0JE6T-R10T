"""
R3V3R53//F0RG3  Streaming & Memory-Mapped PE Analysis Engine
============================================================
Phase 41: Zero-copy memory-mapped binary triage and chunked inspection.
Handles multi-megabyte/gigabyte PE binaries without exhausting heap memory.

Zero external dependencies — pure Python stdlib (mmap + struct + hashlib + math).
"""

from __future__ import annotations

import hashlib
import math
import mmap
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StreamingPESection:
    name: str
    virtual_size: int
    virtual_address: str
    raw_size: int
    raw_offset: str
    offset: str
    entropy: float
    executable: bool
    readable: bool
    writable: bool


@dataclass
class StreamingPEMetadata:
    artifact: str
    filename: str
    size_bytes: int
    hashes: Dict[str, str]
    format: str
    is_pe: bool
    architecture: str
    subsystem: str
    entry_point: str
    entry_file_offset: str
    image_base: str
    entropy: float
    characteristics: List[str]
    sections: List[StreamingPESection] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    timestamp: int = 0


class StreamingPEAnalyzer:
    """
    High-performance zero-copy PE analyzer utilizing memory-mapped I/O.
    Avoids copying large binary buffers into Python heap.
    """

    ARCH_MAP: Dict[int, str] = {
        0x014C: "x86 (32-bit)",
        0x8664: "x64 (64-bit AMD64)",
        0x0200: "IA64 (Intel Itanium)",
        0xAA64: "ARM64 (64-bit)",
        0x01C0: "ARM (32-bit)",
        0x01C4: "ARMv7 Thumb",
    }

    SUBSYSTEM_MAP: Dict[int, str] = {
        1: "NATIVE",
        2: "WINDOWS_GUI",
        3: "WINDOWS_CUI",
        5: "OS2_CUI",
        7: "POSIX_CUI",
        9: "WINDOWS_CE_GUI",
        10: "EFI_APPLICATION",
        11: "EFI_BOOT_SERVICE_DRIVER",
        12: "EFI_RUNTIME_DRIVER",
        13: "EFI_ROM",
        14: "XBOX",
        16: "WINDOWS_BOOT_APPLICATION",
    }

    CHARACTERISTIC_FLAGS: List[Tuple[int, str]] = [
        (0x0001, "RELOCS_STRIPPED"),
        (0x0002, "EXECUTABLE_IMAGE"),
        (0x0004, "LINE_NUMS_STRIPPED"),
        (0x0008, "LOCAL_SYMS_STRIPPED"),
        (0x0020, "LARGE_ADDRESS_AWARE"),
        (0x0100, "32BIT_MACHINE"),
        (0x0200, "DEBUG_STRIPPED"),
        (0x1000, "SYSTEM"),
        (0x2000, "DLL"),
    ]

    def __init__(self, filepath: str):
        self.filepath = os.path.abspath(filepath)
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Binary artifact not found: {self.filepath}")
        self.size_bytes = os.path.getsize(self.filepath)

    @staticmethod
    def calculate_entropy_chunked(buf: mmap.mmap | bytes, offset: int = 0, length: Optional[int] = None) -> float:
        """Calculate Shannon entropy over a buffer slice using fast C-accelerated counting."""
        import collections
        if length is None:
            length = len(buf) - offset
        if length <= 0:
            return 0.0

        take = min(length, 16 * 1024 * 1024)
        sample = buf[offset : offset + take]
        counts = collections.Counter(sample)

        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / take
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def calculate_hashes_streaming(self) -> Dict[str, str]:
        """Compute SHA256 and MD5 using 64KB streaming blocks."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5(usedforsecurity=False, )
        with open(self.filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
        return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}

    def analyze(self, include_hashes: bool = False) -> StreamingPEMetadata:
        """Zero-copy memory-mapped parse of PE headers and section structures."""
        warnings: List[str] = []
        hashes = self.calculate_hashes_streaming() if include_hashes else {}

        if self.size_bytes < 64:
            return StreamingPEMetadata(
                artifact=self.filepath,
                filename=os.path.basename(self.filepath),
                size_bytes=self.size_bytes,
                hashes=hashes,
                format="Unknown",
                is_pe=False,
                architecture="Unknown",
                subsystem="Unknown",
                entry_point="0x0",
                entry_file_offset="0x0",
                image_base="0x0",
                entropy=0.0,
                characteristics=[],
                warnings=["File too small for DOS header"],
            )

        with open(self.filepath, "rb") as f:
            # Memory-map the file in read-only mode
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                # Check DOS Header
                if mm[0:2] != b"MZ":
                    overall_entropy = self.calculate_entropy_chunked(mm, 0, self.size_bytes)
                    return StreamingPEMetadata(
                        artifact=self.filepath,
                        filename=os.path.basename(self.filepath),
                        size_bytes=self.size_bytes,
                        hashes=hashes,
                        format="Unknown",
                        is_pe=False,
                        architecture="Unknown",
                        subsystem="Unknown",
                        entry_point="0x0",
                        entry_file_offset="0x0",
                        image_base="0x0",
                        entropy=overall_entropy,
                        characteristics=[],
                        warnings=["Invalid MZ magic header"],
                    )

                # e_lfanew offset at 0x3C
                if len(mm) < 0x40:
                    warnings.append("Truncated DOS header")
                    return self._truncated_fallback(hashes, warnings, mm)

                e_lfanew = struct.unpack_from("<I", mm, 0x3C)[0]
                if e_lfanew + 24 > len(mm):
                    warnings.append("Corrupt e_lfanew offset pointing beyond EOF")
                    return self._truncated_fallback(hashes, warnings, mm)

                # Check PE Signature
                if mm[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
                    warnings.append("Invalid PE signature")
                    return self._truncated_fallback(hashes, warnings, mm)

                coff_offset = e_lfanew + 4
                machine, num_sections, timedatestamp, _, _, opt_size, characteristics_raw = struct.unpack_from(
                    "<HHIIIHH", mm, coff_offset
                )

                arch_str = self.ARCH_MAP.get(machine, f"Unknown (0x{machine:04X})")

                # Parse characteristics
                char_list = [name for flag, name in self.CHARACTERISTIC_FLAGS if characteristics_raw & flag]

                # Parse Optional Header
                opt_offset = coff_offset + 20
                entry_point_rva = 0
                image_base = 0
                subsystem_id = 0
                is_pe32_plus = False

                if opt_size >= 2:
                    magic = struct.unpack_from("<H", mm, opt_offset)[0]
                    is_pe32_plus = (magic == 0x020B)

                    if is_pe32_plus and opt_size >= 30:
                        entry_point_rva = struct.unpack_from("<I", mm, opt_offset + 16)[0]
                        image_base = struct.unpack_from("<Q", mm, opt_offset + 24)[0]
                        if opt_size >= 70:
                            subsystem_id = struct.unpack_from("<H", mm, opt_offset + 68)[0]
                    elif not is_pe32_plus and opt_size >= 28:
                        entry_point_rva = struct.unpack_from("<I", mm, opt_offset + 16)[0]
                        image_base = struct.unpack_from("<I", mm, opt_offset + 28)[0]
                        if opt_size >= 68:
                            subsystem_id = struct.unpack_from("<H", mm, opt_offset + 68)[0]

                subsystem_str = self.SUBSYSTEM_MAP.get(subsystem_id, f"UNKNOWN_{subsystem_id}")

                # Parse Section Table
                section_headers_offset = opt_offset + opt_size
                sections: List[StreamingPESection] = []
                entry_file_offset = 0

                for i in range(num_sections):
                    sec_hdr = section_headers_offset + (i * 40)
                    if sec_hdr + 40 > len(mm):
                        warnings.append("Truncated section header table")
                        break

                    name_bytes = mm[sec_hdr : sec_hdr + 8].rstrip(b"\x00")
                    name_str = name_bytes.decode("ascii", errors="replace").strip()
                    vsize, vaddr, raw_size, raw_ptr, _, _, _, _, sec_char = struct.unpack_from(
                        "<IIIIIIHHI", mm, sec_hdr + 8
                    )

                    # Section flags
                    readable = bool(sec_char & 0x40000000)
                    writable = bool(sec_char & 0x80000000)
                    executable = bool(sec_char & 0x20000000)

                    # Section entropy
                    sec_entropy = 0.0
                    if raw_ptr < len(mm) and raw_size > 0:
                        valid_len = min(raw_size, len(mm) - raw_ptr)
                        sec_entropy = self.calculate_entropy_chunked(mm, raw_ptr, valid_len)

                    # Check if entry point falls in this section
                    if entry_point_rva >= vaddr and entry_point_rva < (vaddr + max(vsize, raw_size)):
                        entry_file_offset = raw_ptr + (entry_point_rva - vaddr)

                    sections.append(
                        StreamingPESection(
                            name=name_str,
                            virtual_size=vsize,
                            virtual_address=hex(vaddr),
                            raw_size=raw_size,
                            raw_offset=hex(raw_ptr),
                            offset=hex(raw_ptr),
                            entropy=sec_entropy,
                            executable=executable,
                            readable=readable,
                            writable=writable,
                        )
                    )

                overall_entropy = self.calculate_entropy_chunked(mm, 0, self.size_bytes)

                return StreamingPEMetadata(
                    artifact=self.filepath,
                    filename=os.path.basename(self.filepath),
                    size_bytes=self.size_bytes,
                    hashes=hashes,
                    format="PE",
                    is_pe=True,
                    architecture=arch_str,
                    subsystem=subsystem_str,
                    entry_point=hex(entry_point_rva),
                    entry_file_offset=hex(entry_file_offset),
                    image_base=hex(image_base),
                    entropy=overall_entropy,
                    characteristics=char_list,
                    sections=sections,
                    warnings=warnings,
                    timestamp=timedatestamp,
                )

    def _truncated_fallback(self, hashes: Dict[str, str], warnings: List[str], mm: mmap.mmap) -> StreamingPEMetadata:
        return StreamingPEMetadata(
            artifact=self.filepath,
            filename=os.path.basename(self.filepath),
            size_bytes=self.size_bytes,
            hashes=hashes,
            format="Unknown/Damaged PE",
            is_pe=False,
            architecture="Unknown",
            subsystem="Unknown",
            entry_point="0x0",
            entry_file_offset="0x0",
            image_base="0x0",
            entropy=self.calculate_entropy_chunked(mm, 0, len(mm)),
            characteristics=[],
            warnings=warnings,
        )
