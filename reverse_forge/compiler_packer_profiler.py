"""
R3V3R53//F0RG3 — Phase 47: Compiler, Packer, Rich Header & Import Hash (Imphash) Profiler
Modeled on:
  - Detect It Easy (DiE, https://github.com/horsicq/detect-it-easy) for compiler/linker/packer identification
  - Mandiant Imphash (https://cloud.google.com/blog/topics/threat-intelligence/tracking-malware-import-hashing/)
  - PE Rich Header (`Rich` / `DanS`) XOR decryption & MSVC toolchain build provenance
  - Appended Overlay Data detection & extraction after the last section boundary
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class RichHeaderEntry:
    product_id: int
    product_name: str
    build_version: int
    use_count: int


@dataclass
class RichHeaderReport:
    present: bool
    xor_key: str = "0x0"
    rich_hash_md5: str = ""
    entries: List[RichHeaderEntry] = field(default_factory=list)


@dataclass
class OverlayReport:
    has_overlay: bool
    overlay_offset: int
    overlay_size_bytes: int
    overlay_entropy: float
    overlay_magic_hint: str


@dataclass
class CompilerPackerProfile:
    detected_compilers: List[str]
    detected_packers_or_protectors: List[str]
    detected_runtime_language: str
    imphash_md5: str
    fuzzy_block_digest: str
    rich_header: RichHeaderReport
    overlay: OverlayReport


class CompilerPackerProfiler:
    """
    Fingerprints compilers, linkers, packers, runtime languages (Go, Rust, .NET, Python/PyInstaller,
    C/C++), decrypts PE Rich headers, computes Mandiant Imphash, and inspects trailing overlay data.
    """

    PRODID_MAP: Dict[int, str] = {
        0x0000: "Unknown/Import0",
        0x0001: "Linker_Import",
        0x0004: "Linker_600",
        0x005D: "MASM_800",
        0x0083: "Utc1500_C_VS2008",
        0x0084: "Utc1500_CPP_VS2008",
        0x0093: "Utc1600_C_VS2010",
        0x0094: "Utc1600_CPP_VS2010",
        0x00AA: "Utc1700_C_VS2012",
        0x00AB: "Utc1700_CPP_VS2012",
        0x00C7: "Utc1800_C_VS2013",
        0x00C8: "Utc1800_CPP_VS2013",
        0x00FF: "Utc1900_C_VS2015",
        0x0100: "Utc1900_CPP_VS2015",
        0x0104: "Linker_1400_VS2015",
        0x010E: "Utc1910_C_VS2017",
        0x010F: "Utc1910_CPP_VS2017",
        0x0114: "Utc1920_C_VS2019",
        0x0115: "Utc1920_CPP_VS2019",
        0x012D: "Utc1930_C_VS2022",
        0x012E: "Utc1930_CPP_VS2022",
    }

    def parse_pe_rich_header(self, data: bytes) -> RichHeaderReport:
        """
        Locate the `Rich` marker inside the DOS stub (0x40..e_lfanew), extract the 32-bit XOR key,
        decrypt backwards to the `DanS` signature (`0x536E6144`), and decode `(prodid, build, count)` records.
        """
        if len(data) < 0x80 or data[:2] != b"MZ":
            return RichHeaderReport(present=False)

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        search_end = min(len(data), max(e_lfanew, 0x200))
        stub = data[:search_end]

        rich_pos = stub.find(b"Rich")
        if rich_pos == -1 or rich_pos + 8 > len(stub):
            return RichHeaderReport(present=False)

        xor_key = struct.unpack_from("<I", stub, rich_pos + 4)[0]
        # Scan backwards from rich_pos in 4-byte steps to find `DanS` ^ xor_key
        dans_magic = 0x536E6144
        dans_pos: Optional[int] = None
        for pos in range(rich_pos - 4, 0x3C, -4):
            dword = struct.unpack_from("<I", stub, pos)[0]
            if (dword ^ xor_key) == dans_magic:
                dans_pos = pos
                break

        if dans_pos is None:
            return RichHeaderReport(present=False)

        decrypted_block = bytearray()
        entries: List[RichHeaderEntry] = []
        for pos in range(dans_pos, rich_pos, 4):
            dec_val = struct.unpack_from("<I", stub, pos)[0] ^ xor_key
            decrypted_block.extend(struct.pack("<I", dec_val))

        # First 16 bytes of decrypted DanS block are `DanS` + 3 zero padding dwords
        for off in range(16, len(decrypted_block), 8):
            if off + 8 > len(decrypted_block):
                break
            comp_id, use_count = struct.unpack_from("<II", decrypted_block, off)
            if comp_id == 0 and use_count == 0:
                continue
            prod_id = (comp_id >> 16) & 0xFFFF
            build_ver = comp_id & 0xFFFF
            entries.append(
                RichHeaderEntry(
                    product_id=prod_id,
                    product_name=self.PRODID_MAP.get(prod_id, f"MSVC_Tool_0x{prod_id:04x}"),
                    build_version=build_ver,
                    use_count=use_count,
                )
            )

        rich_hash = hashlib.md5(bytes(decrypted_block)).hexdigest()
        return RichHeaderReport(
            present=True,
            xor_key=f"0x{xor_key:08x}",
            rich_hash_md5=rich_hash,
            entries=entries,
        )

    @staticmethod
    def compute_imphash(imported_symbols: List[str], default_dll: str = "kernel32") -> str:
        """
        Compute Mandiant-compatible Import Hash (Imphash) by normalizing `dll.func` pairs
        to lowercase without extensions (`.dll`, `.ocx`, `.sys`) and hashing with MD5.
        """
        if not imported_symbols:
            return ""
        normalized: List[str] = []
        for entry in imported_symbols:
            s = str(entry).strip().lower().lstrip("_")
            if not s:
                continue
            if ":" in s:
                dll_part, fn_part = s.split(":", 1)
            elif "." in s and not s.endswith((".dll", ".so", ".dylib")):
                dll_part, fn_part = s.rsplit(".", 1)
            else:
                dll_part, fn_part = default_dll, s
            for ext in (".dll", ".ocx", ".sys", ".drv"):
                if dll_part.endswith(ext):
                    dll_part = dll_part[: -len(ext)]
            normalized.append(f"{dll_part}.{fn_part}")
        joined = ",".join(normalized)
        return hashlib.md5(joined.encode("utf-8")).hexdigest()

    @staticmethod
    def compute_fuzzy_block_digest(data: bytes, buckets: int = 16) -> str:
        """
        Compute a 16-bucket sliding-window quartile similarity digest (lightweight ssdeep/TLSH analog)
        for resilient binary family comparison.
        """
        if not data:
            return "0" * buckets
        counts = [0] * buckets
        step = max(1, len(data) // 4096)
        for i in range(0, len(data) - 3, step):
            h = ((data[i] * 31 + data[i + 1]) * 31 + data[i + 2]) % buckets
            counts[h] += 1
        avg = sum(counts) / max(1, buckets)
        hex_chars = []
        for c in counts:
            ratio = min(15, int((c / max(1.0, avg)) * 4))
            hex_chars.append(f"{ratio:x}")
        return "".join(hex_chars)

    def detect_overlay(self, data: bytes, sections: List[Dict[str, Any]]) -> OverlayReport:
        """
        Check if additional data (installer archives, digital signatures, config blobs)
        is appended after the highest raw section end in the binary.
        """
        if not sections or not data:
            return OverlayReport(False, 0, 0, 0.0, "None")

        max_end = 0
        for sec in sections:
            raw_off_s = str(sec.get("raw_offset") or sec.get("offset") or "0x0")
            raw_sz = int(sec.get("raw_size") or sec.get("size") or 0)
            try:
                raw_off = int(raw_off_s, 16) if raw_off_s.startswith("0x") else int(raw_off_s)
                if raw_sz > 0:
                    max_end = max(max_end, raw_off + raw_sz)
            except ValueError:
                continue

        if max_end == 0 or max_end >= len(data):
            return OverlayReport(False, 0, 0, 0.0, "None")

        ov_bytes = data[max_end:]
        from reverse_forge.pe_analyzer import PEAnalyzer
        ov_ent = PEAnalyzer.calculate_entropy(ov_bytes)

        magic_hint = "Raw_Binary_Overlay"
        if ov_bytes.startswith(b"PK\x03\x04"):
            magic_hint = "ZIP_or_JAR_Archive"
        elif ov_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
            magic_hint = "7z_Archive"
        elif ov_bytes.startswith(b"MEI\x0c\x0b\x0a\x0b\x0e") or b"MEI\x0c" in ov_bytes[:64]:
            magic_hint = "PyInstaller_CArchive"
        elif ov_bytes.startswith(b"\x1f\x8b\x08"):
            magic_hint = "GZIP_Archive"

        return OverlayReport(
            has_overlay=True,
            overlay_offset=max_end,
            overlay_size_bytes=len(ov_bytes),
            overlay_entropy=ov_ent,
            overlay_magic_hint=magic_hint,
        )

    def profile_binary(
        self,
        data: bytes,
        sections: Optional[List[Dict[str, Any]]] = None,
        imported_symbols: Optional[List[str]] = None,
    ) -> CompilerPackerProfile:
        """
        Execute full Detect-It-Easy style compiler, packer, Rich Header, Imphash, and Overlay profiling.
        """
        secs = sections or []
        imports = imported_symbols or []
        sec_names = {str(s.get("name", "")).strip() for s in secs}

        compilers: List[str] = []
        packers: List[str] = []
        lang = "C/C++ (Native)"

        rich = self.parse_pe_rich_header(data)
        if rich.present:
            compilers.append("Microsoft Visual C/C++ (Rich Header Verified)")

        if b"GCC: (" in data or b"clang version " in data:
            if b"clang version " in data:
                compilers.append("LLVM/Clang C/C++")
            if b"GCC: (" in data:
                compilers.append("GNU Compiler Collection (GCC)")

        if b"Go build ID:" in data or b"runtime.main" in data or ".gopclntab" in sec_names:
            compilers.append("Go Toolchain (gc)")
            lang = "Go (Golang)"

        if b"rustc version" in data or b"core::panicking" in data or b"_ZN4core9panicking" in data:
            compilers.append("Rust Compiler (rustc / LLVM)")
            lang = "Rust"

        if b"mscoree.dll" in data.lower() or b"BSJB" in data:
            compilers.append("Microsoft .NET CLR Compiler")
            lang = "C# / .NET CIL"

        if b"PyInstaller" in data or b"pyi-runtime-tmpdir" in data:
            packers.append("PyInstaller Frozen Python Bundle")
            lang = "Python (PyInstaller)"

        if b"UPX0" in data or b"UPX1" in data or b"UPX!" in data or "UPX0" in sec_names:
            packers.append("UPX (Ultimate Packer for eXecutables)")

        if ".vmp0" in sec_names or ".vmp1" in sec_names or b"VMProtect" in data:
            packers.append("VMProtect Virtualization Packer")

        if ".themida" in sec_names or b"Themida" in data:
            packers.append("Oreans Themida / WinLicense Protector")

        if b"NullsoftInst" in data:
            packers.append("NSIS (Nullsoft Scriptable Install System)")

        if not compilers:
            compilers.append("Generic Native Compiler / Stripped")

        imphash = self.compute_imphash(imports)
        fuzzy = self.compute_fuzzy_block_digest(data)
        overlay = self.detect_overlay(data, secs)

        return CompilerPackerProfile(
            detected_compilers=compilers,
            detected_packers_or_protectors=packers,
            detected_runtime_language=lang,
            imphash_md5=imphash,
            fuzzy_block_digest=fuzzy,
            rich_header=rich,
            overlay=overlay,
        )
