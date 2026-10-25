"""
R3V3R53//F0RG3 — Phase 58: Go (`runtime.pclntab`) & Rust (`v0` / `_ZN`) Semantic Reconstructor
Recovers high-level function names, package namespaces, source files, and panic metadata from
stripped Go and Rust binaries:
  1. Go `runtime.pclntab` Parser across Go 1.2–1.15 (`0xfffffffb`), Go 1.16–1.17 (`0xfffffffa`),
     Go 1.18–1.19 (`0xfffffff0`), and Go 1.20–1.22+ (`0xfffffff1`) magic headers.
  2. Rust Symbol Demangler supporting both RFC 2627 `_R` v0 mangling (`_RNvCs..._4core3fmt5write`)
     and legacy `_ZN` Rust hash suffixes (`17h[0-9a-f]{16}E`).
  3. Rust Panic Location Extractor (`src/main.rs`, `core/src/panicking.rs`).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
import struct
from typing import Dict, List, Optional, Tuple


@dataclass
class GoRecoveredFunction:
    name: str
    package_name: str
    entry_va: str


@dataclass
class GoPclntabReport:
    present: bool
    go_version_family: str
    magic_hex: str
    pointer_size: int
    functions_recovered: List[GoRecoveredFunction] = field(default_factory=list)


@dataclass
class RustReconstructionReport:
    is_rust_binary: bool
    demangled_symbols: Dict[str, str]
    source_files: List[str]
    panic_strings: List[str]


class GoRustReconstructor:
    """
    Reconstructs Go `pclntab` function tables and demangles Rust `v0` (`_R`) and legacy (`_ZN`) symbols.
    """

    PCLNTAB_MAGICS: Dict[bytes, str] = {
        b"\xfb\xff\xff\xff\x00\x00": "Go_1.2_to_1.15",
        b"\xfa\xff\xff\xff\x00\x00": "Go_1.16_to_1.17",
        b"\xf0\xff\xff\xff\x00\x00": "Go_1.18_to_1.19",
        b"\xf1\xff\xff\xff\x00\x00": "Go_1.20_plus",
    }

    GO_FUNC_NAME_RE = re.compile(rb"\b((?:main|runtime|net/http|crypto/[a-z0-9]+|os|fmt|sync|syscall)\.[A-Za-z0-9_\.\*\(\)]+)\x00")
    RUST_HASH_SUFFIX_RE = re.compile(r"::h[0-9a-fA-F]{16}$")
    RUST_SOURCE_RE = re.compile(rb"([a-zA-Z0-9_\-/\\]+\.rs)")

    def parse_go_pclntab(self, binary_bytes: bytes) -> GoPclntabReport:
        """
        Scan `binary_bytes` for a valid Go `runtime.pclntab` header (`fb/fa/f0/f1 ff ff ff 00 00`),
        validate quantum (`1`, `2`, or `4`) and pointer size (`4` or `8`), and extract Go function names.
        """
        found_ver = ""
        found_magic = ""
        ptr_size = 8

        for magic_bytes, ver_name in self.PCLNTAB_MAGICS.items():
            idx = binary_bytes.find(magic_bytes)
            while idx != -1 and idx + 8 <= len(binary_bytes):
                quantum = binary_bytes[idx + 6]
                psize = binary_bytes[idx + 7]
                if quantum in (1, 2, 4) and psize in (4, 8):
                    found_ver = ver_name
                    found_magic = hex(struct.unpack_from("<I", magic_bytes, 0)[0])
                    ptr_size = psize
                    break
                idx = binary_bytes.find(magic_bytes, idx + 1)
            if found_ver:
                break

        funcs: List[GoRecoveredFunction] = []
        seen: set[str] = set()
        for m in self.GO_FUNC_NAME_RE.finditer(binary_bytes):
            full_name = m.group(1).decode("ascii", errors="ignore")
            if full_name not in seen:
                seen.add(full_name)
                pkg = full_name.split(".", 1)[0]
                funcs.append(
                    GoRecoveredFunction(
                        name=full_name,
                        package_name=pkg,
                        entry_va=hex(0x401000 + m.start()),
                    )
                )

        is_present = bool(found_ver or funcs)
        return GoPclntabReport(
            present=is_present,
            go_version_family=found_ver or ("Go_Heuristic" if funcs else "None"),
            magic_hex=found_magic or "0x0",
            pointer_size=ptr_size,
            functions_recovered=funcs,
        )

    def demangle_rust_symbol(self, mangled: str) -> str:
        """
        Demangle both Rust RFC 2627 `v0` symbols (`_RNvCs..._4core3fmt5write`)
        and legacy Rust `_ZN` symbols (`_ZN4core3fmt5write17h0123456789abcdefE`).
        """
        s = mangled.strip().lstrip("_")
        if s.startswith("R"):
            s = "_" + s
        elif s.startswith("ZN"):
            s = "_" + s

        # 1. RFC 2627 Rust v0 mangling (`_R...`)
        if s.startswith("_R"):
            rest = s[2:]
            # Strip optional crate disambiguator `Cs<base62>_`
            segments: List[str] = []
            pos = 0
            while pos < len(rest):
                # Skip namespace tags like Nv, Nt, NC, Cs..._
                if rest[pos : pos + 2] in ("Nv", "Nt", "NC"):
                    pos += 2
                    continue
                if rest[pos : pos + 2] == "Cs":
                    und = rest.find("_", pos + 2)
                    if und != -1:
                        pos = und + 1
                        continue
                m_len = re.match(r"^(\d+)", rest[pos:])
                if m_len:
                    n_len = int(m_len.group(1))
                    pos += len(m_len.group(1))
                    if rest[pos : pos + 1] == "_":
                        pos += 1
                    seg = rest[pos : pos + n_len]
                    if seg:
                        segments.append(seg)
                    pos += n_len
                else:
                    pos += 1
            return "::".join(segments) if segments else mangled

        # 2. Legacy Rust `_ZN...E` with trailing `17h<16-hex>` hash
        if s.startswith("_ZN"):
            from reverse_forge.cpp_rtti_engine import CppRTTIEngine
            dem = CppRTTIEngine().demangle_itanium_symbol(s).split("(", 1)[0]
            dem = dem.replace("$LT$", "<").replace("$GT$", ">").replace("$u20$", " ").replace("$C$", ",")
            dem = self.RUST_HASH_SUFFIX_RE.sub("", dem)
            return dem

        return mangled

    def reconstruct_rust_metadata(
        self,
        binary_bytes: bytes,
        symbols: Optional[List[str]] = None,
    ) -> RustReconstructionReport:
        sym_list = list(symbols or [])
        for m in re.finditer(rb"(_R[A-Za-z0-9_]+|_ZN[A-Za-z0-9_$]+E)", binary_bytes):
            sym_list.append(m.group(1).decode("ascii", errors="ignore"))

        demangled: Dict[str, str] = {}
        for sym in sorted(set(sym_list)):
            if sym.startswith(("_R", "R", "_ZN", "ZN")):
                demangled[sym] = self.demangle_rust_symbol(sym)

        src_files = sorted({
            m.group(1).decode("ascii", errors="ignore")
            for m in self.RUST_SOURCE_RE.finditer(binary_bytes)
        })
        panics = []
        if b"panicked at" in binary_bytes:
            panics.append("panicked at")
        if b"unwrap()` on a `None`" in binary_bytes:
            panics.append("called `Option::unwrap()` on a `None` value")

        is_rust = bool(demangled or src_files or panics or b"rustc" in binary_bytes)
        return RustReconstructionReport(
            is_rust_binary=is_rust,
            demangled_symbols=demangled,
            source_files=src_files[:50],
            panic_strings=panics,
        )
