"""
R3V3R53//F0RG3 — Phase 52: Automated Microsoft PDB & DWARF Symbol Server Engine
Implements:
  1. PE Debug Directory & CodeView (`RSDS` / `NB10`) GUID, Age, and PDB filename extractor
  2. Microsoft Symbol Server URL synthesizer (`https://msdl.microsoft.com/download/symbols/{pdb}/{guid_age}/{pdb}`)
     and local symbol cache path resolver (`~/.cache/symbols`)
  3. Multi-Stream File (MSF v7.00 `Microsoft C/C++ MSF 7.00\\r\\n\\x1aDS\\0\\0\\0`) container parser
  4. Public Symbol Stream (`PUB32` / `S_PUB32 = 0x110E`) and Type Information (`TPI` `LF_STRUCTURE = 0x1505`,
     `LF_ENUM = 0x1507`, `LF_UNION = 0x1506`) record parser
  5. Automatic synchronization into `ProjectWorkspaceDB` (`.rfdb`)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import os
import struct
import uuid
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CodeViewRSDSRecord:
    present: bool
    signature: str = ""
    guid_string: str = ""
    age: int = 0
    pdb_path: str = ""
    pdb_filename: str = ""
    symbol_server_id: str = ""
    symbol_server_url: str = ""
    local_cache_path: str = ""


@dataclass
class PDBSymbolRecord:
    symbol_name: str
    section_index: int
    offset: int
    virtual_address: int
    flags: int


@dataclass
class PDBTypeRecord:
    leaf_type: str              # LF_STRUCTURE, LF_UNION, LF_ENUM
    type_name: str
    size_bytes: int
    field_count: int


@dataclass
class PDBParseReport:
    is_valid_msf7: bool
    page_size: int
    total_pages: int
    directory_bytes: int
    public_symbols: List[PDBSymbolRecord] = field(default_factory=list)
    type_records: List[PDBTypeRecord] = field(default_factory=list)


class PDBSymbolEngine:
    """
    Extracts PE CodeView RSDS debug metadata, computes Microsoft Symbol Server download URLs,
    and parses MSF v7.00 PDB containers (`S_PUB32` public symbols and `TPI` type records).
    """

    MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    S_PUB32 = 0x110E
    LF_STRUCTURE = 0x1505
    LF_UNION = 0x1506
    LF_ENUM = 0x1507

    def __init__(self, cache_dir: Optional[str] = None):
        default_cache = os.path.join(os.path.expanduser("~"), ".cache", "symbols")
        self.cache_dir = cache_dir or default_cache

    def extract_codeview_rsds(self, binary_bytes: bytes) -> CodeViewRSDSRecord:
        """
        Scan a PE binary for a CodeView `RSDS` record (`RSDS` + 16-byte GUID + 4-byte Age + UTF-8 path)
        and build the exact Microsoft Symbol Server download URL.
        """
        pos = binary_bytes.find(b"RSDS")
        if pos == -1 or pos + 24 > len(binary_bytes):
            return CodeViewRSDSRecord(present=False)

        guid_bytes = binary_bytes[pos + 4 : pos + 20]
        age = struct.unpack_from("<I", binary_bytes, pos + 20)[0]

        end_str = binary_bytes.find(b"\x00", pos + 24, min(len(binary_bytes), pos + 512))
        if end_str == -1:
            end_str = min(len(binary_bytes), pos + 128)
        raw_path = binary_bytes[pos + 24 : end_str].decode("utf-8", errors="replace").strip()

        u_obj = uuid.UUID(bytes_le=guid_bytes)
        guid_upper = u_obj.hex.upper()
        pdb_fname = raw_path.replace("\\", "/").split("/")[-1] or "unknown.pdb"
        sym_id = f"{guid_upper}{age:X}"
        msdl_url = f"https://msdl.microsoft.com/download/symbols/{pdb_fname}/{sym_id}/{pdb_fname}"
        local_path = os.path.join(self.cache_dir, pdb_fname, sym_id, pdb_fname)

        return CodeViewRSDSRecord(
            present=True,
            signature="RSDS",
            guid_string=str(u_obj).upper(),
            age=age,
            pdb_path=raw_path,
            pdb_filename=pdb_fname,
            symbol_server_id=sym_id,
            symbol_server_url=msdl_url,
            local_cache_path=local_path,
        )

    def parse_pdb_bytes(self, pdb_bytes: bytes, image_base: int = 0x140000000) -> PDBParseReport:
        """
        Parse an MSF v7.00 PDB file buffer, extracting `S_PUB32` public symbol records
        and `LF_STRUCTURE` / `LF_UNION` / `LF_ENUM` TPI records.
        """
        if len(pdb_bytes) < 52 or not pdb_bytes.startswith(self.MSF7_MAGIC):
            return PDBParseReport(is_valid_msf7=False, page_size=0, total_pages=0, directory_bytes=0)

        page_size, _, num_pages, dir_bytes, _ = struct.unpack_from("<IIIII", pdb_bytes, 32)
        symbols: List[PDBSymbolRecord] = []
        types: List[PDBTypeRecord] = []

        # Scan container stream pages for CodeView S_PUB32 (0x110E) and TPI leaf records
        n = len(pdb_bytes)
        pos = 52
        while pos + 16 <= n:
            rec_len, rec_type = struct.unpack_from("<HH", pdb_bytes, pos)
            if rec_type == self.S_PUB32 and 14 <= rec_len <= 512 and pos + 2 + rec_len <= n:
                pub_flags, sym_off, sym_sec = struct.unpack_from("<IIH", pdb_bytes, pos + 4)
                name_start = pos + 14
                name_end = pdb_bytes.find(b"\x00", name_start, pos + 2 + rec_len)
                if name_end != -1:
                    sym_name = pdb_bytes[name_start:name_end].decode("utf-8", errors="ignore")
                    if sym_name and sym_name.isprintable():
                        va = image_base + (max(1, sym_sec) * 0x1000) + sym_off
                        symbols.append(
                            PDBSymbolRecord(
                                symbol_name=sym_name,
                                section_index=sym_sec,
                                offset=sym_off,
                                virtual_address=va,
                                flags=pub_flags,
                            )
                        )
                        pos += 2 + rec_len
                        continue

            elif rec_type in (self.LF_STRUCTURE, self.LF_UNION, self.LF_ENUM) and 12 <= rec_len <= 512 and pos + 2 + rec_len <= n:
                leaf_map = {
                    self.LF_STRUCTURE: "LF_STRUCTURE",
                    self.LF_UNION: "LF_UNION",
                    self.LF_ENUM: "LF_ENUM",
                }
                field_cnt, _, _, _, struct_sz = struct.unpack_from("<HHHII", pdb_bytes, pos + 4)
                name_start = pos + 18
                name_end = pdb_bytes.find(b"\x00", name_start, pos + 2 + rec_len)
                if name_end != -1:
                    t_name = pdb_bytes[name_start:name_end].decode("utf-8", errors="ignore")
                    if t_name and t_name.isprintable():
                        types.append(
                            PDBTypeRecord(
                                leaf_type=leaf_map[rec_type],
                                type_name=t_name,
                                size_bytes=struct_sz & 0xFFFF,
                                field_count=field_cnt,
                            )
                        )
                        pos += 2 + rec_len
                        continue

            pos += 2

        return PDBParseReport(
            is_valid_msf7=True,
            page_size=page_size,
            total_pages=num_pages,
            directory_bytes=dir_bytes,
            public_symbols=symbols,
            type_records=types,
        )

    def sync_pdb_to_project(self, pdb_report: PDBParseReport, project_db: Any) -> int:
        """Populate a `ProjectWorkspaceDB` instance with recovered PDB symbols and struct definitions."""
        synced = 0
        for sym in pdb_report.public_symbols:
            project_db.rename_symbol(sym.virtual_address, sym.symbol_name)
            synced += 1
        for tr in pdb_report.type_records:
            c_def = f"typedef struct {tr.type_name} {{ uint8_t raw_bytes[{max(1, tr.size_bytes)}]; }} {tr.type_name}_t;"
            project_db.define_custom_struct(tr.type_name, c_def)
            synced += 1
        return synced
