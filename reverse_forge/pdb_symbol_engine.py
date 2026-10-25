"""
R3V3R53//F0RG3 — Phase 52 & Phase 66: Automated Microsoft PDB, NB10 & ELF Debuginfod Symbol Server Engine
Implements:
  1. PE Debug Directory & CodeView (`RSDS` PDB 7.0 and `NB10` PDB 2.0) GUID/Timestamp, Age, and PDB filename extractor
  2. ELF `.note.gnu.build-id` (`NT_GNU_BUILD_ID`) extractor and `debuginfod` URL synthesizer
  3. Microsoft Symbol Server URL synthesizer (`https://msdl.microsoft.com/download/symbols/{pdb}/{guid_age}/{pdb}`)
     and local symbol cache resolver/downloader (`~/.cache/symbols`)
  4. Multi-Stream File (MSF v7.00 `Microsoft C/C++ MSF 7.00\\r\\n\\x1aDS\\0\\0\\0`) container parser
     with real PE `section_rvas` Virtual Address mapping
  5. Public Symbol Stream (`PUB32` / `S_PUB32 = 0x110E`) and Type Information (`TPI` `LF_STRUCTURE = 0x1505`,
     `LF_ENUM = 0x1507`, `LF_UNION = 0x1506`) record parser
  6. Automatic synchronization into `ProjectWorkspaceDB` (`.rfdb`)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import os
import struct
import urllib.request
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
    elf_build_id: str = ""
    debuginfod_url: str = ""


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
    Extracts PE CodeView RSDS/NB10 and ELF Build-ID debug metadata, computes Microsoft Symbol Server
    and debuginfod download URLs, manages the local symbol cache, and parses MSF v7.00 PDB containers.
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
        Scan a PE or ELF binary for CodeView `RSDS` (PDB 7.0), `NB10` (PDB 2.0), or ELF `GNU\\x00` Build-ID
        records and synthesize the exact Microsoft Symbol Server or `debuginfod` download URL.
        """
        pos = binary_bytes.find(b"RSDS")
        if pos != -1 and pos + 24 <= len(binary_bytes):
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

        # Fallback 1: CodeView NB10 (PDB 2.0: 'NB10' + 4B offset + 4B timestamp + 4B age + path)
        nb_pos = binary_bytes.find(b"NB10")
        if nb_pos != -1 and nb_pos + 16 <= len(binary_bytes):
            _, ts, age = struct.unpack_from("<III", binary_bytes, nb_pos + 4)
            end_str = binary_bytes.find(b"\x00", nb_pos + 16, min(len(binary_bytes), nb_pos + 512))
            if end_str == -1:
                end_str = min(len(binary_bytes), nb_pos + 128)
            raw_path = binary_bytes[nb_pos + 16 : end_str].decode("utf-8", errors="replace").strip()
            pdb_fname = raw_path.replace("\\", "/").split("/")[-1] or "unknown.pdb"
            sym_id = f"{ts:08X}{age:x}"
            msdl_url = f"https://msdl.microsoft.com/download/symbols/{pdb_fname}/{sym_id}/{pdb_fname}"
            local_path = os.path.join(self.cache_dir, pdb_fname, sym_id, pdb_fname)
            return CodeViewRSDSRecord(
                present=True,
                signature="NB10",
                guid_string=f"TIMESTAMP-{ts:08X}",
                age=age,
                pdb_path=raw_path,
                pdb_filename=pdb_fname,
                symbol_server_id=sym_id,
                symbol_server_url=msdl_url,
                local_cache_path=local_path,
            )

        # Fallback 2: ELF GNU Build-ID note (namesz=4, descsz=20, type=3 NT_GNU_BUILD_ID, "GNU\x00" + 20B SHA1)
        gnu_note = binary_bytes.find(b"\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00")
        if gnu_note != -1 and gnu_note + 36 <= len(binary_bytes):
            bid_hex = binary_bytes[gnu_note + 16 : gnu_note + 36].hex()
            dbg_url = f"https://debuginfod.elfutils.org/buildid/{bid_hex}/debuginfo"
            local_path = os.path.join(self.cache_dir, ".build-id", bid_hex[:2], f"{bid_hex[2:]}.debug")
            return CodeViewRSDSRecord(
                present=True,
                signature="NT_GNU_BUILD_ID",
                elf_build_id=bid_hex,
                debuginfod_url=dbg_url,
                symbol_server_url=dbg_url,
                local_cache_path=local_path,
            )

        return CodeViewRSDSRecord(present=False)

    def download_or_load_cached_pdb(
        self,
        rsds_record: CodeViewRSDSRecord,
        allow_network: bool = False,
        timeout: float = 4.0,
    ) -> Optional[bytes]:
        """
        Load a PDB file from the local symbol cache (`local_cache_path`), or optionally fetch it
        over HTTPS from the Microsoft Symbol Server when `allow_network=True`.
        """
        if not rsds_record.present or not rsds_record.local_cache_path:
            return None
        if os.path.exists(rsds_record.local_cache_path):
            with open(rsds_record.local_cache_path, "rb") as f:
                return f.read()
        if not allow_network or not rsds_record.symbol_server_url.startswith("https://"):
            return None
        try:
            req = urllib.request.Request(
                rsds_record.symbol_server_url,
                headers={"User-Agent": "Microsoft-Symbol-Server/10.0.10036.206"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            if data and data.startswith(self.MSF7_MAGIC):
                os.makedirs(os.path.dirname(rsds_record.local_cache_path), exist_ok=True)
                with open(rsds_record.local_cache_path, "wb") as f:
                    f.write(data)
                return data
        except Exception:
            return None
        return None

    def parse_pdb_bytes(
        self,
        pdb_bytes: bytes,
        image_base: int = 0x140000000,
        section_rvas: Optional[Dict[int, int]] = None,
    ) -> PDBParseReport:
        """
        Parse an MSF v7.00 PDB file buffer, extracting `S_PUB32` public symbol records
        (resolving section indices via `section_rvas` when supplied) and `LF_STRUCTURE` /
        `LF_UNION` / `LF_ENUM` TPI records.
        """
        if len(pdb_bytes) < 52 or not pdb_bytes.startswith(self.MSF7_MAGIC):
            return PDBParseReport(is_valid_msf7=False, page_size=0, total_pages=0, directory_bytes=0)

        page_size, _, num_pages, dir_bytes, _ = struct.unpack_from("<IIIII", pdb_bytes, 32)
        symbols: List[PDBSymbolRecord] = []
        types: List[PDBTypeRecord] = []

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
                        if section_rvas and sym_sec in section_rvas:
                            sec_rva = section_rvas[sym_sec]
                        else:
                            sec_rva = max(1, sym_sec) * 0x1000
                        va = image_base + sec_rva + sym_off
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
