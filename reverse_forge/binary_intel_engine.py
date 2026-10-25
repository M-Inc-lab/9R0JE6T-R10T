"""
R3V3R53//F0RG3 — Phase 43: Core Binary Intelligence, Capability Matcher, Xrefs & Smart Query Engine
Modeled on:
  - Mandiant CAPA (https://github.com/mandiant/capa) for behavioral capability detection & MITRE ATT&CK mapping
  - Cutter / Rizin (https://cutter.re/) for bidirectional CALL / JMP / RIP-relative cross-references
  - ImHex (https://github.com/werwolv/imhex) for multi-representation binary Data Inspection
Provides high-level helper functions so analysts can immediately extract the exact information they need:
  1. `detect_capabilities()` — Maps imports, strings, and byte idioms to behavioral capabilities & ATT&CK IDs
  2. `extract_all_xrefs()`   — Discovers direct CALL, JMP, and x86-64 RIP-relative LEA/MOV cross-references
  3. `inspect_offset()`      — Decodes any offset/VA into 14 data types (ints, floats, timestamps, GUID, asm)
  4. `find_patterns()`       — Searches ASCII, UTF-16LE, 32/64-bit constants, and wildcard hex patterns
  5. `get_full_dossier()`    — Generates a unified one-stop executive & technical binary intelligence dossier
  6. `smart_query()`         — Answers natural/keyword/address queries ("network", "crypto", "urls", "0x401000")
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import hashlib
import os
import re
import struct
import uuid
from typing import Any, Dict, List, Optional, Tuple

from reverse_forge.correlation_engine import CorrelationEngine
from reverse_forge.pe_analyzer import PEAnalyzer
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.macho_analyzer import MachOAnalyzer
from reverse_forge.decompiler_engine import MicroDecompilerEngine
from reverse_forge.cpp_rtti_engine import CppRTTIEngine


@dataclass
class CapabilityMatch:
    capability_id: str
    name: str
    namespace: str
    mitre_attack: str
    mbc_id: str
    severity: str               # HIGH, MEDIUM, INFO
    matched_indicators: List[str]
    description: str


@dataclass
class CrossReferenceItem:
    from_va: str
    from_file_offset: str
    to_va: str
    xref_type: str              # CALL_REL32, JMP_REL32, RIP_RELATIVE_LEA, RIP_RELATIVE_MOV
    instruction: str
    resolved_target_preview: str = ""


@dataclass
class DataInspectionResult:
    query_offset_or_va: str
    file_offset: int
    virtual_address: str
    containing_section: str
    raw_hex_16b: str
    uint8: int
    int8: int
    uint16_le: int
    int16_le: int
    uint32_le: int
    int32_le: int
    uint64_le: int
    int64_le: int
    float32_le: float
    float64_le: float
    unix_timestamp_iso: str
    windows_filetime_iso: str
    guid_uuid: str
    ascii_string: str
    utf16le_string: str
    disassembly_preview: List[str]


@dataclass
class PatternHit:
    file_offset: str
    virtual_address: str
    section_name: str
    match_type: str
    matched_value: str
    context_hex: str


@dataclass
class SmartQueryAnswer:
    query: str
    intent_classified: str
    summary_answer: str
    total_matches: int
    results: List[Dict[str, Any]] = field(default_factory=list)


class BinaryIntelEngine:
    """
    Unified intelligence hub that answers user questions about any binary artifact
    (PE, ELF, Mach-O, or raw firmware) in a single call.
    """

    # CAPA-inspired behavioral capability taxonomy
    CAPABILITY_RULES: List[Dict[str, Any]] = [
        {
            "id": "CAP-NET-001",
            "name": "Perform Network Socket / HTTP Communication",
            "namespace": "communication/socket",
            "mitre": "T1071.001 (Application Layer Protocol)",
            "mbc": "C0001 (Socket Communication)",
            "severity": "MEDIUM",
            "apis": {
                "socket", "connect", "bind", "listen", "accept", "send", "recv",
                "WSAStartup", "WSASocketA", "WSASocketW", "WSAConnect",
                "InternetOpenA", "InternetOpenW", "InternetConnectA", "HttpOpenRequestA",
                "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "URLDownloadToFileA",
                "curl_easy_init", "curl_easy_perform", "getaddrinfo", "gethostbyname",
            },
            "strings": [r"https?://", r"User-Agent:", r"POST /", r"GET /"],
            "desc": "Binary contains socket or HTTP client indicators capable of outbound/inbound network transfer.",
        },
        {
            "id": "CAP-PROC-002",
            "name": "Allocate or Inject Cross-Process Virtual Memory",
            "namespace": "host-interaction/process/inject",
            "mitre": "T1055 (Process Injection)",
            "mbc": "E1055 (Process Injection)",
            "severity": "HIGH",
            "apis": {
                "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "NtMapViewOfSection", "QueueUserAPC", "SetThreadContext",
                "OpenProcess", "VirtualProtect", "VirtualProtectEx", "mprotect", "ptrace",
            },
            "strings": [r"/proc/self/mem", r"NtCreateThreadEx"],
            "desc": "Binary imports memory-protection or remote-process manipulation primitives.",
        },
        {
            "id": "CAP-EXEC-003",
            "name": "Execute External Commands or Subprocesses",
            "namespace": "host-interaction/process/create",
            "mitre": "T1059 (Command and Scripting Interpreter)",
            "mbc": "C0017 (Create Process)",
            "severity": "HIGH",
            "apis": {
                "system", "popen", "execve", "execvp", "execl", "fork", "vfork",
                "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
                "WinExec", "CreateProcessAsUserA", "CreateProcessWithTokenW",
            },
            "strings": [r"cmd\.exe", r"powershell", r"/bin/sh", r"/bin/bash"],
            "desc": "Binary can spawn child processes or invoke system command interpreters.",
        },
        {
            "id": "CAP-CRYP-004",
            "name": "Perform Cryptographic Encryption or Hashing",
            "namespace": "data-manipulation/encryption",
            "mitre": "T1027 (Obfuscated Files or Information)",
            "mbc": "C0027 (Cryptography)",
            "severity": "MEDIUM",
            "apis": {
                "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
                "CryptCreateHash", "CryptHashData", "BCryptEncrypt", "BCryptDecrypt",
                "BCryptGenRandom", "EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "AES_encrypt",
                "SHA256_Update", "MD5_Init",
            },
            "strings": [r"AES-", r"RSA", r"SHA256", r"BEGIN PUBLIC KEY", r"BEGIN PRIVATE KEY"],
            "desc": "Binary invokes OS or OpenSSL cryptographic providers or hashing routines.",
        },
        {
            "id": "CAP-ANTI-005",
            "name": "Detect Debugger or Analysis Sandbox Environment",
            "namespace": "anti-analysis/anti-debugging",
            "mitre": "T1622 (Debugger Evasion)",
            "mbc": "B0001 (Debugger Detection)",
            "severity": "HIGH",
            "apis": {
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                "OutputDebugStringA", "GetTickCount", "QueryPerformanceCounter",
            },
            "strings": [r"SbieDll\.dll", r"VBoxMouse", r"vmware", r"wireshark", r"TracerPid"],
            "desc": "Binary checks for attached debuggers, timing anomalies, or virtualization artifacts.",
        },
        {
            "id": "CAP-PERS-006",
            "name": "Modify Windows Registry or Service Persistence",
            "namespace": "persistence/registry-or-service",
            "mitre": "T1547.001 (Registry Run Keys / Startup Folder)",
            "mbc": "F0012 (Modify Registry)",
            "severity": "MEDIUM",
            "apis": {
                "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
                "RegCreateKeyExA", "OpenSCManagerA", "CreateServiceA", "CreateServiceW",
                "StartServiceA",
            },
            "strings": [r"CurrentVersion\\Run", r"SYSTEM\\CurrentControlSet\\Services"],
            "desc": "Binary accesses registry configuration keys or Windows Service Control Manager APIs.",
        },
        {
            "id": "CAP-FILE-007",
            "name": "Enumerate or Manipulate Host Filesystem",
            "namespace": "host-interaction/file-system",
            "mitre": "T1083 (File and Directory Discovery)",
            "mbc": "C0045 (File System)",
            "severity": "INFO",
            "apis": {
                "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "DeleteFileA",
                "FindFirstFileA", "FindNextFileA", "CopyFileA", "MoveFileExA",
                "fopen", "fread", "fwrite", "unlink", "opendir", "readdir",
            },
            "strings": [r"C:\\Windows\\", r"/etc/passwd", r"/tmp/"],
            "desc": "Binary performs file creation, reading, writing, or directory traversal.",
        },
        {
            "id": "CAP-DYN-008",
            "name": "Resolve Functions Dynamically at Runtime",
            "namespace": "linking/runtime-import",
            "mitre": "T1129 (Shared Modules)",
            "mbc": "C0026 (Dynamic Linking)",
            "severity": "INFO",
            "apis": {
                "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress",
                "LdrLoadDll", "LdrGetProcedureAddress", "dlopen", "dlsym",
            },
            "strings": [],
            "desc": "Binary dynamically loads shared libraries and resolves function pointers by name.",
        },
    ]

    def __init__(self, binary_bytes: bytes, filepath: str = "<memory>"):
        self.binary_bytes = binary_bytes
        self.filepath = filepath
        self.corr = CorrelationEngine()
        self.format_name = self.corr.identify_format(binary_bytes)
        if self.format_name == "PE":
            self.metadata = PEAnalyzer(binary_bytes).analyze()
        elif self.format_name == "ELF":
            self.metadata = ELFAnalyzer(binary_bytes).analyze()
        elif self.format_name == "Mach-O":
            self.metadata = MachOAnalyzer(binary_bytes).analyze()
        else:
            self.metadata = {
                "format": self.format_name,
                "entropy": PEAnalyzer.calculate_entropy(binary_bytes),
                "sections": [],
                "imported_symbols": [],
                "exported_symbols": [],
            }
        self.extracted_strings = self.extract_strings_from_bytes(binary_bytes, min_len=4)

    @staticmethod
    def extract_strings_from_bytes(data: bytes, min_len: int = 4) -> Dict[str, List[str]]:
        ascii_re = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
        raw_strs = [m.group(0).decode("ascii", errors="ignore") for m in ascii_re.finditer(data[:2 * 1024 * 1024])]
        urls, ips, paths, registry, general = [], [], [], [], []
        for st in raw_strs:
            if "http://" in st or "https://" in st:
                urls.append(st)
            elif re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", st):
                ips.append(st)
            elif "Software\\" in st or "CurrentVersion\\" in st or "HKEY_" in st:
                registry.append(st)
            elif ":\\" in st or st.startswith(("/bin/", "/usr/", "/etc/", "/proc/", "/tmp/")):
                paths.append(st)
            else:
                general.append(st)
        return {"urls": urls, "ips": ips, "paths": paths, "registry": registry, "general": general[:200]}

    def _file_offset_to_va(self, file_offset: int) -> Tuple[int, str]:
        """Convert a file offset into (virtual_address, section_name)."""
        image_base_str = str(self.metadata.get("image_base", "0x400000"))
        try:
            image_base = int(image_base_str, 16) if image_base_str.startswith("0x") else int(image_base_str)
        except ValueError:
            image_base = 0x400000 if self.format_name != "PE" else 0x140000000

        for sec in self.metadata.get("sections", []):
            raw_str = str(sec.get("raw_offset") or sec.get("offset") or "0x0")
            vaddr_str = str(sec.get("virtual_address") or "0x0")
            raw_size = int(sec.get("raw_size") or sec.get("size") or 0)
            try:
                raw_off = int(raw_str, 16) if raw_str.startswith("0x") else int(raw_str)
                vaddr = int(vaddr_str, 16) if vaddr_str.startswith("0x") else int(vaddr_str)
                if raw_off <= file_offset < raw_off + max(raw_size, 1):
                    va = (image_base + vaddr + (file_offset - raw_off)) if vaddr < image_base else (vaddr + (file_offset - raw_off))
                    return va, str(sec.get("name", ".unknown"))
            except ValueError:
                continue
        return image_base + file_offset, "HEADER/RAW"

    def _va_to_file_offset(self, va_or_off: int) -> int:
        """Convert a Virtual Address or RVA or file offset into a valid file offset."""
        if 0 <= va_or_off < len(self.binary_bytes):
            return va_or_off
        image_base_str = str(self.metadata.get("image_base", "0x400000"))
        try:
            image_base = int(image_base_str, 16) if image_base_str.startswith("0x") else int(image_base_str)
        except ValueError:
            image_base = 0x140000000
        rva = va_or_off - image_base if va_or_off >= image_base else va_or_off
        for sec in self.metadata.get("sections", []):
            raw_str = str(sec.get("raw_offset") or sec.get("offset") or "0x0")
            vaddr_str = str(sec.get("virtual_address") or "0x0")
            vsize = int(sec.get("virtual_size") or sec.get("raw_size") or 0)
            try:
                raw_off = int(raw_str, 16) if raw_str.startswith("0x") else int(raw_str)
                vaddr = int(vaddr_str, 16) if vaddr_str.startswith("0x") else int(vaddr_str)
                if vaddr <= rva < vaddr + max(vsize, 1):
                    cand = raw_off + (rva - vaddr)
                    if 0 <= cand < len(self.binary_bytes):
                        return cand
            except ValueError:
                continue
        return max(0, min(len(self.binary_bytes) - 1, rva))

    def detect_capabilities(self) -> List[CapabilityMatch]:
        """
        Phase 43.1: Detect CAPA-style behavioral capabilities across imported APIs
        and embedded strings, returning MITRE ATT&CK and Malware Behavior Catalog (MBC) mappings.
        """
        imports_raw = [str(s).lstrip("_") for s in self.metadata.get("imported_symbols", [])]
        imports_lower = {s.lower(): s for s in imports_raw}

        all_strs: List[str] = []
        for cat_list in self.extracted_strings.values():
            if isinstance(cat_list, list):
                all_strs.extend(str(x) for x in cat_list)

        matches: List[CapabilityMatch] = []
        for rule in self.CAPABILITY_RULES:
            hits: List[str] = []
            for api in rule["apis"]:
                if api.lower() in imports_lower:
                    hits.append(f"import:{imports_lower[api.lower()]}")
            for pat in rule["strings"]:
                regex = re.compile(pat, re.IGNORECASE)
                for s in all_strs:
                    if regex.search(s):
                        hits.append(f"string:{s[:48]}")
                        break
            if hits:
                matches.append(
                    CapabilityMatch(
                        capability_id=rule["id"],
                        name=rule["name"],
                        namespace=rule["namespace"],
                        mitre_attack=rule["mitre"],
                        mbc_id=rule["mbc"],
                        severity=rule["severity"],
                        matched_indicators=sorted(set(hits)),
                        description=rule["desc"],
                    )
                )
        return matches

    def extract_all_xrefs(self, max_xrefs: int = 128) -> List[CrossReferenceItem]:
        """
        Phase 43.2: Scan executable code for direct relative CALL (`E8 rel32`),
        relative JMP (`E9 rel32`), and x86-64 RIP-relative LEA/MOV (`48 8D / 48 8B [rip + disp32]`),
        resolving target strings or function addresses automatically.
        """
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(self.binary_bytes, self.metadata)
        base_va = entry_va or 0x401000
        entry_off_str = str(self.metadata.get("entry_file_offset", "0x0"))
        try:
            base_file_off = int(entry_off_str, 16) if entry_off_str.startswith("0x") else int(entry_off_str)
        except ValueError:
            base_file_off = 0

        xrefs: List[CrossReferenceItem] = []
        n = len(code_slice)
        i = 0
        while i < n and len(xrefs) < max_xrefs:
            b = code_slice[i]
            curr_va = base_va + i
            curr_off = base_file_off + i

            # 1. Direct relative CALL: E8 rel32
            if b == 0xE8 and i + 5 <= n:
                rel32 = struct.unpack_from("<i", code_slice, i + 1)[0]
                target_va = (curr_va + 5 + rel32) & 0xFFFFFFFFFFFFFFFF
                if abs(rel32) < 0x1000000:
                    xrefs.append(
                        CrossReferenceItem(
                            from_va=hex(curr_va),
                            from_file_offset=hex(curr_off),
                            to_va=hex(target_va),
                            xref_type="CALL_REL32",
                            instruction=f"call {hex(target_va)}",
                            resolved_target_preview=f"sub_{target_va:x}",
                        )
                    )
                    i += 5
                    continue

            # 2. Direct relative JMP: E9 rel32
            if b == 0xE9 and i + 5 <= n:
                rel32 = struct.unpack_from("<i", code_slice, i + 1)[0]
                target_va = (curr_va + 5 + rel32) & 0xFFFFFFFFFFFFFFFF
                if abs(rel32) < 0x1000000:
                    xrefs.append(
                        CrossReferenceItem(
                            from_va=hex(curr_va),
                            from_file_offset=hex(curr_off),
                            to_va=hex(target_va),
                            xref_type="JMP_REL32",
                            instruction=f"jmp {hex(target_va)}",
                            resolved_target_preview=f"loc_{target_va:x}",
                        )
                    )
                    i += 5
                    continue

            # 3. x86-64 RIP-relative LEA or MOV: 48 8D / 48 8B modrm(00_reg_101) disp32
            if i + 7 <= n and b in (0x48, 0x4C) and code_slice[i + 1] in (0x8D, 0x8B):
                modrm = code_slice[i + 2]
                if (modrm & 0xC7) == 0x05:
                    disp32 = struct.unpack_from("<i", code_slice, i + 3)[0]
                    target_va = (curr_va + 7 + disp32) & 0xFFFFFFFFFFFFFFFF
                    target_off = curr_off + 7 + disp32
                    preview = ""
                    if 0 <= target_off < len(self.binary_bytes):
                        raw_s = self.binary_bytes[target_off : target_off + 40].split(b"\x00", 1)[0]
                        if len(raw_s) >= 3 and all(0x20 <= c <= 0x7E for c in raw_s):
                            preview = f'"{raw_s.decode("ascii", errors="ignore")}"'
                    mnem = "lea" if code_slice[i + 1] == 0x8D else "mov"
                    xrefs.append(
                        CrossReferenceItem(
                            from_va=hex(curr_va),
                            from_file_offset=hex(curr_off),
                            to_va=hex(target_va),
                            xref_type=f"RIP_RELATIVE_{mnem.upper()}",
                            instruction=f"{mnem} reg, [rip + {hex(disp32)}]",
                            resolved_target_preview=preview or f"data_{target_va:x}",
                        )
                    )
                    i += 7
                    continue

            i += 1
        return xrefs

    def inspect_offset(self, offset_or_va: str | int) -> DataInspectionResult:
        """
        Phase 43.3: ImHex-style 14-format Data Inspector at any file offset or Virtual Address.
        """
        if isinstance(offset_or_va, str):
            s = offset_or_va.strip()
            val = int(s, 16) if s.lower().startswith("0x") else int(s, 10)
        else:
            val = int(offset_or_va)

        file_off = self._va_to_file_offset(val) if len(self.binary_bytes) > 0 else 0
        va_int, sec_name = self._file_offset_to_va(file_off)

        window = self.binary_bytes[file_off : file_off + 64]
        padded = window.ljust(64, b"\x00")

        u8 = struct.unpack_from("<B", padded, 0)[0]
        i8 = struct.unpack_from("<b", padded, 0)[0]
        u16 = struct.unpack_from("<H", padded, 0)[0]
        i16 = struct.unpack_from("<h", padded, 0)[0]
        u32 = struct.unpack_from("<I", padded, 0)[0]
        i32 = struct.unpack_from("<i", padded, 0)[0]
        u64 = struct.unpack_from("<Q", padded, 0)[0]
        i64 = struct.unpack_from("<q", padded, 0)[0]
        f32 = struct.unpack_from("<f", padded, 0)[0]
        f64 = struct.unpack_from("<d", padded, 0)[0]

        if not (-1e30 < f32 < 1e30):
            f32 = 0.0
        if not (-1e30 < f64 < 1e30):
            f64 = 0.0

        # Unix timestamp (if u32 is between 1990 and 2050)
        unix_iso = "N/A"
        if 631152000 <= u32 <= 2524608000:
            try:
                unix_iso = datetime.datetime.fromtimestamp(u32, tz=datetime.timezone.utc).isoformat()
            except Exception:
                pass

        # Windows FILETIME (100-ns intervals since Jan 1, 1601)
        ft_iso = "N/A"
        if 120000000000000000 <= u64 <= 150000000000000000:
            try:
                unix_ts = (u64 - 116444736000000000) / 10_000_000
                ft_iso = datetime.datetime.fromtimestamp(unix_ts, tz=datetime.timezone.utc).isoformat()
            except Exception:
                pass

        try:
            guid_str = str(uuid.UUID(bytes_le=padded[:16]))
        except Exception:
            guid_str = "00000000-0000-0000-0000-000000000000"

        ascii_chars = []
        for b in window[:32]:
            if b == 0:
                break
            ascii_chars.append(chr(b) if 0x20 <= b <= 0x7E else ".")
        ascii_str = "".join(ascii_chars)

        try:
            u16_raw = window[:32].decode("utf-16le", errors="ignore").split("\x00", 1)[0]
            utf16_str = "".join(ch if 0x20 <= ord(ch) <= 0x7E else "." for ch in u16_raw)
        except Exception:
            utf16_str = ""

        decomp = MicroDecompilerEngine()
        insns = decomp._fallback_decode_x86(window[:24], va_int)
        disasm_preview = [f"{hex(a)}: {m} {op}".strip() for a, m, op in insns[:5]]

        return DataInspectionResult(
            query_offset_or_va=hex(val),
            file_offset=file_off,
            virtual_address=hex(va_int),
            containing_section=sec_name,
            raw_hex_16b=window[:16].hex(" ").upper(),
            uint8=u8,
            int8=i8,
            uint16_le=u16,
            int16_le=i16,
            uint32_le=u32,
            int32_le=i32,
            uint64_le=u64,
            int64_le=i64,
            float32_le=round(float(f32), 6),
            float64_le=round(float(f64), 6),
            unix_timestamp_iso=unix_iso,
            windows_filetime_iso=ft_iso,
            guid_uuid=guid_str,
            ascii_string=ascii_str,
            utf16le_string=utf16_str,
            disassembly_preview=disasm_preview,
        )

    def find_patterns(self, query_pattern: str, max_hits: int = 50) -> List[PatternHit]:
        """
        Phase 43.4: Search binary for ASCII strings, UTF-16LE wide strings, or hex byte patterns
        (including `??` wildcards like `48 89 E5 ??`) and resolve every match to its VA and section.
        """
        q = query_pattern.strip()
        hits: List[PatternHit] = []
        if not q:
            return hits

        # Check if query is a hex byte pattern (e.g. "48 89 e5" or "48 89 ??")
        tokens = q.split()
        is_hex_pat = len(tokens) >= 2 and all(
            t == "??" or (len(t) == 2 and all(c in "0123456789abcdefABCDEF" for c in t))
            for t in tokens
        )

        if is_hex_pat:
            regex_bytes = b"".join(b"." if t == "??" else re.escape(bytes.fromhex(t)) for t in tokens)
            for m in re.finditer(regex_bytes, self.binary_bytes, re.DOTALL):
                off = m.start()
                va, sec = self._file_offset_to_va(off)
                hits.append(
                    PatternHit(
                        file_offset=hex(off),
                        virtual_address=hex(va),
                        section_name=sec,
                        match_type="HEX_PATTERN",
                        matched_value=self.binary_bytes[off : off + len(tokens)].hex(" ").upper(),
                        context_hex=self.binary_bytes[off : off + 16].hex(" ").upper(),
                    )
                )
                if len(hits) >= max_hits:
                    break
            return hits

        # Otherwise search case-insensitive ASCII and UTF-16LE
        try:
            pat_ascii = re.compile(re.escape(q.encode("ascii", errors="ignore")), re.IGNORECASE)
            for m in pat_ascii.finditer(self.binary_bytes):
                off = m.start()
                va, sec = self._file_offset_to_va(off)
                snippet = self.binary_bytes[off : off + 48].split(b"\x00", 1)[0].decode("ascii", errors="replace")
                hits.append(
                    PatternHit(
                        file_offset=hex(off),
                        virtual_address=hex(va),
                        section_name=sec,
                        match_type="ASCII_STRING",
                        matched_value=snippet,
                        context_hex=self.binary_bytes[off : off + 16].hex(" ").upper(),
                    )
                )
                if len(hits) >= max_hits:
                    return hits

            pat_u16 = re.compile(re.escape(q.encode("utf-16le", errors="ignore")), re.IGNORECASE)
            for m in pat_u16.finditer(self.binary_bytes):
                off = m.start()
                va, sec = self._file_offset_to_va(off)
                snippet = self.binary_bytes[off : off + 64].decode("utf-16le", errors="ignore").split("\x00", 1)[0]
                hits.append(
                    PatternHit(
                        file_offset=hex(off),
                        virtual_address=hex(va),
                        section_name=sec,
                        match_type="UTF16LE_STRING",
                        matched_value=snippet,
                        context_hex=self.binary_bytes[off : off + 16].hex(" ").upper(),
                    )
                )
                if len(hits) >= max_hits:
                    break
        except Exception:
            pass

        return hits

    def get_full_dossier(self) -> Dict[str, Any]:
        """
        Phase 43.5: Produce a unified one-stop executive & technical dossier for the binary.
        """
        caps = self.detect_capabilities()
        xrefs = self.extract_all_xrefs(max_xrefs=32)
        rtti = CppRTTIEngine().analyze_binary_rtti(
            self.binary_bytes,
            symbol_list=self.metadata.get("imported_symbols", []) + self.metadata.get("exported_symbols", []),
        )
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(self.binary_bytes, self.metadata)
        base_va = entry_va or 0x401000
        decomp = MicroDecompilerEngine()
        dfunc = decomp.decompile_raw_bytes(code_slice, base_addr=base_va)
        insns = decomp._fallback_decode_x86(code_slice[:256], base_va)
        structured = decomp.decompile_structured(insns, func_name="entry_main")

        return {
            "artifact": os.path.abspath(self.filepath) if os.path.exists(self.filepath) else self.filepath,
            "size_bytes": len(self.binary_bytes),
            "sha256": hashlib.sha256(self.binary_bytes).hexdigest(),
            "format": self.format_name,
            "architecture": self.metadata.get("architecture", "x64"),
            "entry_point": self.metadata.get("entry_point", hex(base_va)),
            "image_base": self.metadata.get("image_base", "0x400000"),
            "entropy": self.metadata.get("entropy", 0.0),
            "mitigations": self.metadata.get("mitigations", {}),
            "sections": self.metadata.get("sections", []),
            "imported_symbols_count": len(self.metadata.get("imported_symbols", [])),
            "imported_symbols": self.metadata.get("imported_symbols", [])[:100],
            "exported_symbols": self.metadata.get("exported_symbols", [])[:100],
            "capabilities_count": len(caps),
            "capabilities": [asdict(c) for c in caps],
            "cpp_classes_recovered": rtti.total_classes_recovered,
            "cpp_classes": [asdict(c) for c in rtti.classes[:20]],
            "categorized_strings": {
                k: v[:30] for k, v in self.extracted_strings.items() if isinstance(v, list)
            },
            "top_xrefs": [asdict(x) for x in xrefs],
            "decompiled_entry_c": dfunc.c_source,
            "structured_goto_free_c": structured.structured_c,
            "compiler_packer_profile": asdict(
                __import__("reverse_forge.compiler_packer_profiler", fromlist=["CompilerPackerProfiler"])
                .CompilerPackerProfiler()
                .profile_binary(
                    self.binary_bytes,
                    sections=self.metadata.get("sections", []),
                    imported_symbols=self.metadata.get("imported_symbols", []),
                )
            ),
            "deobfuscated_strings": asdict(
                __import__("reverse_forge.string_deobfuscator", fromlist=["ObfuscatedStringSolver"])
                .ObfuscatedStringSolver()
                .deobfuscate_all_strings(self.binary_bytes)
            ),
            "direct_syscalls": [
                asdict(s)
                for s in __import__("reverse_forge.syscall_struct_engine", fromlist=["SyscallAndStructEngine"])
                .SyscallAndStructEngine()
                .resolve_direct_syscalls(code_slice[:512], base_va=base_va)
            ],
        }

    def smart_query(self, query: str) -> SmartQueryAnswer:
        """
        Phase 43.6: Natural & structured query dispatcher that helps the user get the exact
        information they are looking for (`network`, `crypto`, `urls`, `mitigations`, `imports`,
        `exports`, `sections`, `xrefs`, `0x401000`, or any symbol/string substring).
        """
        q = query.strip()
        ql = q.lower()

        # 1. Address / Offset inspection query (e.g. "0x401000" or "offset 64")
        if re.match(r"^(?:0x[0-9a-fA-F]+|\d+)$", ql):
            insp = self.inspect_offset(ql)
            return SmartQueryAnswer(
                query=q,
                intent_classified="ADDRESS_DATA_INSPECTION",
                summary_answer=(
                    f"Decoded address {insp.virtual_address} (file offset {hex(insp.file_offset)} in {insp.containing_section}): "
                    f"uint32={insp.uint32_le}, ascii='{insp.ascii_string}', first insn='{insp.disassembly_preview[0] if insp.disassembly_preview else 'n/a'}'."
                ),
                total_matches=1,
                results=[asdict(insp)],
            )

        # 2. Capability / Behavioral intent ("network", "crypto", "inject", "anti-debug", "capabilities", "what does it do")
        if any(w in ql for w in ("capability", "capabilities", "behavior", "what does", "network", "socket", "http", "crypto", "encrypt", "inject", "debug", "persist", "registry")):
            caps = self.detect_capabilities()
            filtered = [
                asdict(c) for c in caps
                if ql in ("capability", "capabilities", "behavior", "what does")
                or any(tok in (c.name + " " + c.namespace + " " + c.description).lower() for tok in ql.split())
            ]
            if not filtered and caps:
                filtered = [asdict(c) for c in caps]
            # Also include matching URLs/IPs if asking about network
            if any(w in ql for w in ("network", "url", "http", "ip", "socket")):
                for u in self.extracted_strings.get("urls", []):
                    filtered.append({"type": "EXTRACTED_URL", "value": u})
                for ip in self.extracted_strings.get("ips", []):
                    filtered.append({"type": "EXTRACTED_IP", "value": ip})
            return SmartQueryAnswer(
                query=q,
                intent_classified="BEHAVIORAL_CAPABILITY_QUERY",
                summary_answer=f"Matched {len(filtered)} behavioral capability/indicator item(s) for '{q}'.",
                total_matches=len(filtered),
                results=filtered,
            )

        # 3. URLs / Strings / Paths / Registry
        if ql in ("url", "urls", "ip", "ips", "path", "paths", "registry", "strings"):
            key_map = {"url": "urls", "urls": "urls", "ip": "ips", "ips": "ips", "path": "paths", "paths": "paths", "registry": "registry"}
            if ql in key_map:
                items = self.extracted_strings.get(key_map[ql], [])
                return SmartQueryAnswer(
                    query=q,
                    intent_classified=f"STRING_CATEGORY_{key_map[ql].upper()}",
                    summary_answer=f"Extracted {len(items)} {key_map[ql]} from the binary.",
                    total_matches=len(items),
                    results=[{"category": key_map[ql], "value": v} for v in items],
                )

        # 4. Mitigations / Security posture
        if any(w in ql for w in ("mitigation", "checksec", "aslr", "dep", "nx", "canary", "pie", "cfg")):
            mits = self.metadata.get("mitigations", {})
            return SmartQueryAnswer(
                query=q,
                intent_classified="SECURITY_MITIGATIONS",
                summary_answer=f"Retrieved security mitigation posture for {self.format_name} ({len(mits)} flags).",
                total_matches=len(mits) or 1,
                results=[{"mitigations": mits, "format": self.format_name, "architecture": self.metadata.get("architecture")}],
            )

        # 4b. Compiler / Packer / Rich Header / Imphash / Overlay query
        if any(w in ql for w in ("compiler", "packer", "rich", "imphash", "overlay", "upx", "vmprotect", "toolchain")):
            from reverse_forge.compiler_packer_profiler import CompilerPackerProfiler
            prof = CompilerPackerProfiler().profile_binary(
                self.binary_bytes,
                sections=self.metadata.get("sections", []),
                imported_symbols=self.metadata.get("imported_symbols", []),
            )
            return SmartQueryAnswer(
                query=q,
                intent_classified="COMPILER_AND_PACKER_PROVENANCE",
                summary_answer=(
                    f"Compilers: {', '.join(prof.detected_compilers)}; "
                    f"Packers: {', '.join(prof.detected_packers_or_protectors) or 'None'}; "
                    f"Language: {prof.detected_runtime_language}; Imphash: {prof.imphash_md5 or 'N/A'}."
                ),
                total_matches=1,
                results=[asdict(prof)],
            )

        # 4c. Stack / XOR obfuscated strings query
        if any(w in ql for w in ("stack string", "floss", "obfuscated string", "xor string")):
            from reverse_forge.string_deobfuscator import ObfuscatedStringSolver
            s_rep = ObfuscatedStringSolver().deobfuscate_all_strings(self.binary_bytes)
            return SmartQueryAnswer(
                query=q,
                intent_classified="DEOBFUSCATED_STRINGS",
                summary_answer=f"Recovered {s_rep.total_recovered} obfuscated/stack string(s).",
                total_matches=s_rep.total_recovered,
                results=[asdict(x) for x in s_rep.recovered_strings],
            )

        # 4d. Direct Syscalls query
        if "syscall" in ql:
            from reverse_forge.syscall_struct_engine import SyscallAndStructEngine
            code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(self.binary_bytes, self.metadata)
            sc = SyscallAndStructEngine().resolve_direct_syscalls(code_slice, base_va=entry_va or 0x401000)
            return SmartQueryAnswer(
                query=q,
                intent_classified="DIRECT_SYSCALL_SCAN",
                summary_answer=f"Resolved {len(sc)} direct syscall instruction(s).",
                total_matches=len(sc),
                results=[asdict(x) for x in sc],
            )

        # 5. Cross-references
        if "xref" in ql:
            xrefs = [asdict(x) for x in self.extract_all_xrefs(max_xrefs=64)]
            return SmartQueryAnswer(
                query=q,
                intent_classified="CROSS_REFERENCES",
                summary_answer=f"Discovered {len(xrefs)} instruction/data cross-references.",
                total_matches=len(xrefs),
                results=xrefs,
            )

        # 6. General symbol + string + byte pattern search across the binary
        hits = [asdict(h) for h in self.find_patterns(q, max_hits=40)]
        matching_imports = [
            {"match_type": "IMPORTED_SYMBOL", "matched_value": sym}
            for sym in self.metadata.get("imported_symbols", [])
            if ql in str(sym).lower()
        ]
        matching_exports = [
            {"match_type": "EXPORTED_SYMBOL", "matched_value": sym}
            for sym in self.metadata.get("exported_symbols", [])
            if ql in str(sym).lower()
        ]
        combined = matching_imports + matching_exports + hits
        return SmartQueryAnswer(
            query=q,
            intent_classified="SYMBOL_AND_PATTERN_SEARCH",
            summary_answer=f"Found {len(combined)} symbol/string/pattern match(es) for '{q}' across imports, exports, and sections.",
            total_matches=len(combined),
            results=combined,
        )
