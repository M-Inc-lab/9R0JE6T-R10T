import math
import struct
from typing import Dict, Any, List, Optional

DANGEROUS_ELF_APIS = {
    "Banned / Unsafe C Functions": [
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf"
    ],
    "Command & Process Execution": [
        "system", "popen", "execve", "execl", "execlp", "execvp", "posix_spawn"
    ],
    "Memory & Dynamic Loading": [
        "dlopen", "dlsym", "mprotect", "mmap", "ptrace"
    ],
    "Network & Socket I/O": [
        "socket", "connect", "bind", "listen", "accept", "recv", "recvfrom"
    ]
}


class ELFAnalyzer:
    """Pure-Python ELF32 and ELF64 header, segment, section, symbol, dynamic linking, and mitigation analyzer."""

    def __init__(self, data: bytes):
        self.data = data
        self.length = len(data)

    def _read_cstring(self, blob: bytes, offset: int, max_len: int = 256) -> str:
        if offset < 0 or offset >= len(blob):
            return ""
        end = blob.find(b"\x00", offset, min(len(blob), offset + max_len))
        if end == -1:
            end = min(len(blob), offset + max_len)
        return blob[offset:end].decode("utf-8", errors="replace")

    def analyze(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "is_elf": False,
            "class": "Unknown",
            "endianness": "Unknown",
            "architecture": "Unknown",
            "type": "Unknown",
            "entry_point": 0,
            "entry_file_offset": None,
            "interpreter": None,
            "segments": [],
            "sections": [],
            "shared_libraries": [],
            "rpath": None,
            "runpath": None,
            "imported_symbols": [],
            "exported_symbols": [],
            "suspicious_capabilities": {},
            "nx_enabled": None,
            "mitigations": {},
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
            0x6474E550: "PT_GNU_EH_FRAME",
            0x6474E551: "PT_GNU_STACK",
            0x6474E552: "PT_GNU_RELRO",
            0x6474E553: "PT_GNU_PROPERTY"
        }

        has_gnu_relro = False
        has_interp = False
        dyn_seg_offset = 0
        dyn_seg_size = 0

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
                    elif p_type == 0x6474E552:  # PT_GNU_RELRO
                        has_gnu_relro = True
                    elif p_type == 3:  # PT_INTERP
                        has_interp = True
                        if p_offset + p_filesz <= self.length and p_filesz > 0:
                            result["interpreter"] = self._read_cstring(self.data[p_offset:p_offset + p_filesz], 0)
                    elif p_type == 2:  # PT_DYNAMIC
                        dyn_seg_offset = p_offset
                        dyn_seg_size = p_filesz

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

        raw_section_headers: List[tuple[str, int, int, int, int, int, int]] = []
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

                        sec_name = self._read_cstring(strtab_data, sh_name_idx) if strtab_data else ""
                        raw_section_headers.append(
                            (sec_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize, sh_addr)
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

        # Parse .dynsym / .symtab and .dynamic
        dynstr_blob = b""
        for sec_name, sh_type, sh_offset, sh_size, _, _, _ in raw_section_headers:
            if sec_name == ".dynstr" and sh_offset + sh_size <= self.length:
                dynstr_blob = self.data[sh_offset:sh_offset + sh_size]
            elif sec_name == ".dynamic" and dyn_seg_offset == 0:
                dyn_seg_offset = sh_offset
                dyn_seg_size = sh_size

        bind_now = False
        pie_flag = False
        if dyn_seg_offset > 0 and dyn_seg_size > 0 and dyn_seg_offset + dyn_seg_size <= self.length:
            entry_step = 16 if is_64 else 8
            dyn_fmt = endian_char + ("qQ" if is_64 else "iI")
            needed_offsets: List[int] = []
            rpath_off: Optional[int] = None
            runpath_off: Optional[int] = None

            for off in range(dyn_seg_offset, dyn_seg_offset + dyn_seg_size - entry_step + 1, entry_step):
                d_tag, d_val = struct.unpack_from(dyn_fmt, self.data, off)
                if d_tag == 0:  # DT_NULL
                    break
                elif d_tag == 1:  # DT_NEEDED
                    needed_offsets.append(d_val)
                elif d_tag == 15:  # DT_RPATH
                    rpath_off = d_val
                elif d_tag == 29:  # DT_RUNPATH
                    runpath_off = d_val
                elif d_tag == 24:  # DT_BIND_NOW
                    bind_now = True
                elif d_tag == 30:  # DT_FLAGS
                    if d_val & 0x8:  # DF_BIND_NOW
                        bind_now = True
                elif d_tag == 0x6FFFFFFB:  # DT_FLAGS_1
                    if d_val & 0x1:  # DF_1_NOW
                        bind_now = True
                    if d_val & 0x8000000:  # DF_1_PIE
                        pie_flag = True

            if dynstr_blob:
                result["shared_libraries"] = [
                    self._read_cstring(dynstr_blob, noff) for noff in needed_offsets if self._read_cstring(dynstr_blob, noff)
                ]
                if rpath_off is not None:
                    result["rpath"] = self._read_cstring(dynstr_blob, rpath_off) or None
                if runpath_off is not None:
                    result["runpath"] = self._read_cstring(dynstr_blob, runpath_off) or None

        # Extract symbols from SHT_DYNSYM (11) and SHT_SYMTAB (2)
        imports_list: List[str] = []
        exports_list: List[str] = []
        sym_entry_size = 24 if is_64 else 16
        for sec_name, sh_type, sh_offset, sh_size, sh_link, _, _ in raw_section_headers:
            if sh_type not in (2, 11) or sh_offset + sh_size > self.length:
                continue
            if sh_link >= len(raw_section_headers):
                continue
            _, _, str_off, str_sz, _, _, _ = raw_section_headers[sh_link]
            if str_off + str_sz > self.length:
                continue
            str_blob = self.data[str_off:str_off + str_sz]

            count = min(sh_size // sym_entry_size, 8192)
            for idx in range(count):
                s_off = sh_offset + idx * sym_entry_size
                if s_off + sym_entry_size > self.length:
                    break
                if is_64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                        endian_char + "IBBHQQ", self.data, s_off
                    )
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                        endian_char + "IIIBBH", self.data, s_off
                    )
                if st_name == 0:
                    continue
                sname = self._read_cstring(str_blob, st_name)
                if not sname:
                    continue
                base_sym = sname.split("@")[0]
                st_bind = st_info >> 4
                st_type = st_info & 0xF
                if st_shndx == 0:  # SHN_UNDEF -> imported symbol
                    imports_list.append(base_sym)
                elif st_bind in (1, 2) and st_type in (1, 2):  # STB_GLOBAL/WEAK FUNC/OBJECT -> exported
                    exports_list.append(base_sym)

        imports_dedup = list(dict.fromkeys(imports_list))
        exports_dedup = list(dict.fromkeys(exports_list))
        result["imported_symbols"] = imports_dedup[:250]
        result["exported_symbols"] = exports_dedup[:250]

        capabilities: Dict[str, List[str]] = {}
        for sym in imports_dedup:
            clean_sym = sym.lstrip("_")
            for cat, patterns in DANGEROUS_ELF_APIS.items():
                if sym in patterns or clean_sym in patterns:
                    capabilities.setdefault(cat, []).append(sym)
        result["suspicious_capabilities"] = capabilities

        # Compute ELF security mitigations
        has_canary = any(
            s in ("__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie")
            for s in imports_dedup
        )
        has_fortify = any(s.endswith("_chk") and s.startswith("__") for s in imports_dedup)
        is_pie = (e_type == 3 and (pie_flag or has_interp or e_entry > 0))
        if has_gnu_relro and bind_now:
            relro_mode = "Full RELRO"
        elif has_gnu_relro:
            relro_mode = "Partial RELRO"
        else:
            relro_mode = "No RELRO"

        result["mitigations"] = {
            "nx": bool(result["nx_enabled"]),
            "pie": is_pie,
            "relro": relro_mode,
            "stack_canary": has_canary,
            "fortify_source": has_fortify,
            "rpath": result["rpath"],
            "runpath": result["runpath"],
        }

        return result

    def full_audit(self) -> Dict[str, Any]:
        """Generate comprehensive ELF security mitigation and capability audit report."""
        analysis = self.analyze()
        mitigations = analysis.get("mitigations", {})
        caps = analysis.get("suspicious_capabilities", {})
        vulnerabilities = []

        if analysis.get("is_elf"):
            if not mitigations.get("nx"):
                vulnerabilities.append({
                    "id": "ELF-VULN-01",
                    "title": "Executable Stack / Missing NX (PT_GNU_STACK)",
                    "severity": "HIGH",
                    "cwe": "CWE-119",
                    "description": "Binary lacks non-executable PT_GNU_STACK protection, allowing stack memory execution.",
                })
            if not mitigations.get("pie") and "ET_EXEC" in analysis.get("type", ""):
                vulnerabilities.append({
                    "id": "ELF-VULN-02",
                    "title": "Non-PIE Executable (Static Base Address)",
                    "severity": "MEDIUM",
                    "cwe": "CWE-119",
                    "description": "Executable is compiled as ET_EXEC rather than Position-Independent Executable (ET_DYN/PIE), weakening ASLR.",
                })
            if mitigations.get("relro") == "No RELRO":
                vulnerabilities.append({
                    "id": "ELF-VULN-03",
                    "title": "Missing Relocation Read-Only (RELRO)",
                    "severity": "MEDIUM",
                    "cwe": "CWE-119",
                    "description": "Global Offset Table (.got/.got.plt) remains writable at runtime.",
                })
            rpath_val = mitigations.get("rpath") or mitigations.get("runpath")
            if rpath_val and any(tok in rpath_val for tok in ("$ORIGIN", ".", "/tmp", "/var/tmp")):
                vulnerabilities.append({
                    "id": "ELF-VULN-04",
                    "title": "Potentially Unsafe RPATH/RUNPATH Search Path",
                    "severity": "HIGH",
                    "cwe": "CWE-426",
                    "description": f"Dynamic loader search path contains relative or temporary directory: {rpath_val}",
                })
            if "Banned / Unsafe C Functions" in caps:
                vulnerabilities.append({
                    "id": "ELF-VULN-05",
                    "title": "Use of Banned Unbounded Memory/String Functions",
                    "severity": "HIGH",
                    "cwe": "CWE-120",
                    "description": f"Binary imports unbounded C functions: {caps['Banned / Unsafe C Functions']}",
                })

        return {
            "is_elf": analysis.get("is_elf"),
            "architecture": analysis.get("architecture"),
            "type": analysis.get("type"),
            "entry_point": analysis.get("entry_point"),
            "entry_file_offset": analysis.get("entry_file_offset"),
            "interpreter": analysis.get("interpreter"),
            "mitigations": mitigations,
            "shared_libraries": analysis.get("shared_libraries", []),
            "imported_symbols_count": len(analysis.get("imported_symbols", [])),
            "exported_symbols_count": len(analysis.get("exported_symbols", [])),
            "flagged_capabilities": caps,
            "identified_vulnerabilities": vulnerabilities,
        }

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
