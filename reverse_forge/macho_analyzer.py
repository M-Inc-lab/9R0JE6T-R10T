import math
import struct
from typing import Dict, Any, List, Optional

DANGEROUS_MACHO_APIS = {
    "Banned / Unsafe C Functions": [
        "strcpy", "_strcpy", "strcat", "_strcat", "sprintf", "_sprintf", "vsprintf", "_vsprintf", "gets", "_gets"
    ],
    "Process & Command Execution": [
        "system", "_system", "popen", "_popen", "execve", "_execve", "posix_spawn", "_posix_spawn", "NSTask"
    ],
    "Dynamic Loading & Injection": [
        "dlopen", "_dlopen", "dlsym", "_dlsym", "NSCreateObjectFileImageFromMemory", "task_for_pid", "_task_for_pid"
    ]
}


class MachOAnalyzer:
    """Pure-Python Mach-O (32-bit, 64-bit, and Universal/Fat) structural, symbol, signing, and mitigation analyzer."""

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

    @staticmethod
    def _read_cstring(blob: bytes, offset: int, max_len: int = 256) -> str:
        if offset < 0 or offset >= len(blob):
            return ""
        end = blob.find(b"\x00", offset, min(len(blob), offset + max_len))
        if end == -1:
            end = min(len(blob), offset + max_len)
        return blob[offset:end].decode("utf-8", errors="replace")

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

    def _parse_code_signature(self, dataoff: int, datasize: int) -> Dict[str, Any]:
        """Parse LC_CODE_SIGNATURE CS_SuperBlob (0xFADE0CC0) and extract embedded XML entitlements (0xFADE7171)."""
        sig_info: Dict[str, Any] = {
            "present": True,
            "offset": hex(dataoff),
            "size": datasize,
            "entitlements_xml": None,
        }
        if dataoff + 12 > self.length or dataoff + datasize > self.length:
            return sig_info

        sb_magic, sb_len, sb_count = struct.unpack_from(">III", self.data, dataoff)
        if sb_magic != 0xFADE0CC0:
            return sig_info

        for idx in range(min(sb_count, 32)):
            idx_off = dataoff + 12 + idx * 8
            if idx_off + 8 > self.length:
                break
            _, blob_rel_off = struct.unpack_from(">II", self.data, idx_off)
            blob_abs = dataoff + blob_rel_off
            if blob_abs + 8 > self.length:
                continue
            b_magic, b_len = struct.unpack_from(">II", self.data, blob_abs)
            if b_magic == 0xFADE7171 and b_len >= 8 and blob_abs + b_len <= self.length:
                xml_bytes = self.data[blob_abs + 8:blob_abs + b_len]
                sig_info["entitlements_xml"] = xml_bytes.decode("utf-8", errors="replace").strip()
        return sig_info

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
            "dylibs": [],
            "rpaths": [],
            "imported_symbols": [],
            "exported_symbols": [],
            "suspicious_capabilities": {},
            "code_signature": {"present": False, "entitlements_xml": None},
            "mitigations": {},
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

        pie_enabled = bool(flags & 0x200000)                  # MH_PIE
        allow_stack_exec = bool(flags & 0x20000)              # MH_ALLOW_STACK_EXECUTION
        no_heap_exec = bool(flags & 0x1000000)                # MH_NO_HEAP_EXECUTION
        has_restrict_segment = False

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
                if segname == "__RESTRICT":
                    has_restrict_segment = True
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
                if segname == "__RESTRICT":
                    has_restrict_segment = True
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
            elif cmd in (0xC, 0x80000018, 0x8000001F) and cmdsize >= 24:  # LC_LOAD_DYLIB / WEAK / REEXPORT
                str_off = struct.unpack_from(endian + "I", self.data, offset + 8)[0]
                if 8 <= str_off < cmdsize:
                    dylib_name = self._read_cstring(self.data[offset:offset + cmdsize], str_off)
                    if dylib_name:
                        result["dylibs"].append(dylib_name)
            elif cmd == 0x8000001C and cmdsize >= 12:  # LC_RPATH
                str_off = struct.unpack_from(endian + "I", self.data, offset + 8)[0]
                if 8 <= str_off < cmdsize:
                    rpath_str = self._read_cstring(self.data[offset:offset + cmdsize], str_off)
                    if rpath_str:
                        result["rpaths"].append(rpath_str)
            elif cmd == 0x2 and cmdsize >= 24:  # LC_SYMTAB
                symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", self.data, offset + 8)
                if stroff + strsize <= self.length and symoff < self.length:
                    str_blob = self.data[stroff:stroff + strsize]
                    nlist_sz = 16 if is_64 else 12
                    nlist_fmt = endian + ("IBBHQ" if is_64 else "IBBHI")
                    for s_idx in range(min(nsyms, 8192)):
                        cur_s = symoff + s_idx * nlist_sz
                        if cur_s + nlist_sz > self.length:
                            break
                        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(nlist_fmt, self.data, cur_s)
                        if n_strx == 0:
                            continue
                        sname = self._read_cstring(str_blob, n_strx)
                        if not sname:
                            continue
                        if (n_type & 0x0E) == 0x0:  # N_UNDF -> imported
                            result["imported_symbols"].append(sname)
                        elif (n_type & 0x01) != 0:  # N_EXT defined -> exported
                            result["exported_symbols"].append(sname)
            elif cmd == 0x1D and cmdsize >= 16:  # LC_CODE_SIGNATURE
                dataoff, datasize = struct.unpack_from(endian + "II", self.data, offset + 8)
                result["code_signature"] = self._parse_code_signature(dataoff, datasize)

            offset += cmdsize

        imports_dedup = list(dict.fromkeys(result["imported_symbols"]))
        exports_dedup = list(dict.fromkeys(result["exported_symbols"]))
        result["imported_symbols"] = imports_dedup[:250]
        result["exported_symbols"] = exports_dedup[:250]

        capabilities: Dict[str, List[str]] = {}
        for sym in imports_dedup:
            clean_sym = sym.lstrip("_")
            for cat, patterns in DANGEROUS_MACHO_APIS.items():
                if sym in patterns or clean_sym in patterns:
                    capabilities.setdefault(cat, []).append(sym)
        result["suspicious_capabilities"] = capabilities

        has_canary = any(s in ("___stack_chk_fail", "__stack_chk_fail", "___stack_chk_guard") for s in imports_dedup)
        has_arc = any(s in ("_objc_release", "_objc_retain", "_objc_autoreleaseReturnValue") for s in imports_dedup)

        result["mitigations"] = {
            "pie": pie_enabled,
            "nx_stack": not allow_stack_exec,
            "no_heap_execution": no_heap_exec,
            "stack_canary": has_canary,
            "objc_arc": has_arc,
            "restrict_segment": has_restrict_segment,
            "code_signed": bool(result["code_signature"].get("present")),
        }

        return result

    def full_audit(self) -> Dict[str, Any]:
        """Generate comprehensive Mach-O security mitigation and capability audit report."""
        analysis = self.analyze()
        mitigations = analysis.get("mitigations", {})
        caps = analysis.get("suspicious_capabilities", {})
        sig = analysis.get("code_signature", {})
        vulnerabilities = []

        if analysis.get("is_macho") and not analysis.get("is_fat"):
            if not mitigations.get("pie") and analysis.get("file_type") == "MH_EXECUTE":
                vulnerabilities.append({
                    "id": "MACHO-VULN-01",
                    "title": "Missing Position Independent Executable (MH_PIE)",
                    "severity": "MEDIUM",
                    "cwe": "CWE-119",
                    "description": "Executable lacks MH_PIE header flag, disabling full ASLR on macOS/iOS.",
                })
            if not mitigations.get("nx_stack"):
                vulnerabilities.append({
                    "id": "MACHO-VULN-02",
                    "title": "Executable Stack Enabled (MH_ALLOW_STACK_EXECUTION)",
                    "severity": "HIGH",
                    "cwe": "CWE-119",
                    "description": "MH_ALLOW_STACK_EXECUTION flag is set, permitting execution of stack memory.",
                })
            ent_xml = sig.get("entitlements_xml") or ""
            if any(
                k in ent_xml
                for k in (
                    "com.apple.security.cs.disable-library-validation",
                    "com.apple.security.cs.allow-dyld-environment-variables",
                    "get-task-allow",
                )
            ):
                vulnerabilities.append({
                    "id": "MACHO-VULN-03",
                    "title": "Permissive Hardened Runtime / Dylib Injection Entitlements",
                    "severity": "HIGH",
                    "cwe": "CWE-276",
                    "description": "Embedded entitlements disable library validation or permit DYLD_INSERT_LIBRARIES injection.",
                })
            if "Banned / Unsafe C Functions" in caps:
                vulnerabilities.append({
                    "id": "MACHO-VULN-04",
                    "title": "Use of Banned Unbounded Memory/String APIs",
                    "severity": "HIGH",
                    "cwe": "CWE-120",
                    "description": f"Binary imports unbounded C functions: {caps['Banned / Unsafe C Functions']}",
                })

        return {
            "is_macho": analysis.get("is_macho"),
            "is_fat": analysis.get("is_fat"),
            "architecture": analysis.get("architecture"),
            "file_type": analysis.get("file_type"),
            "entry_point": analysis.get("entry_point"),
            "entry_file_offset": analysis.get("entry_file_offset"),
            "mitigations": mitigations,
            "dylibs": analysis.get("dylibs", []),
            "rpaths": analysis.get("rpaths", []),
            "code_signature": sig,
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
