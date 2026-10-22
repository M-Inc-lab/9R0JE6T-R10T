import json
import os
import shutil
import struct
import subprocess
from typing import Dict, Any, List, Optional

try:
    import pefile  # type: ignore
except ImportError:
    pefile = None

DANGEROUS_APIS = {
    "Process Injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "QueueUserAPC", "SetThreadContext", "NtMapViewOfSection",
        "RtlCreateUserThread", "NtQueueApcThread"
    ],
    "Memory Protection & Shellcode": [
        "VirtualProtect", "VirtualProtectEx", "VirtualAlloc"
    ],
    "Keylogging & Hooking": [
        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"
    ],
    "Persistence & Services": [
        "RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW",
        "OpenSCManagerA", "OpenSCManagerW", "StartServiceA", "StartServiceW"
    ],
    "Network & Exfiltration": [
        "InternetOpenA", "InternetOpenW", "HttpSendRequestA", "HttpSendRequestW",
        "WSAStartup", "connect", "send", "URLDownloadToFileA", "URLDownloadToFileW"
    ],
    "Banned / Unsafe C Functions": [
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "_mbscpy", "_mbscat"
    ]
}


class _PurePEParser:
    """Pure-Python fallback parser for PE mitigations, IAT, and EAT when pefile is unavailable."""

    IMAGE_FILE_MACHINE_I386 = 0x014C
    IMAGE_DIRECTORY_ENTRY_EXPORT = 0
    IMAGE_DIRECTORY_ENTRY_IMPORT = 1
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10

    def __init__(self, filepath: str):
        with open(filepath, "rb") as f:
            self.data = f.read()
        self.length = len(self.data)
        self.machine = 0
        self.is_64 = False
        self.dll_characteristics = 0
        self.data_dirs: List[tuple[int, int]] = [(0, 0)] * 16
        self.sections: List[tuple[int, int, int, int]] = []  # (vaddr, vsize, raw_off, raw_size)
        self._parse_headers()

    def _parse_headers(self) -> None:
        if self.length < 64 or self.data[:2] != b"MZ":
            raise ValueError("Invalid MZ header")
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if e_lfanew + 24 > self.length or self.data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("Invalid PE signature")

        coff_off = e_lfanew + 4
        self.machine, num_sections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", self.data, coff_off)
        opt_off = coff_off + 20
        if opt_size >= 2 and opt_off + opt_size <= self.length:
            magic = struct.unpack_from("<H", self.data, opt_off)[0]
            self.is_64 = (magic == 0x20B)
            if opt_size >= 72:
                self.dll_characteristics = struct.unpack_from("<H", self.data, opt_off + 70)[0]
            dd_offset = opt_off + (112 if self.is_64 else 96)
            num_rva_Offset = opt_off + (108 if self.is_64 else 92)
            if num_rva_Offset + 4 <= self.length:
                num_dirs = min(16, struct.unpack_from("<I", self.data, num_rva_Offset)[0])
                dirs: List[tuple[int, int]] = []
                for i in range(16):
                    cur_dd = dd_offset + i * 8
                    if i < num_dirs and cur_dd + 8 <= opt_off + opt_size and cur_dd + 8 <= self.length:
                        vaddr, sz = struct.unpack_from("<II", self.data, cur_dd)
                        dirs.append((vaddr, sz))
                    else:
                        dirs.append((0, 0))
                self.data_dirs = dirs

        sec_off = opt_off + opt_size
        for i in range(min(num_sections, 96)):
            cur = sec_off + i * 40
            if cur + 40 > self.length:
                break
            vsize, vaddr, raw_size, raw_off = struct.unpack_from("<IIII", self.data, cur + 8)
            self.sections.append((vaddr, max(vsize, raw_size), raw_off, raw_size))

    def rva_to_offset(self, rva: int) -> Optional[int]:
        if rva == 0:
            return None
        for vaddr, span, raw_off, raw_size in self.sections:
            if vaddr <= rva < vaddr + max(span, 1):
                delta = rva - vaddr
                if raw_off + delta < self.length:
                    return raw_off + delta
        if rva < self.length:
            return rva
        return None

    def read_cstring(self, offset: Optional[int], max_len: int = 256) -> str:
        if offset is None or offset < 0 or offset >= self.length:
            return ""
        end = self.data.find(b"\x00", offset, min(self.length, offset + max_len))
        if end == -1:
            end = min(self.length, offset + max_len)
        return self.data[offset:end].decode("utf-8", errors="ignore")

    def parse_imports(self) -> List[tuple[str, List[tuple[Optional[str], Optional[int]]]]]:
        imp_rva, imp_size = self.data_dirs[self.IMAGE_DIRECTORY_ENTRY_IMPORT]
        if imp_rva == 0 or imp_size == 0:
            return []
        imp_off = self.rva_to_offset(imp_rva)
        if imp_off is None:
            return []

        imports_out: List[tuple[str, List[tuple[Optional[str], Optional[int]]]]] = []
        for idx in range(256):
            desc_off = imp_off + idx * 20
            if desc_off + 20 > self.length:
                break
            ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from("<IIIII", self.data, desc_off)
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break
            dll_name = self.read_cstring(self.rva_to_offset(name_rva)) or "unknown.dll"
            thunk_rva = ilt_rva if ilt_rva != 0 else iat_rva
            thunk_off = self.rva_to_offset(thunk_rva)
            funcs: List[tuple[Optional[str], Optional[int]]] = []
            if thunk_off is not None:
                step = 8 if self.is_64 else 4
                ord_flag = (1 << 63) if self.is_64 else (1 << 31)
                fmt = "<Q" if self.is_64 else "<I"
                for t_idx in range(4096):
                    cur_t = thunk_off + t_idx * step
                    if cur_t + step > self.length:
                        break
                    val = struct.unpack_from(fmt, self.data, cur_t)[0]
                    if val == 0:
                        break
                    if val & ord_flag:
                        funcs.append((None, val & 0xFFFF))
                    else:
                        ibn_off = self.rva_to_offset(val & 0x7FFFFFFF)
                        if ibn_off is not None and ibn_off + 2 < self.length:
                            fname = self.read_cstring(ibn_off + 2)
                            funcs.append((fname or None, None))
            imports_out.append((dll_name, funcs))
        return imports_out

    def parse_exports(self) -> List[Dict[str, Any]]:
        exp_rva, exp_size = self.data_dirs[self.IMAGE_DIRECTORY_ENTRY_EXPORT]
        if exp_rva == 0 or exp_size == 0:
            return []
        exp_off = self.rva_to_offset(exp_rva)
        if exp_off is None or exp_off + 40 > self.length:
            return []

        _, _, _, _, base_ord, num_funcs, num_names, funcs_rva, names_rva, ords_rva = struct.unpack_from(
            "<IIIIIIIIII", self.data, exp_off
        )
        funcs_off = self.rva_to_offset(funcs_rva)
        names_off = self.rva_to_offset(names_rva)
        ords_off = self.rva_to_offset(ords_rva)
        if funcs_off is None:
            return []

        name_map: Dict[int, str] = {}
        if names_off is not None and ords_off is not None:
            for i in range(min(num_names, 4096)):
                if names_off + (i + 1) * 4 > self.length or ords_off + (i + 1) * 2 > self.length:
                    break
                n_rva = struct.unpack_from("<I", self.data, names_off + i * 4)[0]
                ord_idx = struct.unpack_from("<H", self.data, ords_off + i * 2)[0]
                name_map[ord_idx] = self.read_cstring(self.rva_to_offset(n_rva))

        exports: List[Dict[str, Any]] = []
        for idx in range(min(num_funcs, 4096)):
            if funcs_off + (idx + 1) * 4 > self.length:
                break
            f_rva = struct.unpack_from("<I", self.data, funcs_off + idx * 4)[0]
            if f_rva == 0:
                continue
            ordinal = base_ord + idx
            ename = name_map.get(idx) or f"Ordinal({ordinal})"
            exports.append({"name": ename, "ordinal": ordinal, "rva": hex(f_rva)})
        return exports


class WindowsEngine:
    """Dedicated Windows PE inspection, mitigation auditing, and IAT capability analyzer."""

    def __init__(self, filepath: str):
        self.filepath = os.path.abspath(filepath)
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Binary artifact not found: {self.filepath}")
        if pefile is not None:
            self.pe = pefile.PE(self.filepath)
            self._pure_pe = None
        else:
            self.pe = None
            self._pure_pe = _PurePEParser(self.filepath)

    def check_mitigations(self) -> Dict[str, Any]:
        """Check Windows compile-time security mitigations (ASLR, DEP, CFG, etc.)."""
        if self.pe is not None:
            dll_chars = getattr(self.pe.OPTIONAL_HEADER, "DllCharacteristics", 0)
            is_x86 = (self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"])
            safeseh = None
            if is_x86:
                load_config_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]
                ]
                safeseh = (load_config_dir.VirtualAddress != 0 and load_config_dir.Size > 0)
        else:
            assert self._pure_pe is not None
            dll_chars = self._pure_pe.dll_characteristics
            is_x86 = (self._pure_pe.machine == _PurePEParser.IMAGE_FILE_MACHINE_I386)
            safeseh = None
            if is_x86:
                lc_va, lc_sz = self._pure_pe.data_dirs[_PurePEParser.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
                safeseh = (lc_va != 0 and lc_sz > 0)

        aslr = bool(dll_chars & 0x0040)
        high_entropy_va = bool(dll_chars & 0x0020)
        dep = bool(dll_chars & 0x0100)
        cfg = bool(dll_chars & 0x4000)
        isolation = not bool(dll_chars & 0x0200)
        no_seh = bool(dll_chars & 0x0400)
        has_seh = not no_seh

        return {
            "aslr": aslr,
            "high_entropy_va": high_entropy_va,
            "dep_nx": dep,
            "control_flow_guard": cfg,
            "isolation_manifest": isolation,
            "seh_enabled": has_seh,
            "safe_seh": safeseh,
            "authenticode_signed": self._check_authenticode_dir(),
        }

    def _check_authenticode_dir(self) -> bool:
        if self.pe is not None:
            security_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            ]
            return security_dir.VirtualAddress != 0 and security_dir.Size > 0
        assert self._pure_pe is not None
        sec_va, sec_sz = self._pure_pe.data_dirs[_PurePEParser.IMAGE_DIRECTORY_ENTRY_SECURITY]
        return sec_va != 0 and sec_sz > 0

    def verify_authenticode_signature(self) -> Dict[str, Any]:
        """Verify Windows Authenticode digital signature safely without command string interpolation."""
        has_security_dir = self._check_authenticode_dir()
        if not has_security_dir:
            return {
                "status": "Unsigned",
                "valid": False,
                "signer": None,
                "details": "No embedded security certificate directory found",
            }

        ps_exe = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
        ps_script = (
            "(Get-AuthenticodeSignature -LiteralPath $env:RF_TARGET_PATH) | "
            "Select-Object -Property Status, StatusMessage, "
            "@{Name='Signer'; Expression={$_.SignerCertificate.Subject}} | ConvertTo-Json"
        )
        env = os.environ.copy()
        env["RF_TARGET_PATH"] = self.filepath

        try:
            res = subprocess.run(
                [ps_exe, "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                status = data.get("Status", "Unknown")
                return {
                    "status": status,
                    "valid": status in (0, "Valid"),
                    "signer": data.get("Signer"),
                    "details": data.get("StatusMessage"),
                }
            return {
                "status": "Unverified",
                "valid": False,
                "signer": None,
                "details": res.stderr.strip() or f"Signature check exited with status {res.returncode}",
            }
        except Exception as e:
            return {"status": "QueryFailed", "valid": False, "signer": None, "error": str(e)}

    def inspect_iat(self) -> Dict[str, Any]:
        """Extract imported DLLs and correlate dangerous API capabilities."""
        raw_imports: List[tuple[str, List[str]]] = []
        if self.pe is not None:
            if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
                return {
                    "imported_dlls_count": 0,
                    "total_imported_functions": 0,
                    "imported_dlls": [],
                    "suspicious_capabilities": {},
                    "all_imports_count": 0,
                }
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                funcs = [
                    imp.name.decode("utf-8", errors="ignore") if imp.name else f"Ordinal({imp.ordinal})"
                    for imp in entry.imports
                ]
                raw_imports.append((dll_name, funcs))
        else:
            assert self._pure_pe is not None
            parsed = self._pure_pe.parse_imports()
            if not parsed:
                return {
                    "imported_dlls_count": 0,
                    "total_imported_functions": 0,
                    "imported_dlls": [],
                    "suspicious_capabilities": {},
                    "all_imports_count": 0,
                }
            for dll_name, fn_tuples in parsed:
                funcs = [fn if fn else f"Ordinal({ord_no})" for fn, ord_no in fn_tuples]
                raw_imports.append((dll_name, funcs))

        dlls = []
        all_funcs = []
        capabilities: Dict[str, List[str]] = {}

        for dll_name, funcs in raw_imports:
            for fname in funcs:
                all_funcs.append(fname)
                for category, patterns in DANGEROUS_APIS.items():
                    for pat in patterns:
                        fl = fname.lower()
                        pl = pat.lower()
                        if fl == pl or fl in (f"{pl}a", f"{pl}w", f"{pl}ex", f"{pl}exa", f"{pl}exw"):
                            capabilities.setdefault(category, []).append(f"{dll_name}!{fname}")
            dlls.append({"dll": dll_name, "functions_count": len(funcs), "sample_functions": funcs[:5]})

        for cat in capabilities:
            capabilities[cat] = list(dict.fromkeys(capabilities[cat]))

        return {
            "imported_dlls_count": len(dlls),
            "total_imported_functions": len(all_funcs),
            "imported_dlls": dlls,
            "suspicious_capabilities": capabilities,
        }

    def inspect_eat(self) -> Dict[str, Any]:
        """Extract exported functions (for DLLs)."""
        if self.pe is not None:
            if not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
                return {"exported_functions": [], "count": 0}
            exports = []
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                ename = exp.name.decode("utf-8", errors="ignore") if exp.name else f"Ordinal({exp.ordinal})"
                exports.append({"name": ename, "ordinal": exp.ordinal, "rva": hex(exp.address)})
            return {"count": len(exports), "exported_functions": exports[:50]}

        assert self._pure_pe is not None
        exports = self._pure_pe.parse_exports()
        return {"count": len(exports), "exported_functions": exports[:50]}

    def full_audit(self) -> Dict[str, Any]:
        """Generate comprehensive Windows audit record."""
        mitigations = self.check_mitigations()
        signature = self.verify_authenticode_signature()
        iat_data = self.inspect_iat()
        eat_data = self.inspect_eat()

        vulnerabilities = []
        if not mitigations["dep_nx"]:
            vulnerabilities.append({
                "id": "WIN-VULN-01",
                "title": "Missing Data Execution Prevention (DEP/NX)",
                "severity": "HIGH",
                "cwe": "CWE-119",
                "description": "Binary lacks IMAGE_DLLCHARACTERISTICS_NX_COMPAT flag. Memory pages marked writable may be directly executable.",
            })
        if not mitigations["aslr"]:
            vulnerabilities.append({
                "id": "WIN-VULN-02",
                "title": "Missing Address Space Layout Randomization (ASLR)",
                "severity": "HIGH",
                "cwe": "CWE-119",
                "description": "Binary lacks IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE. Code pages load at a predictable static base address.",
            })
        if not mitigations["control_flow_guard"]:
            vulnerabilities.append({
                "id": "WIN-VULN-03",
                "title": "Missing Control Flow Guard (CFG)",
                "severity": "MEDIUM",
                "cwe": "CWE-691",
                "description": "Binary was compiled without /guard:cf. Indirect function calls are not validated at runtime.",
            })
        if "Banned / Unsafe C Functions" in iat_data["suspicious_capabilities"]:
            vulnerabilities.append({
                "id": "WIN-VULN-04",
                "title": "Use of Banned Memory/String APIs",
                "severity": "HIGH",
                "cwe": "CWE-120",
                "description": f"Binary imports deprecated memory functions: {iat_data['suspicious_capabilities']['Banned / Unsafe C Functions']}",
            })

        return {
            "artifact": self.filepath,
            "mitigations": mitigations,
            "signature": signature,
            "iat_summary": {
                "dll_count": iat_data.get("imported_dlls_count", 0),
                "api_count": iat_data.get("total_imported_functions", 0),
                "flagged_capabilities": iat_data.get("suspicious_capabilities", {}),
            },
            "eat_summary": eat_data,
            "identified_vulnerabilities": vulnerabilities,
        }
