import os
import subprocess
from typing import Dict, Any, List, Optional
import pefile

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

class WindowsEngine:
    """Dedicated Windows PE inspection, mitigation auditing, and IAT capability analyzer."""

    def __init__(self, filepath: str):
        self.filepath = os.path.abspath(filepath)
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Binary artifact not found: {self.filepath}")
        self.pe = pefile.PE(self.filepath)

    def check_mitigations(self) -> Dict[str, Any]:
        """Check Windows compile-time security mitigations (ASLR, DEP, CFG, etc.)."""
        dll_chars = getattr(self.pe.OPTIONAL_HEADER, "DllCharacteristics", 0)

        # Dynamic Base (ASLR)
        aslr = bool(dll_chars & 0x0040)
        # High Entropy 64-bit ASLR
        high_entropy_va = bool(dll_chars & 0x0020)
        # DEP / NX Compatibility
        dep = bool(dll_chars & 0x0100)
        # Control Flow Guard (CFG)
        cfg = bool(dll_chars & 0x4000)
        # Isolation (Manifest)
        isolation = not bool(dll_chars & 0x0200)  # NO_ISOLATION is 0x0200
        # Structured Exception Handling
        no_seh = bool(dll_chars & 0x0400)
        has_seh = not no_seh

        # SafeSEH (x86 only check)
        safeseh = None
        if self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            # Check Load Config Directory
            load_config_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]]
            safeseh = (load_config_dir.VirtualAddress != 0 and load_config_dir.Size > 0)

        return {
            "aslr": aslr,
            "high_entropy_va": high_entropy_va,
            "dep_nx": dep,
            "control_flow_guard": cfg,
            "isolation_manifest": isolation,
            "safe_seh": safeseh,
            "authenticode_signed": self._check_authenticode_dir()
        }

    def _check_authenticode_dir(self) -> bool:
        security_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        return security_dir.VirtualAddress != 0 and security_dir.Size > 0

    def verify_authenticode_signature(self) -> Dict[str, Any]:
        """Verify Windows Authenticode digital signature using PowerShell native cmdlet."""
        has_security_dir = self._check_authenticode_dir()
        if not has_security_dir:
            return {
                "status": "Unsigned",
                "valid": False,
                "signer": None,
                "details": "No embedded security certificate directory found"
            }

        ps_cmd = f"(Get-AuthenticodeSignature -LiteralPath '{self.filepath}') | Select-Object -Property Status, StatusMessage, @{{Name='Signer'; Expression={{$_.SignerCertificate.Subject}}}} | ConvertTo-Json"
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=10)
            if res.returncode == 0 and res.stdout.strip():
                import json
                data = json.loads(res.stdout)
                return {
                    "status": data.get("Status", "Unknown"),
                    "valid": data.get("Status") == 0 or data.get("Status") == "Valid",
                    "signer": data.get("Signer"),
                    "details": data.get("StatusMessage")
                }
        except Exception as e:
            return {"status": "QueryFailed", "valid": False, "error": str(e)}

        return {"status": "Signed", "valid": True, "signer": "Embedded Signature Present"}

    def inspect_iat(self) -> Dict[str, Any]:
        """Extract imported DLLs and correlate dangerous API capabilities."""
        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return {"imported_dlls": [], "suspicious_capabilities": {}, "all_imports_count": 0}

        dlls = []
        all_funcs = []
        capabilities: Dict[str, List[str]] = {}

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore")
            funcs = []
            for imp in entry.imports:
                fname = imp.name.decode("utf-8", errors="ignore") if imp.name else f"Ordinal({imp.ordinal})"
                funcs.append(fname)
                all_funcs.append(fname)

                # Match against dangerous categories (exact match or function name ending in A/W/Ex)
                for category, patterns in DANGEROUS_APIS.items():
                    for pat in patterns:
                        fl = fname.lower()
                        pl = pat.lower()
                        if fl == pl or fl in (f"{pl}a", f"{pl}w", f"{pl}ex", f"{pl}exa", f"{pl}exw"):
                            capabilities.setdefault(category, []).append(f"{dll_name}!{fname}")

            dlls.append({"dll": dll_name, "functions_count": len(funcs), "sample_functions": funcs[:5]})

        # Deduplicate capabilities
        for cat in capabilities:
            capabilities[cat] = list(dict.fromkeys(capabilities[cat]))

        return {
            "imported_dlls_count": len(dlls),
            "total_imported_functions": len(all_funcs),
            "imported_dlls": dlls,
            "suspicious_capabilities": capabilities
        }

    def inspect_eat(self) -> Dict[str, Any]:
        """Extract exported functions (for DLLs)."""
        if not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            return {"exported_functions": [], "count": 0}

        exports = []
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            ename = exp.name.decode("utf-8", errors="ignore") if exp.name else f"Ordinal({exp.ordinal})"
            exports.append({"name": ename, "ordinal": exp.ordinal, "rva": hex(exp.address)})

        return {"count": len(exports), "exported_functions": exports[:50]}

    def full_audit(self) -> Dict[str, Any]:
        """Generate comprehensive Windows audit record."""
        mitigations = self.check_mitigations()
        signature = self.verify_authenticode_signature()
        iat_data = self.inspect_iat()
        eat_data = self.inspect_eat()

        # Vulnerability Hypotheses & Weaknesses
        vulnerabilities = []
        if not mitigations["dep_nx"]:
            vulnerabilities.append({
                "id": "WIN-VULN-01",
                "title": "Missing Data Execution Prevention (DEP/NX)",
                "severity": "HIGH",
                "cwe": "CWE-119",
                "description": "Binary lacks IMAGE_DLLCHARACTERISTICS_NX_COMPAT flag. Memory pages marked writable may be directly executable."
            })
        if not mitigations["aslr"]:
            vulnerabilities.append({
                "id": "WIN-VULN-02",
                "title": "Missing Address Space Layout Randomization (ASLR)",
                "severity": "HIGH",
                "cwe": "CWE-119",
                "description": "Binary lacks IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE. Code pages load at a predictable static base address."
            })
        if not mitigations["control_flow_guard"]:
            vulnerabilities.append({
                "id": "WIN-VULN-03",
                "title": "Missing Control Flow Guard (CFG)",
                "severity": "MEDIUM",
                "cwe": "CWE-691",
                "description": "Binary was compiled without /guard:cf. Indirect function calls are not validated at runtime."
            })
        if "Banned / Unsafe C Functions" in iat_data["suspicious_capabilities"]:
            vulnerabilities.append({
                "id": "WIN-VULN-04",
                "title": "Use of Banned Memory/String APIs",
                "severity": "HIGH",
                "cwe": "CWE-120",
                "description": f"Binary imports deprecated memory functions: {iat_data['suspicious_capabilities']['Banned / Unsafe C Functions']}"
            })

        return {
            "artifact": self.filepath,
            "mitigations": mitigations,
            "signature": signature,
            "iat_summary": {
                "dll_count": iat_data["imported_dlls_count"],
                "api_count": iat_data["total_imported_functions"],
                "flagged_capabilities": iat_data["suspicious_capabilities"]
            },
            "eat_summary": eat_data,
            "identified_vulnerabilities": vulnerabilities
        }
