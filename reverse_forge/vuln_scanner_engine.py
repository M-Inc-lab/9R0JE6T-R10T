"""
R3V3R53//F0RG3 — Phase 68: Automated CWE Vulnerability & Exploit Primitive Scanner Engine
Statically audits binaries, instruction streams, sections, mitigations, and cross-references for
6 concrete classes of memory-corruption and logic vulnerabilities:
  1. CWE-120 / CWE-787: Classic Stack/Heap Buffer Overflow Sinks (`gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `scanf`)
  2. CWE-134: Uncontrolled Format String (`printf`, `fprintf`, `snprintf`, `syslog` with non-constant format register)
  3. CWE-78: OS Command Injection Sinks (`system`, `popen`, `_popen`, `WinExec`, `ShellExecuteA`, `ShellExecuteW`)
  4. CWE-190 / CWE-680: Integer Overflow to Buffer Overflow (`imul` / `shl` arithmetic directly feeding `malloc` / `HeapAlloc` without bounds check)
  5. CWE-416 / CWE-415: Use-After-Free & Double-Free (`free` / `HeapFree` followed by reuse of the freed register/pointer without zeroing)
  6. CWE-693 / W^X Violation: Writable + Executable (`RWX`) memory sections or missing ASLR/DEP mitigations on binaries with dangerous sinks
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class VulnerabilityFinding:
    finding_id: str
    cwe_id: str
    title: str
    severity: str               # CRITICAL, HIGH, MEDIUM, LOW
    cvss_estimate: float
    location_va: str
    sink_or_section: str
    evidence: str
    remediation: str


@dataclass
class VulnerabilityAuditReport:
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    overall_risk_rating: str    # CRITICAL, HIGH, MEDIUM, LOW, CLEAN
    findings: List[VulnerabilityFinding] = field(default_factory=list)


class BinaryVulnerabilityScannerEngine:
    """
    Performs static CWE vulnerability discovery across binary imports, sections, mitigations,
    and disassembled instruction streams.
    """

    OVERFLOW_SINKS = {
        "gets": ("CWE-120", "CRITICAL", 9.8, "Unbounded stack read via gets(); guaranteed buffer overflow."),
        "strcpy": ("CWE-120", "HIGH", 8.4, "Unbounded string copy via strcpy() without destination length check."),
        "strcat": ("CWE-120", "HIGH", 8.1, "Unbounded string concatenation via strcat()."),
        "wcscpy": ("CWE-120", "HIGH", 8.1, "Unbounded wide-string copy via wcscpy()."),
        "sprintf": ("CWE-787", "HIGH", 8.2, "Unbounded formatted buffer write via sprintf(); use snprintf()."),
        "vsprintf": ("CWE-787", "HIGH", 8.2, "Unbounded formatted buffer write via vsprintf(); use vsnprintf()."),
        "scanf": ("CWE-120", "MEDIUM", 6.8, "Potentially unbounded format read via scanf()."),
        "sscanf": ("CWE-120", "MEDIUM", 6.5, "Potentially unbounded buffer extraction via sscanf()."),
    }

    COMMAND_INJECTION_SINKS = {
        "system": ("CWE-78", "CRITICAL", 9.3, "Direct shell command execution via system()."),
        "popen": ("CWE-78", "HIGH", 8.8, "Shell pipe execution via popen()."),
        "_popen": ("CWE-78", "HIGH", 8.8, "Windows shell pipe execution via _popen()."),
        "WinExec": ("CWE-78", "HIGH", 8.5, "Process execution sink via WinExec()."),
        "ShellExecuteA": ("CWE-78", "HIGH", 8.5, "Shell command execution via ShellExecuteA()."),
        "ShellExecuteW": ("CWE-78", "HIGH", 8.5, "Shell command execution via ShellExecuteW()."),
    }

    FORMAT_STRING_SINKS = {"printf", "fprintf", "syslog", "vprintf", "vfprintf"}
    ALLOC_SINKS = {"malloc", "calloc", "realloc", "HeapAlloc", "VirtualAlloc", "LocalAlloc", "_Znwm", "_Znam"}
    FREE_SINKS = {"free", "HeapFree", "LocalFree", "VirtualFree", "_ZdlPv", "_ZdaPv"}

    def scan_binary(
        self,
        binary_bytes: bytes,
        imported_symbols: Optional[List[str]] = None,
        sections: Optional[List[Dict[str, Any]]] = None,
        mitigations: Optional[Dict[str, Any]] = None,
        instructions: Optional[List[Tuple[int, str, str]]] = None,
    ) -> VulnerabilityAuditReport:
        findings: List[VulnerabilityFinding] = []
        imports = list(imported_symbols or [])
        secs = list(sections or [])
        mits = dict(mitigations or {})
        insns = list(instructions or [])

        # Also extract ASCII symbol strings matching known sinks if the binary has raw string table entries
        for cand_sink in list(self.OVERFLOW_SINKS.keys()) + list(self.COMMAND_INJECTION_SINKS.keys()) + list(self.FORMAT_STRING_SINKS):
            needle = b"\x00" + cand_sink.encode("ascii") + b"\x00"
            if needle in binary_bytes and cand_sink not in imports:
                imports.append(cand_sink)

        # 1. Dangerous Buffer Overflow Sinks (CWE-120 / CWE-787)
        for sym in imports:
            clean_sym = sym.split("!")[-1].split("@")[0].lstrip("_")
            lookup = sym if sym in self.OVERFLOW_SINKS else clean_sym
            if lookup in self.OVERFLOW_SINKS:
                cwe, sev, cvss, desc = self.OVERFLOW_SINKS[lookup]
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"RF-VULN-{len(findings)+1:03d}",
                        cwe_id=cwe,
                        title=f"Unsafe Memory/String Sink ({lookup})",
                        severity=sev,
                        cvss_estimate=cvss,
                        location_va="IMPORT_TABLE",
                        sink_or_section=lookup,
                        evidence=desc,
                        remediation=f"Replace {lookup}() with bounds-checked alternative (fgets, strncpy_s, snprintf).",
                    )
                )

        # 2. OS Command Injection Sinks (CWE-78)
        for sym in imports:
            clean_sym = sym.split("!")[-1].split("@")[0]
            lookup = sym if sym in self.COMMAND_INJECTION_SINKS else clean_sym
            if lookup in self.COMMAND_INJECTION_SINKS:
                cwe, sev, cvss, desc = self.COMMAND_INJECTION_SINKS[lookup]
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"RF-VULN-{len(findings)+1:03d}",
                        cwe_id=cwe,
                        title=f"OS Command Execution Sink ({lookup})",
                        severity=sev,
                        cvss_estimate=cvss,
                        location_va="IMPORT_TABLE",
                        sink_or_section=lookup,
                        evidence=desc,
                        remediation="Avoid invoking a command shell; pass arguments as an explicit argv array to execve/CreateProcess.",
                    )
                )

        # 3. Instruction-Level Patterns: Integer Overflow -> Alloc (CWE-190), UAF/Double-Free (CWE-416), Format String (CWE-134)
        freed_regs: Dict[str, int] = {}  # reg -> free_insn_va
        last_arg_reg_val: Dict[str, str] = {}

        for idx, (addr, mnem, op_str) in enumerate(insns):
            m = mnem.strip().lower()
            ops = [p.strip() for p in op_str.split(",") if p.strip()]

            if m in ("mov", "lea") and len(ops) >= 2:
                dst, src = ops[0].lower(), ops[1]
                last_arg_reg_val[dst] = src
                if dst in freed_regs:
                    # Reassigned with a new value -> no longer dangling
                    freed_regs.pop(dst, None)

            # Check if a freed register is dereferenced (`[rdi...]` or `[rax...]`) -> CWE-416 Use-After-Free
            for f_reg, free_va in list(freed_regs.items()):
                if f"[{f_reg}" in op_str.lower():
                    findings.append(
                        VulnerabilityFinding(
                            finding_id=f"RF-VULN-{len(findings)+1:03d}",
                            cwe_id="CWE-416",
                            title="Use-After-Free (Dangling Pointer Dereference)",
                            severity="CRITICAL",
                            cvss_estimate=9.1,
                            location_va=hex(addr),
                            sink_or_section=f"{mnem} {op_str}",
                            evidence=f"Register '{f_reg}' freed at {hex(free_va)} is dereferenced at {hex(addr)} without reassignment.",
                            remediation="Zero out pointers immediately after free() and validate object lifetime before dereferencing.",
                        )
                    )
                    freed_regs.pop(f_reg, None)

            if m in ("call", "bl", "blr") and ops:
                target = ops[0].split("!")[-1].lstrip("_")

                # 3a. Integer Overflow before Allocation (CWE-190 / CWE-680)
                if any(a_sink.lower() in target.lower() for a_sink in self.ALLOC_SINKS):
                    window = insns[max(0, idx - 5) : idx]
                    has_mul_or_shl = any(w_m.lower() in ("imul", "mul", "shl", "sal") for _, w_m, _ in window)
                    has_bounds_check = any(w_m.lower() in ("jo", "jc", "jb", "ja", "cmp") for _, w_m, _ in window)
                    if has_mul_or_shl and not has_bounds_check:
                        findings.append(
                            VulnerabilityFinding(
                                finding_id=f"RF-VULN-{len(findings)+1:03d}",
                                cwe_id="CWE-190",
                                title="Integer Overflow to Buffer Allocation Size",
                                severity="HIGH",
                                cvss_estimate=8.6,
                                location_va=hex(addr),
                                sink_or_section=target,
                                evidence=f"Unchecked multiplication/shift precedes allocation call '{target}' at {hex(addr)}.",
                                remediation="Check for arithmetic wraparound (e.g., count > SIZE_MAX / elem_size) or use calloc().",
                            )
                        )

                # 3b. Use-After-Free / Double-Free tracking (CWE-415 / CWE-416)
                if any(f_sink.lower() == target.lower() for f_sink in self.FREE_SINKS):
                    arg_reg = "rdi" if "rdi" in last_arg_reg_val or not ("rcx" in last_arg_reg_val) else "rcx"
                    if arg_reg in freed_regs:
                        findings.append(
                            VulnerabilityFinding(
                                finding_id=f"RF-VULN-{len(findings)+1:03d}",
                                cwe_id="CWE-415",
                                title="Double Free Vulnerability",
                                severity="CRITICAL",
                                cvss_estimate=9.4,
                                location_va=hex(addr),
                                sink_or_section=target,
                                evidence=f"Pointer in '{arg_reg}' freed at {hex(freed_regs[arg_reg])} is passed to '{target}' again at {hex(addr)}.",
                                remediation="Set pointer to NULL immediately after freeing to prevent duplicate deallocation.",
                            )
                        )
                    else:
                        freed_regs[arg_reg] = addr

                # 3c. Uncontrolled Format String (CWE-134)
                if any(fmt_s.lower() == target.lower() for fmt_s in self.FORMAT_STRING_SINKS):
                    fmt_src = last_arg_reg_val.get("rdi") or last_arg_reg_val.get("rcx") or ""
                    if fmt_src and ("rbp" in fmt_src.lower() or "rsp" in fmt_src.lower() or fmt_src.lower() in ("rax", "rsi", "rdx")):
                        findings.append(
                            VulnerabilityFinding(
                                finding_id=f"RF-VULN-{len(findings)+1:03d}",
                                cwe_id="CWE-134",
                                title="Uncontrolled Format String Parameter",
                                severity="HIGH",
                                cvss_estimate=8.5,
                                location_va=hex(addr),
                                sink_or_section=target,
                                evidence=f"Format argument to '{target}' at {hex(addr)} originates from dynamic/stack source '{fmt_src}'.",
                                remediation="Always pass a constant format string literal such as printf(\"%s\", user_buf).",
                            )
                        )

        # 4. Section W^X Memory Protection Audit (CWE-693)
        for sec in secs:
            if sec.get("writable") and sec.get("executable"):
                s_name = str(sec.get("name", ".unknown"))
                s_va = str(sec.get("virtual_address", "0x0"))
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"RF-VULN-{len(findings)+1:03d}",
                        cwe_id="CWE-693",
                        title=f"Writable & Executable (RWX / W^X Violation) Section ({s_name})",
                        severity="HIGH",
                        cvss_estimate=7.8,
                        location_va=s_va,
                        sink_or_section=s_name,
                        evidence=f"Section '{s_name}' at {s_va} has both WRITE and EXECUTE permissions enabled.",
                        remediation="Enforce strict W^X permissions; separate code (.text RX) from writable data (.data RW).",
                    )
                )

        # 5. Missing Exploit Mitigations when high-risk sinks exist
        if findings and mits:
            if mits.get("ASLR") is False or mits.get("DEP_NX") is False:
                findings.append(
                    VulnerabilityFinding(
                        finding_id=f"RF-VULN-{len(findings)+1:03d}",
                        cwe_id="CWE-693",
                        title="Missing Hardware Exploit Mitigations (ASLR / DEP Disabled)",
                        severity="MEDIUM",
                        cvss_estimate=6.2,
                        location_va="PE_OPTIONAL_HEADER",
                        sink_or_section="DllCharacteristics",
                        evidence=f"Binary exposes dangerous sinks while ASLR={mits.get('ASLR')} and DEP_NX={mits.get('DEP_NX')}.",
                        remediation="Compile with /DYNAMICBASE, /HIGHENTROPYVA, /NXCOMPAT, and /GUARD:CF.",
                    )
                )

        crit_c = sum(1 for f in findings if f.severity == "CRITICAL")
        high_c = sum(1 for f in findings if f.severity == "HIGH")
        med_c = sum(1 for f in findings if f.severity == "MEDIUM")

        if crit_c > 0:
            rating = "CRITICAL"
        elif high_c > 0:
            rating = "HIGH"
        elif med_c > 0:
            rating = "MEDIUM"
        elif findings:
            rating = "LOW"
        else:
            rating = "CLEAN"

        return VulnerabilityAuditReport(
            total_findings=len(findings),
            critical_count=crit_c,
            high_count=high_c,
            medium_count=med_c,
            overall_risk_rating=rating,
            findings=findings,
        )
