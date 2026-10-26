import argparse
import hashlib
import json
import os
import re
import struct
import sys
from typing import Dict, Any, List

from reverse_forge.pe_analyzer import PEAnalyzer
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.macho_analyzer import MachOAnalyzer
from reverse_forge.ghidra_analyzer import GhidraHeadlessAnalyzer
from reverse_forge.tool_installer import ToolchainInstaller
from reverse_forge.correlation_engine import CorrelationEngine
from reverse_forge.windows_sandbox import WindowsSandbox

MAX_STRING_SCAN_BYTES = 64 * 1024 * 1024


def hash_file(filepath: str) -> Dict[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}


def extract_strings(filepath: str, min_len: int = 5, max_bytes: int = MAX_STRING_SCAN_BYTES) -> Dict[str, List[str]]:
    min_len = max(1, int(min_len))
    with open(filepath, "rb") as f:
        data = f.read(max_bytes)

    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode("ascii") + rb",}")
    matches = [m.group(0).decode("ascii", errors="ignore") for m in ascii_pattern.finditer(data)]

    categorized: Dict[str, List[str]] = {
        "urls": [],
        "ips": [],
        "paths": [],
        "registry": [],
        "general": []
    }

    url_re = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
    ip_re = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    path_re = re.compile(r"(?:[a-zA-Z]:\\|\/)[^\s\"']+", re.IGNORECASE)
    reg_re = re.compile(r"(?:HKEY_|HKLM|HKCU)[^\s\"']+", re.IGNORECASE)

    for s in matches:
        if url_re.search(s):
            categorized["urls"].append(s)
        elif ip_re.search(s):
            categorized["ips"].append(s)
        elif reg_re.search(s):
            categorized["registry"].append(s)
        elif path_re.search(s):
            categorized["paths"].append(s)
        else:
            if len(categorized["general"]) < 200:
                categorized["general"].append(s)

    for k in categorized:
        categorized[k] = list(dict.fromkeys(categorized[k]))
    return categorized


def _require_existing_file(filepath: str) -> None:
    if not os.path.exists(filepath):
        sys.exit(f"Error: Artifact not found: {filepath}")


def _write_or_print(res: Dict[str, Any], output_path: str | None, label: str) -> None:
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
        print(f"Success: {label} written to {output_path}")
    elif (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()) or os.environ.get("RF_PRETTY_TUI") == "1":
        from reverse_forge.tui_renderer import render_pretty_cli_output
        print(render_pretty_cli_output(res, label))
    else:
        print(json.dumps(res, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="R3V3R53//F0RG3 Autonomous Multi-Tool Cross-Platform Reverse Engineering Engine"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # detect-tools
    subparsers.add_parser("detect-tools", help="Discover local/managed reverse engineering toolchain")

    # bootstrap
    boot_p = subparsers.add_parser("bootstrap", help="Automatically download and install required analysis tools")
    boot_p.add_argument("--tool", choices=["r2", "capstone", "all"], default="all", help="Tool to provision")

    # triage
    triage_p = subparsers.add_parser("triage", help="Perform cross-platform format triage (PE, ELF, Mach-O, JVM)")
    triage_p.add_argument("--input", "-i", required=True, help="Target binary artifact path")
    triage_p.add_argument("--output", "-o", help="Path to write JSON results")

    # correlate
    corr_p = subparsers.add_parser("correlate", help="Combinational multi-engine correlation analysis")
    corr_p.add_argument("--input", "-i", required=True, help="Target binary artifact path")
    corr_p.add_argument("--output", "-o", help="Path to write JSON results")

    # strings
    str_p = subparsers.add_parser("strings", help="Extract and categorize strings from binary")
    str_p.add_argument("--input", "-i", required=True, help="Target binary artifact path")
    str_p.add_argument("--output", "-o", help="Path to write JSON results")
    str_p.add_argument("--min-len", type=int, default=5, help="Minimum string length")

    # elf-audit
    eaudit_p = subparsers.add_parser("elf-audit", help="Full Linux ELF mitigation, dynamic linking, and symbol audit")
    eaudit_p.add_argument("--input", "-i", required=True, help="Target ELF binary")
    eaudit_p.add_argument("--output", "-o", help="Path to write JSON results")

    # macho-audit
    maudit_p = subparsers.add_parser("macho-audit", help="Full Apple Mach-O mitigation, dylib, symbol, and signing audit")
    maudit_p.add_argument("--input", "-i", required=True, help="Target Mach-O binary")
    maudit_p.add_argument("--output", "-o", help="Path to write JSON results")

    # ghidra-audit
    gaudit_p = subparsers.add_parser("ghidra-audit", help="Headless Ghidra function, sink xref, and decompilation export")
    gaudit_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    gaudit_p.add_argument("--output", "-o", help="Path to write JSON results")
    gaudit_p.add_argument("--timeout", type=int, default=120, help="Headless Ghidra timeout in seconds")

    # win-checksec
    wsec_p = subparsers.add_parser("win-checksec", help="Inspect Windows security mitigations (ASLR, DEP, CFG, SafeSEH)")
    wsec_p.add_argument("--input", "-i", required=True, help="Target Windows PE binary")
    wsec_p.add_argument("--output", "-o", help="Path to write JSON results")

    # win-iat
    wiat_p = subparsers.add_parser("win-iat", help="Analyze Windows Import Address Table and dangerous API capabilities")
    wiat_p.add_argument("--input", "-i", required=True, help="Target Windows PE binary")
    wiat_p.add_argument("--output", "-o", help="Path to write JSON results")

    # win-audit
    waudit_p = subparsers.add_parser("win-audit", help="Full Windows PE vulnerability audit")
    waudit_p.add_argument("--input", "-i", required=True, help="Target Windows PE binary")
    waudit_p.add_argument("--output", "-o", help="Path to write JSON results")

    # win-sandbox
    wsbox_p = subparsers.add_parser("win-sandbox", help="Generate Windows Sandbox (.wsb) isolated detonation profile")
    wsbox_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    wsbox_p.add_argument("--output", "-o", default="sandbox_profile.wsb", help="Output .wsb profile path")

    # pipeline (12-stage state machine)
    pipe_p = subparsers.add_parser("pipeline", help="Execute 12-stage autonomous reverse engineering pipeline")
    pipe_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    pipe_p.add_argument("--autonomy", choices=["0", "1", "2", "3", "4"], default="2", help="Autonomy level (0=Manual, 2=Supervised, 3=Autonomous)")
    pipe_p.add_argument("--output-json", help="Path to write final report JSON")
    pipe_p.add_argument("--output-md", help="Path to write final report Markdown")
    pipe_p.add_argument("--output-html", help="Path to write interactive HTML/SVG workbench dashboard")
    pipe_p.add_argument("--output-sarif", help="Path to write OASIS SARIF v2.1.0 report")
    pipe_p.add_argument("--output-sbom", help="Path to write CycloneDX v1.5 SBOM JSON")

    # behavioral-correlate (dynamic runtime correlation)
    behav_p = subparsers.add_parser("behavioral-correlate", help="Correlate runtime sandbox telemetry JSON with static analysis")
    behav_p.add_argument("--trace", "-t", required=True, help="Path to runtime telemetry trace JSON")
    behav_p.add_argument("--binary", "-b", help="Path to analyzed binary for static cross-reference")
    behav_p.add_argument("--output", "-o", help="Path to write correlation JSON output")

    # unpack (multi-layer container extraction)
    unpack_p = subparsers.add_parser("unpack", help="Inspect and extract embedded container layers, .NET headers, or JARs")
    unpack_p.add_argument("--input", "-i", required=True, help="Target archive/firmware/binary artifact")
    unpack_p.add_argument("--output", "-o", help="Path to write JSON inspection results")

    # dataflow (source-to-sink taint analysis)
    df_p = subparsers.add_parser("dataflow", help="Trace source-to-sink reachability paths and hazardous memory flows")
    df_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    df_p.add_argument("--output", "-o", help="Path to write JSON dataflow results")

    # crypto-audit (cryptographic primitives & hardcoded secrets)
    crypto_p = subparsers.add_parser("crypto-audit", help="Audit cryptographic constant tables and discover hardcoded secrets")
    crypto_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    crypto_p.add_argument("--output", "-o", help="Path to write JSON crypto audit results")

    # remediate (defensive patch & regression test generator)
    rem_p = subparsers.add_parser("remediate", help="Synthesize defensive code patch and regression unit test for a CWE")
    rem_p.add_argument("--cwe", required=True, help="Target CWE identifier (e.g. CWE-120, CWE-78, CWE-134, CWE-798)")
    rem_p.add_argument("--symbol", default="main", help="Target function symbol name")
    rem_p.add_argument("--output", "-o", help="Path to write JSON remediation payload")

    # ida-audit (Headless IDA Pro + Hex-Rays batch analysis)
    ida_p = subparsers.add_parser("ida-audit", help="Headless IDA Pro (idat64/idat) + Hex-Rays decompilation & FLIRT export")
    ida_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    ida_p.add_argument("--output", "-o", help="Path to write JSON results")
    ida_p.add_argument("--timeout", type=int, default=120, help="Headless IDA timeout in seconds")

    # bindiff (Structural binary & patch diffing)
    diff_p = subparsers.add_parser("bindiff", help="Compare two binary versions across sections, imports, and mitigations")
    diff_p.add_argument("--old", required=True, help="Baseline/unpatched binary path")
    diff_p.add_argument("--new", required=True, help="Updated/patched binary path")
    diff_p.add_argument("--output", "-o", help="Path to write JSON diff report")

    # symbolic-verify (SSA Symbolic Interval Bounds Verification)
    sym_p = subparsers.add_parser("symbolic-verify", help="Verify buffer access bounds over an SSA JSON block")
    sym_p.add_argument("--ssa-json", required=True, help="Path to JSON list of SSAOperation definitions")
    sym_p.add_argument("--output", "-o", help="Path to write symbolic proof JSON")

    # semantic-recover (Stripped function naming & struct field recovery)
    sem_p = subparsers.add_parser("semantic-recover", help="Recover semantic function names and struct fields from pseudocode")
    sem_p.add_argument("--function", default="sub_401000", help="Original stripped function name")
    sem_p.add_argument("--code-file", required=True, help="Path to decompiled C pseudocode file")
    sem_p.add_argument("--output", "-o", help="Path to write recovered symbol JSON")

    # smt-solve (SMT constraint & guard completeness verification)
    smt_p = subparsers.add_parser("smt-solve", help="Solve symbolic path constraints and verify buffer guard completeness")
    smt_p.add_argument("--constraints-json", required=True, help="Path to JSON list of PathConstraint objects")
    smt_p.add_argument("--length-var", help="Optional length variable name to check against buffer capacity")
    smt_p.add_argument("--buffer-cap", type=int, default=64, help="Buffer capacity in bytes for guard check")
    smt_p.add_argument("--output", "-o", help="Path to write SMT result JSON")

    # frida-gen (Read-only Frida DBI telemetry script generator)
    frida_p = subparsers.add_parser("frida-gen", help="Generate read-only Frida Interceptor.attach telemetry script")
    frida_p.add_argument("--symbols", required=True, help="Comma-separated list of function names or hex addresses")
    frida_p.add_argument("--module", default=None, help="Optional target module/DLL/shared-object name")
    frida_p.add_argument("--output", "-o", default="frida_telemetry.js", help="Output .js script path")

    # sig-scan (Wildcard byte-pattern & stripped function prologue scanner)
    sig_p = subparsers.add_parser("sig-scan", help="Scan binary for FLIRT/YARA-style byte signatures and stripped function prologues")
    sig_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    sig_p.add_argument("--rules", default=None, help="Optional path to custom JSON signature rules")
    sig_p.add_argument("--output", "-o", help="Path to write JSON signature scan results")

    # dashboard (Interactive HTML5/SVG Reverse-Engineering Workbench)
    dash_p = subparsers.add_parser("dashboard", help="Generate interactive single-file HTML5/SVG reverse-engineering workbench")
    dash_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    dash_p.add_argument("--output", "-o", default="reverse_forge_workbench.html", help="Output HTML file path")

    # sbom (CycloneDX v1.5 SBOM & SARIF v2.1.0 Exporter)
    sbom_p = subparsers.add_parser("sbom", help="Generate CycloneDX v1.5 Binary SBOM and optional SARIF v2.1.0 report")
    sbom_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    sbom_p.add_argument("--output", "-o", help="Path to write CycloneDX v1.5 SBOM JSON")
    sbom_p.add_argument("--sarif", help="Optional path to write OASIS SARIF v2.1.0 JSON")

    # batch-scan (Recursive directory / firmware corpus scanner + SQLite indexing)
    batch_p = subparsers.add_parser("batch-scan", help="Recursively scan directory of binaries and index findings in SQLite")
    batch_p.add_argument("--dir", "-d", required=True, help="Target directory or extracted firmware root")
    batch_p.add_argument("--db", default="reverse_forge_kb.sqlite", help="SQLite knowledge base file path")
    batch_p.add_argument("--max-files", type=int, default=50, help="Maximum binaries to analyze in batch")
    batch_p.add_argument("--output", "-o", help="Path to write JSON corpus rollup")

    # db-query (Query indexed artifacts and findings from SQLite KB)
    dbq_p = subparsers.add_parser("db-query", help="Query indexed findings from the SQLite Artifact Knowledge Base")
    dbq_p.add_argument("--db", default="reverse_forge_kb.sqlite", help="SQLite knowledge base file path")
    dbq_p.add_argument("--cwe", default=None, help="Filter findings by CWE ID (e.g. CWE-120)")
    dbq_p.add_argument("--min-cvss", type=float, default=0.0, help="Minimum CVSS 4.0 score filter")
    dbq_p.add_argument("--output", "-o", help="Path to write JSON query results")

    # posix-trace (Linux/POSIX isolated runner & strace/gdb log converter)
    pt_p = subparsers.add_parser("posix-trace", help="Parse Linux strace/gdb logs into telemetry JSON or generate isolated bwrap runner")
    pt_p.add_argument("--strace-log", help="Path to strace log file to convert into telemetry JSON")
    pt_p.add_argument("--gdb-log", help="Optional path to batch gdb crash log")
    pt_p.add_argument("--generate-runner", help="Target binary path to generate an isolated bubblewrap runner script")
    pt_p.add_argument("--output", "-o", required=True, help="Output telemetry JSON or .sh runner path")

    # doctor (Full 16-Phase System & Toolchain Readiness Verification)
    subparsers.add_parser("doctor", help="Verify all 16 R3V3R53//F0RG3 internal engines and external tool integrations")

    # decompile (Native Pure-Python SSA-to-C Micro-Decompiler)
    decomp_p = subparsers.add_parser("decompile", help="Perform native pure-Python micro-decompilation into ANSI C")
    decomp_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    decomp_p.add_argument("--entry", type=lambda x: int(x, 0), default=0x401000, help="Entry address (hex or int)")
    decomp_p.add_argument("--output", "-o", help="Optional path to write C source file")

    # alias-trace (Interprocedural pointer & heap lifecycle analysis)
    alias_p = subparsers.add_parser("alias-trace", help="Statically analyze heap memory lifecycles for UAF and double-free")
    alias_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    alias_p.add_argument("--output", "-o", help="Optional path to write JSON memory defect analysis")

    # uil-lift (Cross-architecture Unified IL lifter for x86/x64, ARM64, MIPS)
    uil_p = subparsers.add_parser("uil-lift", help="Lift assembly instructions into platform-independent Unified IL (UIL)")
    uil_p.add_argument("--arch", default="x64", choices=["x86", "x64", "arm64", "aarch64", "mips"], help="Source architecture")
    uil_p.add_argument("--asm", required=True, help="Semicolon-separated assembly instructions (e.g. 'mov rax, [rbp-0x10]; ret')")
    uil_p.add_argument("--output", "-o", help="Optional path to write JSON UIL output")

    # taint-trace (Fine-grained register & memory instruction taint tracker)
    tt_p = subparsers.add_parser("taint-trace", help="Run instruction-level register and memory taint tracking")
    tt_p.add_argument("--taint-reg", default="rdx", help="Initial register to mark tainted")
    tt_p.add_argument("--asm", required=True, help="Semicolon-separated assembly trace (e.g. 'mov rsi, rdx; call memcpy')")
    tt_p.add_argument("--output", "-o", help="Optional path to write JSON taint violations")

    # zeroday-scan (Heuristic zero-day anomaly clustering)
    zd_p = subparsers.add_parser("zeroday-scan", help="Score binary entry/functions for zero-day heuristic anomalies")
    zd_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    zd_p.add_argument("--threshold", type=float, default=0.50, help="Anomaly score threshold in [0.0, 1.0]")
    zd_p.add_argument("--output", "-o", help="Optional path to write JSON anomaly report")

    # patch-verify (Automated defensive patch resilience & C/Python harness verifier)
    pv_p = subparsers.add_parser("patch-verify", help="Verify defensive patch resilience and generate C/Python test harnesses")
    pv_p.add_argument("--cwe", required=True, help="Target CWE ID (e.g. CWE-120, CWE-78)")
    pv_p.add_argument("--symbol", default="parse_packet", help="Target function symbol name")
    pv_p.add_argument("--capacity", type=int, default=256, help="Target buffer capacity in bytes")
    pv_p.add_argument("--output", "-o", help="Optional path to write JSON verification report")

    # corpus-cluster (Multi-threaded distributed binary corpus clustering)
    cc_p = subparsers.add_parser("corpus-cluster", help="Concurrently profile and cluster a directory of binaries into families")
    cc_p.add_argument("--dir", "-d", required=True, help="Target corpus directory")
    cc_p.add_argument("--workers", type=int, default=4, help="Worker thread count")
    cc_p.add_argument("--output", "-o", help="Optional path to write JSON cluster report")

    # ssa-optimize (Phase 32: Cytron SSA Lifter & Algebraic Optimizer over UnifiedIL)
    ssa_p = subparsers.add_parser("ssa-optimize", help="Lift assembly to UnifiedIL SSA form and run constant/copy/DSE passes")
    ssa_p.add_argument("--arch", default="x64", choices=["x86", "x64", "arm64", "aarch64", "mips"], help="Source architecture")
    ssa_p.add_argument("--asm", required=True, help="Semicolon-separated assembly instructions")
    ssa_p.add_argument("--output", "-o", help="Optional path to write JSON SSA report")

    # structure-cfg (Phase 33: Pattern-Independent Region-Based Control-Flow Structurer)
    scfg_p = subparsers.add_parser("structure-cfg", help="Recover goto-free structured C (if/else, loops, switch) using post-dominators")
    scfg_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    scfg_p.add_argument("--output", "-o", help="Optional path to write structured C report")

    # vsa-analyze (Phase 34: Declarative Datalog Fact Engine & Value-Set Analysis)
    vsa_p = subparsers.add_parser("vsa-analyze", help="Run Datalog fixed-point inference and Value-Set Analysis (strided intervals)")
    vsa_p.add_argument("--asm", required=True, help="Semicolon-separated assembly instructions")
    vsa_p.add_argument("--output", "-o", help="Optional path to write JSON VSA report")

    # deobfuscate-mba (Phase 36: Mixed Boolean-Arithmetic & Opaque Predicate Deobfuscator)
    mba_p = subparsers.add_parser("deobfuscate-mba", help="Simplify Mixed Boolean-Arithmetic (MBA) expressions via truth-table vectors")
    mba_p.add_argument("--expr", required=True, help="Obfuscated MBA expression (e.g. '(x ^ y) + 2 * (x & y)')")
    mba_p.add_argument("--output", "-o", help="Optional path to write JSON MBA report")

    # cpp-rtti (Phase 37: C++ RTTI, VTable & Class Hierarchy Reconstructor)
    rtti_p = subparsers.add_parser("cpp-rtti", help="Reconstruct C++ classes, namespaces, and vtables from Itanium/MSVC RTTI")
    rtti_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    rtti_p.add_argument("--output", "-o", help="Optional path to write JSON RTTI report")

    # firmware-base (Phase 38: Bare-Metal Firmware Base-Address & RTOS Scanner)
    fwb_p = subparsers.add_parser("firmware-base", help="Infer memory load base address and RTOS signatures for raw firmware blobs")
    fwb_p.add_argument("--input", "-i", required=True, help="Target raw firmware binary")
    fwb_p.add_argument("--output", "-o", help="Optional path to write JSON firmware base report")

    # eh-frame (Phase 39: DWARF / .eh_frame Unwind & Function Boundary Parser)
    ehf_p = subparsers.add_parser("eh-frame", help="Parse .eh_frame CIE/FDE records to recover exact stripped function boundaries")
    ehf_p.add_argument("--input", "-i", required=True, help="Target binary or raw .eh_frame blob")
    ehf_p.add_argument("--output", "-o", help="Optional path to write JSON unwind report")

    # trace-diff (Phase 40: Differential Execution Trace & Crash Root-Cause Aligner)
    td_p = subparsers.add_parser("trace-diff", help="Align baseline vs. divergent execution traces and isolate divergence point")
    td_p.add_argument("--base-addrs", required=True, help="Comma-separated hex addresses for baseline trace (e.g. '0x401000,0x401004,0x401008')")
    td_p.add_argument("--div-addrs", required=True, help="Comma-separated hex addresses for divergent trace (e.g. '0x401000,0x401004,0x401020')")
    td_p.add_argument("--output", "-o", help="Optional path to write JSON differential trace report")

    # streaming-triage (Phase 41: Zero-Copy Memory-Mapped Streaming PE Analyzer)
    str_triage_p = subparsers.add_parser("streaming-triage", help="Zero-copy memory-mapped streaming PE triage for large binaries")
    str_triage_p.add_argument("--input", "-i", required=True, help="Target PE binary artifact")
    str_triage_p.add_argument("--output", "-o", help="Optional path to write JSON metadata report")

    # ab-bench (Phase 41: Statistical A/B Benchmarking & Optimization Testing)
    ab_p = subparsers.add_parser("ab-bench", help="Run empirical A/B statistical hypothesis test comparing triage variants")
    ab_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    ab_p.add_argument("--trials", "-n", type=int, default=10, help="Number of benchmark trials per variant (default: 10)")
    ab_p.add_argument("--warmup", type=int, default=2, help="Number of warmup trials (default: 2)")
    ab_p.add_argument("--output", "-o", help="Optional path to write JSON A/B experiment report")
    ab_p.add_argument("--output-md", help="Optional path to write Markdown A/B report")

    # gui (Phase 42: Modern Interactive Reverse Engineering Workbench)
    gui_p = subparsers.add_parser("gui", help="Launch the IDA Pro-beating interactive GUI Workbench application")
    gui_p.add_argument("--input", "-i", help="Initial binary artifact path to load")
    gui_p.add_argument("--port", "-p", type=int, default=8080, help="Local HTTP server port (default: 8080)")
    gui_p.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")

    # dossier (Phase 43: Unified Executive & Technical Binary Intelligence Dossier)
    dos_p = subparsers.add_parser("dossier", help="Generate unified one-stop executive & technical binary intelligence dossier")
    dos_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    dos_p.add_argument("--output", "-o", help="Optional path to write JSON dossier")

    # capabilities (Phase 43: CAPA-Style Behavioral Capability & MITRE ATT&CK Matcher)
    cap_p = subparsers.add_parser("capabilities", help="Detect behavioral capabilities and map to MITRE ATT&CK / MBC")
    cap_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    cap_p.add_argument("--output", "-o", help="Optional path to write JSON capability report")

    # xrefs (Phase 43: Bidirectional CALL, JMP & RIP-Relative String Cross-References)
    xr_p = subparsers.add_parser("xrefs", help="Extract CALL, JMP, and RIP-relative LEA/MOV cross-references")
    xr_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    xr_p.add_argument("--output", "-o", help="Optional path to write JSON xrefs report")

    # inspect (Phase 43: ImHex-Style 14-Format Data Inspector at any Offset or VA)
    ins_p = subparsers.add_parser("inspect", help="Decode 14 data types (ints, floats, timestamps, GUID, asm) at any offset/VA")
    ins_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    ins_p.add_argument("--offset", default="0x0", help="File offset or Virtual Address (e.g. 0x401000 or 64)")
    ins_p.add_argument("--output", "-o", help="Optional path to write JSON inspection report")

    # ask (Phase 43: Smart Natural/Keyword/Address Binary Query Engine)
    ask_p = subparsers.add_parser("ask", help="Query the binary for any capability, symbol, string, or address (e.g. 'network', 'crypto', '0x401000')")
    ask_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    ask_p.add_argument("--query", "-q", required=True, help="Question, keyword, symbol, hex pattern, or address")
    ask_p.add_argument("--output", "-o", help="Optional path to write JSON query answer")

    # desktop-app (Phase 45: Cross-Platform Native Desktop Studio Application)
    app_p = subparsers.add_parser("desktop-app", help="Launch Cross-Platform Native Desktop Studio (Tkinter Dark IDE or Chromeless App Window)")
    app_p.add_argument("--input", "-i", help="Optional binary artifact to load on startup")
    app_p.add_argument("--mode", choices=["tk", "app-window", "headless-json"], default="tk", help="Desktop UI mode")
    app_p.add_argument("--output", "-o", help="Optional output file when running in headless-json mode")

    # floss-strings (Phase 46: FLOSS-Style Stack & XOR/ADD Obfuscated String Solver)
    fls_p = subparsers.add_parser("floss-strings", help="Recover stack-constructed strings and XOR/ADD obfuscated strings")
    fls_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    fls_p.add_argument("--min-len", type=int, default=4, help="Minimum string length")
    fls_p.add_argument("--output", "-o", help="Optional path to write JSON deobfuscated string report")

    # compiler-profile (Phase 47: DIE-Style Compiler, Packer, Rich Header, Imphash & Overlay Profiler)
    cmp_p = subparsers.add_parser("compiler-profile", help="Fingerprint compiler, packer, PE Rich Header, Imphash, and trailing overlay")
    cmp_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    cmp_p.add_argument("--output", "-o", help="Optional path to write JSON compiler/packer profile")

    # syscall-scan (Phase 48: Direct Kernel Syscall ABI Resolver)
    sys_p = subparsers.add_parser("syscall-scan", help="Detect direct syscall / int 0x80 / svc #0 instructions and resolve kernel ABI names")
    sys_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    sys_p.add_argument("--platform", default="linux_x64", choices=["linux_x64", "windows_nt_x64", "linux_x86", "linux_arm64"], help="Target syscall ABI")
    sys_p.add_argument("--output", "-o", help="Optional path to write JSON syscall report")

    # struct-parse (Phase 48: Kaitai/ImHex-Style Declarative C-Struct Template Parser)
    stp_p = subparsers.add_parser("struct-parse", help="Overlay a C struct definition onto any binary offset and unpack typed fields")
    stp_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    stp_p.add_argument("--struct-def", required=True, help="C struct definition (e.g. 'struct Hdr { uint32_t magic; uint16_t ver; };')")
    stp_p.add_argument("--offset", default="0x0", help="File offset to apply struct template")
    stp_p.add_argument("--output", "-o", help="Optional path to write JSON struct parse report")

    # binary-patch (Phase 49: LIEF/Binary-Ninja Style Non-Destructive Binary Patcher & Micro-Assembler)
    bp_p = subparsers.add_parser("binary-patch", help="Apply NOP-fill, branch inversion (je<->jne), or return-value patches and save binary")
    bp_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    bp_p.add_argument("--action", required=True, choices=["nop", "invert-branch", "force-return"], help="Patch operation type")
    bp_p.add_argument("--offset", required=True, help="File offset to patch (hex or int)")
    bp_p.add_argument("--length", type=int, default=4, help="Byte length for NOP fill")
    bp_p.add_argument("--ret-val", type=int, default=1, help="Immediate return value for force-return")
    bp_p.add_argument("--save-binary", help="Optional output path for patched binary file")
    bp_p.add_argument("--output", "-o", help="Optional path to write JSON patch transaction log")

    # project-export (Phase 50: Persistent .rfdb Project DB & C-Header / IDAPython / Ghidra Script Exporter)
    px_p = subparsers.add_parser("project-export", help="Create or export .rfdb project annotations to C Header (.h), IDAPython, or Ghidra script")
    px_p.add_argument("--format", choices=["c-header", "idapython", "ghidra", "rfdb"], default="c-header", help="Export format")
    px_p.add_argument("--rename", action="append", default=[], help="Rename mapping ADDR=NAME (e.g. 0x401000=decrypt_packet)")
    px_p.add_argument("--comment", action="append", default=[], help="Comment mapping ADDR=TEXT (e.g. '0x401000=Entry loop')")
    px_p.add_argument("--output", "-o", help="Optional path to write exported artifact")

    # jump-tables (Phase 51: Indirect Jump Table & Multi-Target Switch Resolver)
    jt_p = subparsers.add_parser("jump-tables", help="Resolve indirect switch jump tables via backward microcode slicing")
    jt_p.add_argument("--asm", required=True, help="Semicolon-separated assembly stream containing indirect jmp")
    jt_p.add_argument("--output", "-o", help="Optional path to write JSON jump table report")

    # pdb-parse (Phase 52: Automated Microsoft PDB & CodeView RSDS Symbol Server Engine)
    pdb_p = subparsers.add_parser("pdb-parse", help="Extract PE CodeView RSDS debug records, Symbol Server URLs, or parse MSF v7 PDB files")
    pdb_p.add_argument("--input", "-i", required=True, help="Target PE binary or .pdb file")
    pdb_p.add_argument("--output", "-o", help="Optional path to write JSON PDB/RSDS report")

    # struct-infer (Phase 53: Struct Layout Inference & Pointer Offset Recovery Engine)
    si_p = subparsers.add_parser("struct-infer", help="Infer C struct layouts from pointer offset dereferences and rewrite AST")
    si_p.add_argument("--code", required=True, help="Decompiled C or assembly lines containing pointer offsets")
    si_p.add_argument("--output", "-o", help="Optional path to write JSON struct recovery report")

    # flirt-scan (Phase 54: FLIRT Compiler Runtime Identification & De-Stripping Engine)
    flr_p = subparsers.add_parser("flirt-scan", help="Identify static CRT and library functions using IDA-compatible FLIRT patterns & CRC-16")
    flr_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    flr_p.add_argument("--output", "-o", help="Optional path to write JSON FLIRT match report")

    # gdb-debug (Phase 55: Native GDB/WinDbg Remote Serial Protocol Dynamic Debugger)
    gdb_p = subparsers.add_parser("gdb-debug", help="Connect to GDB RSP target (or simulated stub) to inspect registers, breakpoints, and step")
    gdb_p.add_argument("--host", default="127.0.0.1", help="GDB RSP host")
    gdb_p.add_argument("--port", type=int, default=1234, help="GDB RSP port")
    gdb_p.add_argument("--simulated", action="store_true", default=True, help="Use built-in deterministic RSP target simulator")
    gdb_p.add_argument("--steps", type=int, default=2, help="Number of single-step instructions to execute")
    gdb_p.add_argument("--output", "-o", help="Optional path to write JSON debugger state snapshot")

    # canvas-cull (Phase 56: High-Performance Virtualized Workbench Quadtree & Multi-LOD Engine)
    cv_p = subparsers.add_parser("canvas-cull", help="Benchmark Quadtree viewport frustum culling and Multi-LOD serialization")
    cv_p.add_argument("--nodes", type=int, default=100, help="Number of synthetic CFG nodes to populate")
    cv_p.add_argument("--zoom", type=float, default=1.0, help="Viewport zoom scale (e.g. 1.0=high, 0.5=medium, 0.2=low)")
    cv_p.add_argument("--output", "-o", help="Optional path to write JSON viewport frame")

    # recursive-disasm (Phase 57: Pure-Python Table-Driven Recursive Descent Multi-Arch Disassembler)
    rd_p = subparsers.add_parser("recursive-disasm", help="Run pure-Python table-driven recursive-descent disassembly (x64/ARM64/RISC-V)")
    rd_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    rd_p.add_argument("--arch", default="x64", choices=["x86", "x64", "arm64", "riscv"], help="Target instruction set")
    rd_p.add_argument("--output", "-o", help="Optional path to write JSON recursive disassembly")

    # go-rust-recover (Phase 58: Go pclntab & Rust v0 Symbol & Panic Reconstructor)
    gr_p = subparsers.add_parser("go-rust-recover", help="Recover Go runtime.pclntab functions and demangle Rust v0/_ZN symbols")
    gr_p.add_argument("--input", "-i", required=True, help="Target Go or Rust binary artifact")
    gr_p.add_argument("--output", "-o", help="Optional path to write JSON Go/Rust reconstruction report")

    # decompile-full (Phase 62: Unified 8-Pass End-to-End Decompilation Pipeline)
    df_p = subparsers.add_parser("decompile-full", help="Run the unified 8-pass decompilation pipeline (RecursiveDisasm -> JumpTable -> FLIRT -> UIL -> SSA -> MBA -> Region -> Struct)")
    df_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    df_p.add_argument("--arch", default="x64", choices=["x86", "x64", "arm64", "riscv"], help="Target architecture")
    df_p.add_argument("--output", "-o", help="Optional path to write JSON unified decompilation report")

    # vuln-scan (Phase 68: Automated CWE Vulnerability & Exploit Primitive Scanner)
    vs_p = subparsers.add_parser("vuln-scan", help="Scan binary for CWE memory-corruption & logic vulnerabilities")
    vs_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    vs_p.add_argument("--output", "-o", help="Optional path to write JSON vulnerability scan report")

    # bytecode-audit (Phase 71: Multi-Runtime .NET CLR / Android DEX / WebAssembly WASM Decompiler)
    bc_p = subparsers.add_parser("bytecode-audit", help="Disassemble & decompile .NET CLR, Android DEX, or WebAssembly (WASM) binaries")
    bc_p.add_argument("--input", "-i", required=True, help="Target managed or bytecode binary")
    bc_p.add_argument("--output", "-o", help="Optional path to write JSON bytecode report")

    # emulate-cpu (Phase 72: Pure-Python Deterministic CPU & API Stub Emulator)
    em_p = subparsers.add_parser("emulate-cpu", help="Emulate binary entry point or shellcode in pure-Python CPU & API sandbox")
    em_p.add_argument("--input", "-i", required=True, help="Target binary or raw shellcode")
    em_p.add_argument("--steps", type=int, default=64, help="Maximum instructions to emulate")
    em_p.add_argument("--output", "-o", help="Optional path to write JSON CPU emulation trace")

    # abi-recover (Phase 73: ABI Calling Convention, Prototype & Stack-Frame Variable Recovery)
    ab_p = subparsers.add_parser("abi-recover", help="Recover function ABI calling convention, C prototype & stack-frame variables")
    ab_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    ab_p.add_argument("--output", "-o", help="Optional path to write JSON ABI & stack-frame report")

    # extract-config (Phase 74: C2 Configuration, Custom Base64 Alphabet & RC4 KSA Extractor)
    ec_p = subparsers.add_parser("extract-config", help="Extract custom Base64 tables, RC4 KSA loops, mutexes & C2 configs")
    ec_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    ec_p.add_argument("--output", "-o", help="Optional path to write JSON config & crypto report")

    # container-triage (Phase 76: Multi-Container APK/ZIP/PyInstaller/OLE2/PDF Dropper Triage)
    ct_p = subparsers.add_parser("container-triage", help="Recursively triage APK, ZIP, PyInstaller, OLE2, or PDF dropper containers")
    ct_p.add_argument("--input", "-i", required=True, help="Target archive, APK, installer, or document")
    ct_p.add_argument("--output", "-o", help="Optional path to write JSON container triage report")

    # generate-yara (Phase 77: Automated YARA Rule, SIGMA YAML & STIX 2.1 Threat-Intel Generator)
    gy_p = subparsers.add_parser("generate-yara", help="Auto-synthesize YARA rule, SIGMA YAML & STIX 2.1 bundle from binary triage")
    gy_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    gy_p.add_argument("--output", "-o", help="Optional path to write JSON detection bundle")

    # export-bridge (Phase 78: Universal Layer-1 -> Layer-2 Bridge Exporter for IDA/Ghidra/Binja/x64dbg)
    eb_p = subparsers.add_parser("export-bridge", help="Export Layer-1 triage findings into IDA Pro, Ghidra, Binary Ninja & x64dbg (.dd64)")
    eb_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    eb_p.add_argument("--output", "-o", help="Optional path to write JSON Layer-2 bridge package")

    # force-exec (Phase 81: Under-Constrained Force-Execution & Auto-Paging CPU Micro-Visor)
    fe_p = subparsers.add_parser("force-exec", help="Force-execute binary across both conditional branch arms with lazy shadow auto-paging")
    fe_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    fe_p.add_argument("--paths", type=int, default=4, help="Maximum branch paths to explore")
    fe_p.add_argument("--output", "-o", help="Optional path to write JSON force-execution report")

    # decompile-fuse (Phase 82: Multi-Decompiler AST Fusion, Pre-Deobfuscation & Visor Verification)
    dfu_p = subparsers.add_parser("decompile-fuse", help="Run Multi-Decompiler AST Fusion with pre-deobfuscation & visor return verification")
    dfu_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    dfu_p.add_argument("--output", "-o", help="Optional path to write JSON fused decompilation report")

    # memory-dump (Phase 84: Windows Minidump MDMP, ELF ET_CORE & In-Memory PE Unmapper)
    md_p = subparsers.add_parser("memory-dump", help="Analyze Windows Minidump (.dmp), ELF Core Dump, or unmap in-memory PE image")
    md_p.add_argument("--input", "-i", required=True, help="Target minidump, core dump, or memory-dumped PE")
    md_p.add_argument("--output", "-o", help="Optional path to write JSON memory dump forensics report")

    # rust-bench (Phase 86-90: Zero-Copy Native Rust / C-ABI Core & Ghidra P-Code Benchmark)
    rb_p = subparsers.add_parser("rust-bench", help="Benchmark compiled zero-copy Rust/C-ABI core vs Python and run Ghidra P-Code SSA")
    rb_p.add_argument("--size", type=int, default=524288, help="Buffer size in bytes to benchmark")
    rb_p.add_argument("--output", "-o", help="Optional path to write JSON benchmark report")

    # rust-decompile (Phase 86-90: Native Rust Ghidra P-Code & Heritage SSA Decompiler)
    rd_p = subparsers.add_parser("rust-decompile", help="Decompile binary using the native Rust Ghidra P-Code & Heritage SSA engine")
    rd_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    rd_p.add_argument("--output", "-o", help="Optional path to write JSON P-Code decompilation report")

    # pcap-dissect (Phase 91-100: Wireshark/Zeek PCAP Dissector & Netzob Protocol Grammar Inferencer)
    pc_p = subparsers.add_parser("pcap-dissect", help="Dissect PCAP capture and infer L7 binary protocol struct grammar (Wireshark/Netzob)")
    pc_p.add_argument("--input", "-i", required=True, help="Target .pcap file")
    pc_p.add_argument("--output", "-o", help="Optional path to write JSON PCAP protocol report")

    # imhex-eval (Phase 91-100: ImHex .hexpat Binary Struct Pattern DSL Evaluator)
    ih_p = subparsers.add_parser("imhex-eval", help="Evaluate an ImHex .hexpat struct definition against a binary file")
    ih_p.add_argument("--input", "-i", required=True, help="Target binary artifact")
    ih_p.add_argument("--pattern", "-p", default="struct Header { u16 magic; u16 cblp; u32 reserved; };", help="ImHex struct pattern")
    ih_p.add_argument("--offset", type=int, default=0, help="Starting byte offset")
    ih_p.add_argument("--output", "-o", help="Optional path to write JSON evaluated fields")

    # jvm-decompile (Phase 91-100: Recaf/CFR/FernFlower Java .class Bytecode Decompiler)
    jv_p = subparsers.add_parser("jvm-decompile", help="Parse JVM .class (0xCAFEBABE) constant pool and decompile to Java")
    jv_p.add_argument("--input", "-i", required=True, help="Target .class file")
    jv_p.add_argument("--output", "-o", help="Optional path to write JSON JVM decompilation report")

    # binwalk-carve (Phase 91-100: Binwalk Embedded Filesystem & Compression Partition Carver)
    bw_p = subparsers.add_parser("binwalk-carve", help="Scan firmware image for SquashFS, CramFS, UBI, uImage, DTB, and compressed streams")
    bw_p.add_argument("--input", "-i", required=True, help="Target firmware image")
    bw_p.add_argument("--output", "-o", help="Optional path to write JSON Binwalk partition report")

    args = parser.parse_args()
    installer = ToolchainInstaller()

    if args.command == "detect-tools":
        results = installer.detect_all()
        print(json.dumps(results, indent=2))

    elif args.command == "bootstrap":
        if args.tool == "r2":
            res = installer.install_radare2()
        elif args.tool == "capstone":
            res = installer.install_capstone_disassembler()
        else:
            res = installer.bootstrap_all()
        print(json.dumps(res, indent=2))

    elif args.command == "triage":
        _require_existing_file(args.input)
        with open(args.input, "rb") as f:
            data = f.read()

        engine = CorrelationEngine()
        fmt = engine.identify_format(data)
        if fmt == "PE":
            meta = PEAnalyzer(data).analyze()
        elif fmt == "ELF":
            meta = ELFAnalyzer(data).analyze()
        elif fmt == "Mach-O":
            meta = MachOAnalyzer(data).analyze()
        elif fmt == "JVM Class":
            minor_v, major_v = struct.unpack_from(">HH", data, 4)
            meta = {
                "format": "JVM Class Bytecode",
                "architecture": "JVM",
                "class_version": f"{major_v}.{minor_v}",
                "entropy": PEAnalyzer.calculate_entropy(data),
            }
        else:
            meta = {"format": "Unknown/Raw Binary", "entropy": PEAnalyzer.calculate_entropy(data)}

        res = {
            "artifact": os.path.abspath(args.input),
            "filename": os.path.basename(args.input),
            "size_bytes": os.path.getsize(args.input),
            "hashes": hash_file(args.input),
            "format": fmt,
            "metadata": meta
        }
        _write_or_print(res, args.output, "Triage analysis")

    elif args.command == "correlate":
        _require_existing_file(args.input)
        engine = CorrelationEngine()
        res = engine.analyze_artifact(args.input)
        _write_or_print(res, args.output, "Correlated analysis")

    elif args.command == "strings":
        _require_existing_file(args.input)
        res = extract_strings(args.input, min_len=args.min_len)
        _write_or_print(res, args.output, "Strings")

    elif args.command == "elf-audit":
        _require_existing_file(args.input)
        with open(args.input, "rb") as f:
            data = f.read()
        res = ELFAnalyzer(data).full_audit()
        res["artifact"] = os.path.abspath(args.input)
        _write_or_print(res, args.output, "ELF audit")

    elif args.command == "macho-audit":
        _require_existing_file(args.input)
        with open(args.input, "rb") as f:
            data = f.read()
        res = MachOAnalyzer(data).full_audit()
        res["artifact"] = os.path.abspath(args.input)
        _write_or_print(res, args.output, "Mach-O audit")

    elif args.command == "ghidra-audit":
        _require_existing_file(args.input)
        ghidra = GhidraHeadlessAnalyzer()
        res = ghidra.analyze(args.input, timeout=args.timeout)
        _write_or_print(res, args.output, "Ghidra headless audit")

    elif args.command in ("win-checksec", "win-iat", "win-audit"):
        _require_existing_file(args.input)
        from reverse_forge.windows_engine import WindowsEngine
        wengine = WindowsEngine(args.input)
        if args.command == "win-checksec":
            res = wengine.check_mitigations()
            msg = "Checksec"
        elif args.command == "win-iat":
            res = wengine.inspect_iat()
            msg = "IAT analysis"
        else:
            res = wengine.full_audit()
            msg = "Windows audit"
        _write_or_print(res, args.output, msg)

    elif args.command == "win-sandbox":
        _require_existing_file(args.input)
        wsb = WindowsSandbox(args.input)
        out = wsb.generate_wsb_profile(args.output)
        print(f"[+] Windows Sandbox profile generated: {out}")

    elif args.command == "pipeline":
        _require_existing_file(args.input)
        from reverse_forge.pipeline import PipelineStateMachine, AutonomyLevel
        autonomy = AutonomyLevel(int(args.autonomy))
        sm = PipelineStateMachine(args.input, autonomy_level=autonomy)
        print(f"[*] Starting 12-stage R3V3R53//F0RG3 pipeline on {args.input} (Autonomy Level: {autonomy.name})...")
        res = sm.run_all()
        for st in res["stages"]:
            status_symbol = "[+]" if st["status"] == "COMPLETED" else "[-]"
            detail = st["summary"] if st["summary"] else (st.get("error") or "")
            print(f"  {status_symbol} Stage {st['stage']}: {st['name']} -> {st['status']} ({detail})")

        if args.output_json:
            with open(args.output_json, "w", encoding="utf-8") as f:
                json.dump(res["report_json"], f, indent=2)
            print(f"[+] JSON report saved to {args.output_json}")

        if args.output_md:
            with open(args.output_md, "w", encoding="utf-8") as f:
                f.write(res["report_markdown"])
            print(f"[+] Markdown report saved to {args.output_md}")

        if getattr(args, "output_html", None):
            from reverse_forge.visual_dashboard import DashboardGenerator
            html_out = DashboardGenerator.write_dashboard_from_pipeline(sm, args.output_html)
            print(f"[+] Interactive HTML/SVG dashboard saved to {html_out}")

        if getattr(args, "output_sarif", None):
            from reverse_forge.sarif_sbom_exporter import SARIFExporter
            sarif_doc = SARIFExporter.to_sarif(res)
            with open(args.output_sarif, "w", encoding="utf-8") as f:
                json.dump(sarif_doc, f, indent=2)
            print(f"[+] SARIF v2.1.0 report saved to {args.output_sarif}")

        if getattr(args, "output_sbom", None):
            from reverse_forge.sarif_sbom_exporter import CycloneDXExporter
            sbom_doc = CycloneDXExporter.to_cyclonedx(res, static_metadata=sm.static_metadata)
            with open(args.output_sbom, "w", encoding="utf-8") as f:
                json.dump(sbom_doc, f, indent=2)
            print(f"[+] CycloneDX v1.5 SBOM saved to {args.output_sbom}")

        if not any([
            args.output_json,
            args.output_md,
            getattr(args, "output_html", None),
            getattr(args, "output_sarif", None),
            getattr(args, "output_sbom", None),
        ]):
            print("\n" + res["report_markdown"])

    elif args.command == "behavioral-correlate":
        _require_existing_file(args.trace)
        from reverse_forge.behavioral_engine import BehavioralTelemetryEngine
        b_engine = BehavioralTelemetryEngine()
        counts = b_engine.ingest_json_trace(args.trace)
        print(f"[*] Ingested runtime trace: {counts}")

        static_ctx: Dict[str, Any] = {}
        if args.binary and os.path.exists(args.binary):
            static_ctx["strings"] = extract_strings(args.binary)

        matches = b_engine.correlate_with_static_analysis(static_ctx)
        summary = b_engine.generate_behavioral_summary()
        _write_or_print(summary, args.output, "Behavioral Correlation")

    elif args.command == "unpack":
        _require_existing_file(args.input)
        from reverse_forge.layer_unpacker import LayerUnpacker
        with open(args.input, "rb") as f:
            data = f.read()

        containers = LayerUnpacker.identify_embedded_containers(data)
        dotnet_info = LayerUnpacker.inspect_dotnet_metadata(data)
        fat_slices = LayerUnpacker.parse_macho_fat_slices(data)
        jar_info = LayerUnpacker.inspect_java_archive(args.input) if zipfile.is_zipfile(args.input) else {}

        res = {
            "artifact": os.path.abspath(args.input),
            "size_bytes": len(data),
            "dotnet": dotnet_info,
            "embedded_containers": [{"type": c[0], "offset": c[1], "size": c[2]} for c in containers],
            "macho_fat_slices": fat_slices,
            "java_archive": jar_info,
        }
        _write_or_print(res, args.output, "Container & Layer Inspection")

    elif args.command == "dataflow":
        _require_existing_file(args.input)
        from reverse_forge.dataflow_engine import DataFlowGraph
        from reverse_forge.ghidra_analyzer import GhidraHeadlessAnalyzer
        ghidra = GhidraHeadlessAnalyzer()
        g_res = ghidra.analyze(args.input, timeout=60)

        dfg = DataFlowGraph()
        sinks = dict(g_res.get("sink_xrefs", {}))
        if not sinks and g_res.get("analysis", {}).get("dangerous_sink_xrefs"):
            for item in g_res["analysis"]["dangerous_sink_xrefs"]:
                s_name = item.get("sink", "").lstrip("_")
                caller = item.get("caller_function") or "unknown"
                if s_name:
                    sinks.setdefault(s_name, []).append(caller)
        if sinks:
            dfg.build_from_xrefs(sinks)

        flows = dfg.analyze_source_to_sink_flows()
        res = {
            "artifact": os.path.abspath(args.input),
            "total_call_edges": len(dfg.call_edges),
            "total_functions_mapped": len(dfg.functions),
            "discovered_taint_paths": [
                {
                    "source": f.source_name,
                    "sink": f.sink_name,
                    "path": f.intermediate_nodes,
                    "confidence": f.path_confidence,
                    "cwe": f.cwe,
                    "description": f.description
                }
                for f in flows
            ]
        }
        _write_or_print(res, args.output, "Data-Flow & Taint Analysis")

    elif args.command == "crypto-audit":
        _require_existing_file(args.input)
        from reverse_forge.crypto_engine import CryptoSecretEngine
        with open(args.input, "rb") as f:
            data = f.read()

        c_engine = CryptoSecretEngine()
        audit = c_engine.full_crypto_audit(data)
        audit["artifact"] = os.path.abspath(args.input)
        _write_or_print(audit, args.output, "Crypto & Secret Audit")

    elif args.command == "remediate":
        from reverse_forge.remediation_engine import RemediationEngine
        from dataclasses import asdict
        rem = RemediationEngine()
        patch = rem.generate_defensive_patch(f"VULN-{args.cwe}", args.cwe, args.symbol)
        harness = rem.generate_regression_test_harness(args.symbol, args.cwe)

        res = {
            "cwe_id": args.cwe,
            "target_symbol": args.symbol,
            "defensive_patch": asdict(patch),
            "regression_harness": asdict(harness)
        }
        _write_or_print(res, args.output, "Defensive Remediation Synthesis")

    elif args.command == "ida-audit":
        _require_existing_file(args.input)
        from reverse_forge.ida_analyzer import IDAHeadlessAnalyzer
        ida = IDAHeadlessAnalyzer()
        res = ida.analyze(args.input, timeout=args.timeout)
        _write_or_print(res, args.output, "IDA Headless Audit")

    elif args.command == "bindiff":
        _require_existing_file(args.old)
        _require_existing_file(args.new)
        from reverse_forge.bindiff_engine import BinaryDiffEngine
        differ = BinaryDiffEngine()
        res = differ.diff_files(args.old, args.new)
        _write_or_print(res, args.output, "Structural Binary Diff")

    elif args.command == "symbolic-verify":
        _require_existing_file(args.ssa_json)
        from dataclasses import asdict
        from reverse_forge.symbolic_ir_engine import SymbolicIREngine, SSAOperation
        with open(args.ssa_json, "r", encoding="utf-8") as f:
            raw_ops = json.load(f)
        ops = [SSAOperation(**item) for item in raw_ops]
        engine = SymbolicIREngine()
        proofs = engine.evaluate_ssa_block(ops)
        res = {"ssa_operations_count": len(ops), "proofs": [asdict(p) for p in proofs]}
        _write_or_print(res, args.output, "Symbolic Bounds Verification")

    elif args.command == "semantic-recover":
        _require_existing_file(args.code_file)
        from dataclasses import asdict
        from reverse_forge.semantic_recovery import SemanticRecoveryEngine
        with open(args.code_file, "r", encoding="utf-8") as f:
            code_text = f.read()
        rec_engine = SemanticRecoveryEngine()
        recovered = rec_engine.recover_from_pseudocode(args.function, code_text)
        _write_or_print(asdict(recovered), args.output, "Semantic Symbol & Struct Recovery")

    elif args.command == "smt-solve":
        _require_existing_file(args.constraints_json)
        from dataclasses import asdict
        from reverse_forge.smt_solver_engine import SMTSolverEngine, PathConstraint
        with open(args.constraints_json, "r", encoding="utf-8") as f:
            raw_c = json.load(f)
        constraints = [PathConstraint(**item) for item in raw_c]
        solver = SMTSolverEngine()
        solve_res = solver.solve_constraints(constraints)
        out_payload: Dict[str, Any] = {"feasibility": asdict(solve_res)}
        if args.length_var:
            out_payload["guard_verification"] = solver.verify_guard_completeness(
                constraints, args.length_var, args.buffer_cap
            )
        _write_or_print(out_payload, args.output, "SMT Path & Guard Verification")

    elif args.command == "frida-gen":
        from reverse_forge.frida_dbi_engine import FridaDBIEngine
        sym_list = [s.strip() for s in args.symbols.split(",") if s.strip()]
        out_js = FridaDBIEngine.write_frida_script(args.output, sym_list, module_name=args.module)
        print(f"[+] Frida DBI telemetry script generated: {out_js}")

    elif args.command == "sig-scan":
        _require_existing_file(args.input)
        from reverse_forge.signature_engine import SignatureEngine
        with open(args.input, "rb") as f:
            data = f.read()
        sig_engine = SignatureEngine()
        if args.rules:
            sig_engine.load_rules_from_json(args.rules)
        res = sig_engine.full_signature_scan(data)
        res["artifact"] = os.path.abspath(args.input)
        _write_or_print(res, args.output, "Signature & Prologue Scan")

    elif args.command == "dashboard":
        _require_existing_file(args.input)
        from reverse_forge.pipeline import PipelineStateMachine, AutonomyLevel
        from reverse_forge.visual_dashboard import DashboardGenerator
        sm = PipelineStateMachine(args.input, autonomy_level=AutonomyLevel.AUTONOMOUS)
        sm.run_all()
        html_out = DashboardGenerator.write_dashboard_from_pipeline(sm, args.output)
        print(f"[+] Interactive HTML/SVG workbench generated: {html_out}")

    elif args.command == "sbom":
        _require_existing_file(args.input)
        from reverse_forge.pipeline import PipelineStateMachine, AutonomyLevel
        from reverse_forge.sarif_sbom_exporter import CycloneDXExporter, SARIFExporter
        sm = PipelineStateMachine(args.input, autonomy_level=AutonomyLevel.AUTONOMOUS)
        state = sm.run_all()
        sbom_doc = CycloneDXExporter.to_cyclonedx(state, static_metadata=sm.static_metadata)
        if args.sarif:
            sarif_doc = SARIFExporter.to_sarif(state)
            with open(args.sarif, "w", encoding="utf-8") as sf:
                json.dump(sarif_doc, sf, indent=2)
            print(f"[+] SARIF v2.1.0 report written to {args.sarif}")
        _write_or_print(sbom_doc, args.output, "CycloneDX v1.5 SBOM")

    elif args.command == "batch-scan":
        if not os.path.isdir(args.dir):
            sys.exit(f"Error: Directory not found: {args.dir}")
        from reverse_forge.corpus_db import ArtifactKnowledgeBase, BatchCorpusScanner
        kb = ArtifactKnowledgeBase(args.db)
        scanner = BatchCorpusScanner(kb=kb)
        res = scanner.scan_directory(args.dir, max_files=args.max_files)
        _write_or_print(res, args.output, "Batch Corpus Scan")

    elif args.command == "db-query":
        _require_existing_file(args.db)
        from reverse_forge.corpus_db import ArtifactKnowledgeBase
        kb = ArtifactKnowledgeBase(args.db)
        matches = kb.query_findings(cwe_id=args.cwe, min_cvss=args.min_cvss)
        res = {
            "database": os.path.abspath(args.db),
            "filters": {"cwe": args.cwe, "min_cvss": args.min_cvss},
            "matches_count": len(matches),
            "findings": matches,
        }
        _write_or_print(res, args.output, "Knowledge Base Query")

    elif args.command == "posix-trace":
        from reverse_forge.posix_sandbox import POSIXSandboxEngine
        from reverse_forge.behavioral_engine import BehavioralTelemetryEngine
        if args.generate_runner:
            _require_existing_file(args.generate_runner)
            out_sh = POSIXSandboxEngine(args.generate_runner).generate_isolated_runner_script(args.output)
            print(f"[+] Isolated Linux/POSIX runner script generated: {out_sh}")
        else:
            b_engine = BehavioralTelemetryEngine()
            if args.strace_log:
                _require_existing_file(args.strace_log)
                with open(args.strace_log, "r", encoding="utf-8", errors="replace") as sf:
                    POSIXSandboxEngine.parse_strace_output(sf.read(), engine=b_engine)
            if args.gdb_log:
                _require_existing_file(args.gdb_log)
                with open(args.gdb_log, "r", encoding="utf-8", errors="replace") as gf:
                    POSIXSandboxEngine.parse_gdb_crash_output(gf.read(), engine=b_engine)
            out_json = POSIXSandboxEngine.export_telemetry_json(b_engine, args.output)
            print(f"[+] POSIX telemetry JSON exported: {out_json}")

    elif args.command == "doctor":
        import shutil
        import reverse_forge.smt_solver_engine  # Registers built-in Z3 BitVec engine if external z3-solver is absent
        from reverse_forge.ida_analyzer import IDAHeadlessAnalyzer
        tools = installer.detect_all()
        optional_mods = {}
        for mod_name in ("pefile", "capstone", "z3", "angr", "frida"):
            try:
                __import__(mod_name)
                optional_mods[mod_name] = True
            except ImportError:
                optional_mods[mod_name] = False

        internal_engines = [
            "PEAnalyzer", "ELFAnalyzer", "MachOAnalyzer", "LayerUnpacker",
            "WindowsEngine", "GhidraHeadlessAnalyzer", "IDAHeadlessAnalyzer",
            "CorrelationEngine", "DataFlowGraph", "SymbolicIREngine",
            "SMTSolverEngine", "CryptoSecretEngine", "SignatureEngine",
            "SemanticRecoveryEngine", "BinaryDiffEngine", "WindowsSandbox",
            "POSIXSandboxEngine", "FridaDBIEngine", "BehavioralTelemetryEngine",
            "PipelineStateMachine", "ReportGenerator", "DashboardGenerator",
            "SARIFExporter", "CycloneDXExporter", "ArtifactKnowledgeBase",
            "MicroDecompilerEngine", "PointerAliasEngine", "MicrocodeOptimizer",
            "ConcolicPathPruner", "FineGrainedTaintTracker", "UnifiedILLifter",
            "AntiInjectionGuard", "ZeroDayClusterEngine", "PatchVerifier",
            "DistributedCorpusClusteringEngine", "SSALifterAndOptimizer",
            "ControlFlowRegionStructurer", "DatalogVSAEngine",
            "DeobfuscationEngine", "CppRTTIEngine", "FirmwareBaseEngine",
            "UnwindFrameEngine", "TraceDiffEngine", "StreamingPEAnalyzer",
            "BinaryABBenchmarker", "GUIWorkbenchServer", "BinaryIntelEngine",
            "DesktopAppStudio", "ObfuscatedStringSolver", "CompilerPackerProfiler",
            "SyscallAndStructEngine", "BinaryPatcherEngine", "ProjectWorkspaceDB",
            "IndirectJumpTableResolver", "PDBSymbolEngine", "StructLayoutRecoveryEngine",
            "FLIRTRuntimeEngine", "GDBRSPClient", "VirtualizedCanvasEngine",
            "RecursiveDescentDisassembler", "GoRustReconstructor", "ForgeScriptingWorkspace",
            "UnifiedDecompilerPipeline", "BinaryVulnerabilityScannerEngine", "BytecodeManagedEngine", "DeterministicCPUEmulator", "ABIAndStackFrameEngine", "ConfigAndCryptoExtractorEngine", "ArchiveContainerTriageEngine", "YaraSigmaIOCGenerator", "Tier2BridgeExporter", "UnderConstrainedMicroVisor", "MultiDecompilerFusionEngine", "LiveMemoryAndDumpEngine", "NativeRustAccelerator", "OmniToolkit16CatEngine", "RustPcapNetzobEngine", "RustImHexPatternEngine", "RustGhidraCollapseStructurer", "RustDeobfuscationFlossMbaEngine", "RustSymbolsRttiGolangPdbEngine", "RustTaintVsaVulnEngine", "RustYaraSigmaBridgeEngine", "RustDeepElfMachoEhFrameEngine", "RustGhidraRuleActionTypeLattice", "Rust12StagePipelineSarifSbomEngine", "RustUpxDe4dotCapaRizinEngine",
        ]
        report = {
            "version": "26.0.0-rust-bicentennial",
            "phases_implemented": 120,
            "internal_engines_count": len(internal_engines),
            "internal_engines_status": "ALL_READY",
            "external_toolchains": {
                "radare2": tools["radare2"]["available"],
                "ghidra_headless": tools["ghidra"]["available"],
                "ida_headless": IDAHeadlessAnalyzer().is_available(),
                "objdump": tools["system_disassemblers"]["objdump"],
                "gdb": tools["system_disassemblers"]["gdb"],
                "strace": shutil.which("strace") is not None,
                "bubblewrap": shutil.which("bwrap") is not None,
            },
            "optional_python_bindings": optional_mods,
        }
        print(json.dumps(report, indent=2))

    elif args.command == "decompile":
        _require_existing_file(args.input)
        from reverse_forge.decompiler_engine import MicroDecompilerEngine
        with open(args.input, "rb") as f:
            data = f.read()
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        meta = (
            PEAnalyzer(data).analyze() if fmt == "PE"
            else (ELFAnalyzer(data).analyze() if fmt == "ELF"
                  else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {}))
        )
        code_slice, resolved_entry = CorrelationEngine._resolve_disassembly_slice(data, meta)
        base_addr = resolved_entry if resolved_entry else args.entry
        decompiler = MicroDecompilerEngine()
        res = decompiler.decompile_raw_bytes(code_slice, base_addr=base_addr)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(res.c_source)
            print(f"[+] Decompiled C code written to {args.output}")
        else:
            print(res.c_source)

    elif args.command == "alias-trace":
        _require_existing_file(args.input)
        from reverse_forge.pointer_alias_engine import PointerAliasEngine
        with open(args.input, "rb") as f:
            data = f.read()
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        meta = (
            ELFAnalyzer(data).analyze() if fmt == "ELF"
            else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {})
        )
        imported = [str(s).lstrip("_") for s in meta.get("imported_symbols", [])]
        pae = PointerAliasEngine()
        alloc_imports = sorted(set(imported) & pae.ALLOC_FUNCTIONS)
        free_imports = sorted(set(imported) & pae.FREE_FUNCTIONS)
        report = {
            "artifact": os.path.abspath(args.input),
            "detected_format": fmt,
            "allocator_imports": alloc_imports,
            "deallocator_imports": free_imports,
            "total_defects_found": len(pae.defects),
            "defects": [
                {
                    "type": d.defect_type,
                    "cwe": d.cwe,
                    "pointer": d.pointer_var,
                    "alloc_site": d.alloc_site,
                    "trigger_site": d.trigger_site,
                    "description": d.description,
                    "cvss_score": d.cvss_score,
                }
                for d in pae.defects
            ],
        }
        _write_or_print(report, args.output, "Pointer & Heap Alias Analysis")

    elif args.command == "uil-lift":
        from dataclasses import asdict
        from reverse_forge.unified_il_lifter import UnifiedILLifter
        lifter = UnifiedILLifter(target_arch=args.arch)
        parsed_insns = []
        for raw_stmt in args.asm.split(";"):
            stmt = raw_stmt.strip()
            if not stmt:
                continue
            parts = stmt.split(None, 1)
            mnem = parts[0]
            ops = [op.strip() for op in parts[1].split(",")] if len(parts) > 1 else []
            parsed_insns.append((mnem, ops))
        lifted = lifter.lift_block(parsed_insns)
        _write_or_print({"arch": args.arch, "instructions": [asdict(i) for i in lifted]}, args.output, "Unified IL Lift")

    elif args.command == "taint-trace":
        from dataclasses import asdict
        from reverse_forge.fine_grain_taint_engine import FineGrainedTaintTracker, TaintTag
        tracker = FineGrainedTaintTracker()
        tracker.mark_tainted(args.taint_reg, TaintTag.TAINTED_INPUT, "cli_taint_seed")
        parsed_insns = []
        for raw_stmt in args.asm.split(";"):
            stmt = raw_stmt.strip()
            if not stmt:
                continue
            parts = stmt.split(None, 1)
            mnem = parts[0]
            ops = [op.strip() for op in parts[1].split(",")] if len(parts) > 1 else []
            parsed_insns.append((mnem, ops))
        violations = tracker.analyze_linear_trace(parsed_insns)
        _write_or_print(
            {
                "active_taints": tracker.get_active_taints(),
                "violations_count": len(violations),
                "violations": [asdict(v) for v in violations],
            },
            args.output,
            "Fine-Grained Taint Trace",
        )

    elif args.command == "zeroday-scan":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.zeroday_cluster_engine import ZeroDayClusterEngine
        from reverse_forge.decompiler_engine import MicroDecompilerEngine
        with open(args.input, "rb") as f:
            data = f.read()
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        meta = (
            PEAnalyzer(data).analyze() if fmt == "PE"
            else (ELFAnalyzer(data).analyze() if fmt == "ELF"
                  else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {}))
        )
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, meta)
        dfunc = MicroDecompilerEngine().decompile_raw_bytes(code_slice, base_addr=entry_va or 0x401000)
        called = {str(s).lstrip("_") for s in meta.get("imported_symbols", [])}
        zd = ZeroDayClusterEngine(anomaly_threshold=args.threshold)
        vec = zd.extract_function_metrics("entry", dfunc.c_source.splitlines(), called_functions=called)
        cands = zd.analyze_functions({"entry": dfunc.c_source.splitlines()}, call_graph={"entry": called})
        _write_or_print(
            {
                "artifact": os.path.abspath(args.input),
                "entry_metrics": asdict(vec),
                "candidates": [asdict(c) for c in cands],
            },
            args.output,
            "Zero-Day Heuristic Scan",
        )

    elif args.command == "patch-verify":
        from dataclasses import asdict
        from reverse_forge.remediation_engine import RemediationEngine
        from reverse_forge.patch_verifier import PatchVerifier
        rem = RemediationEngine()
        patch = rem.generate_defensive_patch(f"VULN-{args.cwe}", args.cwe, args.symbol)
        report = PatchVerifier().verify_patch_resilience(patch, buffer_capacity=args.capacity)
        _write_or_print(asdict(report), args.output, "Defensive Patch Verification")

    elif args.command == "corpus-cluster":
        if not os.path.isdir(args.dir):
            sys.exit(f"Error: Directory not found: {args.dir}")
        from dataclasses import asdict
        from reverse_forge.distributed_corpus import DistributedCorpusClusteringEngine
        engine = DistributedCorpusClusteringEngine(max_workers=args.workers)
        report = engine.scan_and_cluster_directory(args.dir)
        _write_or_print(asdict(report), args.output, "Distributed Corpus Clustering")

    elif args.command == "ssa-optimize":
        from dataclasses import asdict
        from reverse_forge.unified_il_lifter import UnifiedILLifter
        from reverse_forge.ssa_lifter import SSABasicBlock, SSALifterAndOptimizer
        lifter = UnifiedILLifter(target_arch=args.arch)
        parsed_insns = []
        for raw_stmt in args.asm.split(";"):
            stmt = raw_stmt.strip()
            if not stmt:
                continue
            parts = stmt.split(None, 1)
            mnem = parts[0]
            ops = [op.strip() for op in parts[1].split(",")] if len(parts) > 1 else []
            parsed_insns.append((mnem, ops))
        uil_list = lifter.lift_block(parsed_insns)
        raw_blocks = {0: SSABasicBlock(block_id=0, instructions=uil_list)}
        opt_report = SSALifterAndOptimizer().optimize_ssa_blocks(raw_blocks, entry_id=0)
        _write_or_print(asdict(opt_report), args.output, "SSA Optimization Report")

    elif args.command == "structure-cfg":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.decompiler_engine import MicroDecompilerEngine
        with open(args.input, "rb") as f:
            data = f.read()
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        meta = (
            PEAnalyzer(data).analyze() if fmt == "PE"
            else (ELFAnalyzer(data).analyze() if fmt == "ELF"
                  else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {}))
        )
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, meta)
        base_va = entry_va or 0x401000
        decomp = MicroDecompilerEngine()
        dfunc = decomp.decompile_raw_bytes(code_slice, base_addr=base_va)
        insns = decomp._fallback_decode_x86(code_slice, base_va)
        struct_rep = decomp.decompile_structured(insns, func_name="entry_structured")
        _write_or_print(asdict(struct_rep), args.output, "Region-Structured Decompilation")

    elif args.command == "vsa-analyze":
        from dataclasses import asdict
        from reverse_forge.datalog_vsa_engine import DatalogVSAEngine
        insns = []
        addr = 0x401000
        for raw_stmt in args.asm.split(";"):
            stmt = raw_stmt.strip()
            if not stmt:
                continue
            parts = stmt.split(None, 1)
            mnem = parts[0]
            op_str = parts[1].strip() if len(parts) > 1 else ""
            insns.append((addr, mnem, op_str))
            addr += 4
        vsa_rep = DatalogVSAEngine().analyze_instruction_facts(insns)
        _write_or_print(asdict(vsa_rep), args.output, "Datalog & Value-Set Analysis")

    elif args.command == "deobfuscate-mba":
        from dataclasses import asdict
        from reverse_forge.deobfuscation_engine import DeobfuscationEngine
        res = DeobfuscationEngine().simplify_mba_expression(args.expr)
        _write_or_print(asdict(res), args.output, "MBA Algebraic Deobfuscation")

    elif args.command == "cpp-rtti":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.cpp_rtti_engine import CppRTTIEngine
        with open(args.input, "rb") as f:
            data = f.read()
        rep = CppRTTIEngine().analyze_binary_rtti(data)
        _write_or_print(asdict(rep), args.output, "C++ RTTI & VTable Reconstruction")

    elif args.command == "firmware-base":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.firmware_base_engine import FirmwareBaseEngine
        with open(args.input, "rb") as f:
            data = f.read()
        rep = FirmwareBaseEngine().scan_firmware_base(data)
        _write_or_print(asdict(rep), args.output, "Bare-Metal Firmware Base-Address Scan")

    elif args.command == "eh-frame":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.unwind_frame_engine import UnwindFrameEngine
        with open(args.input, "rb") as f:
            data = f.read()
        rep = UnwindFrameEngine().parse_eh_frame_bytes(data)
        _write_or_print(asdict(rep), args.output, "DWARF .eh_frame Unwind Recovery")

    elif args.command == "trace-diff":
        from dataclasses import asdict
        from reverse_forge.trace_diff_engine import TraceDiffEngine, TraceStep
        base_steps = [
            TraceStep(address=int(x.strip(), 16) if x.strip().startswith("0x") else int(x.strip(), 10))
            for x in args.base_addrs.split(",") if x.strip()
        ]
        div_steps = [
            TraceStep(address=int(x.strip(), 16) if x.strip().startswith("0x") else int(x.strip(), 10))
            for x in args.div_addrs.split(",") if x.strip()
        ]
        rep = TraceDiffEngine().align_and_diff_traces(base_steps, div_steps)
        _write_or_print(asdict(rep), args.output, "Differential Execution Trace Alignment")

    elif args.command == "streaming-triage":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.streaming_pe import StreamingPEAnalyzer
        rep = StreamingPEAnalyzer(args.input).analyze(include_hashes=True)
        _write_or_print(asdict(rep), args.output, "Streaming PE Triage")

    elif args.command == "ab-bench":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.ab_benchmarker import BinaryABBenchmarker
        bench = BinaryABBenchmarker(args.input, trials=args.trials, warmup_runs=args.warmup)
        print(f"[*] Executing A/B Statistical Benchmark on {args.input} (N={bench.trials} trials, warmup={bench.warmup_runs})...")
        rep = bench.run_experiment()
        rep_dict = asdict(rep)
        del rep_dict["summary_markdown"]

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(rep_dict, f, indent=2)
            print(f"[+] JSON A/B report saved to {args.output}")

        if args.output_md:
            with open(args.output_md, "w", encoding="utf-8") as f:
                f.write(rep.summary_markdown)
            print(f"[+] Markdown A/B report saved to {args.output_md}")

        if not args.output and not args.output_md:
            print("\n" + rep.summary_markdown)

    elif args.command == "gui":
        from reverse_forge.gui_server import start_gui_workbench
        start_gui_workbench(port=args.port, open_browser=(not args.no_browser), binary_path=args.input)

    elif args.command == "dossier":
        _require_existing_file(args.input)
        from reverse_forge.binary_intel_engine import BinaryIntelEngine
        with open(args.input, "rb") as f:
            data = f.read()
        dossier = BinaryIntelEngine(data, filepath=args.input).get_full_dossier()
        _write_or_print(dossier, args.output, "Binary Executive & Technical Dossier")

    elif args.command == "capabilities":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.binary_intel_engine import BinaryIntelEngine
        with open(args.input, "rb") as f:
            data = f.read()
        intel = BinaryIntelEngine(data, filepath=args.input)
        caps = [asdict(c) for c in intel.detect_capabilities()]
        _write_or_print({"artifact": os.path.abspath(args.input), "capabilities_count": len(caps), "capabilities": caps}, args.output, "CAPA Behavioral Capabilities")

    elif args.command == "xrefs":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.binary_intel_engine import BinaryIntelEngine
        with open(args.input, "rb") as f:
            data = f.read()
        intel = BinaryIntelEngine(data, filepath=args.input)
        xrefs = [asdict(x) for x in intel.extract_all_xrefs()]
        _write_or_print({"artifact": os.path.abspath(args.input), "xrefs_count": len(xrefs), "xrefs": xrefs}, args.output, "Cross-References Report")

    elif args.command == "inspect":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.binary_intel_engine import BinaryIntelEngine
        with open(args.input, "rb") as f:
            data = f.read()
        intel = BinaryIntelEngine(data, filepath=args.input)
        insp = intel.inspect_offset(args.offset)
        _write_or_print(asdict(insp), args.output, "14-Format Data Inspector")

    elif args.command == "ask":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.binary_intel_engine import BinaryIntelEngine
        with open(args.input, "rb") as f:
            data = f.read()
        intel = BinaryIntelEngine(data, filepath=args.input)
        ans = intel.smart_query(args.query)
        _write_or_print(asdict(ans), args.output, "Smart Binary Query")

    elif args.command == "desktop-app":
        from dataclasses import asdict
        from reverse_forge.desktop_app import build_desktop_workspace_model, launch_chromeless_app_window, launch_native_tk_ide
        if args.mode == "headless-json":
            model = build_desktop_workspace_model(args.input)
            _write_or_print(asdict(model), args.output, "Desktop Studio Workspace Model")
        elif args.mode == "app-window":
            if not launch_chromeless_app_window(args.input):
                launch_native_tk_ide(args.input)
        else:
            launch_native_tk_ide(args.input)

    elif args.command == "floss-strings":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.string_deobfuscator import ObfuscatedStringSolver
        with open(args.input, "rb") as f:
            data = f.read()
        rep = ObfuscatedStringSolver().deobfuscate_all_strings(data, min_len=args.min_len)
        _write_or_print(asdict(rep), args.output, "FLOSS Obfuscated & Stack String Recovery")

    elif args.command == "compiler-profile":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.binary_intel_engine import BinaryIntelEngine
        from reverse_forge.compiler_packer_profiler import CompilerPackerProfiler
        with open(args.input, "rb") as f:
            data = f.read()
        intel = BinaryIntelEngine(data, filepath=args.input)
        prof = CompilerPackerProfiler().profile_binary(
            data,
            sections=intel.metadata.get("sections", []),
            imported_symbols=intel.metadata.get("imported_symbols", []),
        )
        _write_or_print(asdict(prof), args.output, "Compiler, Packer, Rich Header & Imphash Profile")

    elif args.command == "syscall-scan":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.syscall_struct_engine import SyscallAndStructEngine
        with open(args.input, "rb") as f:
            data = f.read()
        sites = SyscallAndStructEngine().resolve_direct_syscalls(data, platform_hint=args.platform)
        _write_or_print({"artifact": os.path.abspath(args.input), "syscalls_count": len(sites), "syscalls": [asdict(s) for s in sites]}, args.output, "Direct Syscall ABI Scan")

    elif args.command == "struct-parse":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.syscall_struct_engine import SyscallAndStructEngine
        with open(args.input, "rb") as f:
            data = f.read()
        off_int = int(args.offset, 16) if args.offset.strip().lower().startswith("0x") else int(args.offset, 10)
        res = SyscallAndStructEngine().apply_c_struct_template(data, args.struct_def, base_offset=off_int)
        _write_or_print(asdict(res), args.output, "Kaitai/ImHex C-Struct Template Parse")

    elif args.command == "binary-patch":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.binary_patcher import BinaryPatcherEngine
        with open(args.input, "rb") as f:
            data = f.read()
        patcher = BinaryPatcherEngine(data)
        off_int = int(args.offset, 16) if args.offset.strip().lower().startswith("0x") else int(args.offset, 10)
        if args.action == "nop":
            patcher.nop_range(off_int, args.length)
        elif args.action == "invert-branch":
            patcher.invert_conditional_branch(off_int)
        elif args.action == "force-return":
            patcher.patch_function_return(off_int, return_value=args.ret_val)
        if args.save_binary:
            rep = patcher.save_patched_binary(args.save_binary)
        else:
            rep = patcher.get_patch_summary()
        _write_or_print(asdict(rep), args.output, "Binary Patch Transaction Summary")

    elif args.command == "project-export":
        from reverse_forge.project_workspace_db import ProjectWorkspaceDB
        proj = ProjectWorkspaceDB()
        for r_pair in args.rename:
            if "=" in r_pair:
                a_k, n_v = r_pair.split("=", 1)
                proj.rename_symbol(a_k, n_v)
        for c_pair in args.comment:
            if "=" in c_pair:
                a_k, c_v = c_pair.split("=", 1)
                proj.set_comment(a_k, c_v)
        if args.format == "c-header":
            out_txt = proj.export_c_header()
        elif args.format == "idapython":
            out_txt = proj.export_idapython_script()
        elif args.format == "ghidra":
            out_txt = proj.export_ghidra_script()
        else:
            out_txt = json.dumps(proj.to_dict(), indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_txt)
            print(f"[+] Exported {args.format} to {args.output}")
        else:
            print(out_txt)

    elif args.command == "jump-tables":
        from dataclasses import asdict
        from reverse_forge.jump_table_resolver import IndirectJumpTableResolver
        insns = []
        addr = 0x401000
        for raw_stmt in args.asm.split(";"):
            stmt = raw_stmt.strip()
            if not stmt:
                continue
            parts = stmt.split(None, 1)
            insns.append((addr, parts[0], parts[1].strip() if len(parts) > 1 else ""))
            addr += 4
        tables = IndirectJumpTableResolver().resolve_jump_tables_in_stream(insns)
        _write_or_print({"tables_resolved": len(tables), "tables": [asdict(t) for t in tables]}, args.output, "Indirect Jump Table Resolution")

    elif args.command == "pdb-parse":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.pdb_symbol_engine import PDBSymbolEngine
        with open(args.input, "rb") as f:
            data = f.read()
        eng = PDBSymbolEngine()
        if data.startswith(eng.MSF7_MAGIC):
            rep = asdict(eng.parse_pdb_bytes(data))
        else:
            rep = asdict(eng.extract_codeview_rsds(data))
        _write_or_print(rep, args.output, "Microsoft PDB & CodeView RSDS Analysis")

    elif args.command == "struct-infer":
        from dataclasses import asdict
        from reverse_forge.struct_recovery_engine import StructLayoutRecoveryEngine
        lines = [s.strip() for s in args.code.split(";") if s.strip()]
        structs, rewritten = StructLayoutRecoveryEngine().recover_structs_from_code(lines)
        _write_or_print({"structs_recovered": len(structs), "structs": [asdict(s) for s in structs], "rewritten_c": rewritten}, args.output, "Struct Layout Recovery")

    elif args.command == "flirt-scan":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.flirt_runtime_engine import FLIRTRuntimeEngine
        with open(args.input, "rb") as f:
            data = f.read()
        matches = FLIRTRuntimeEngine().scan_and_destrip(data)
        _write_or_print({"matches_count": len(matches), "matches": [asdict(m) for m in matches]}, args.output, "FLIRT Runtime Signature Scan")

    elif args.command == "gdb-debug":
        from dataclasses import asdict
        from reverse_forge.gdb_rsp_debugger import GDBRSPClient
        dbg = GDBRSPClient(host=args.host, port=args.port, simulated=args.simulated)
        dbg.connect()
        dbg.set_breakpoint(0x401004, "sw")
        snap = None
        for _ in range(max(1, args.steps)):
            snap = dbg.step_into()
        dbg.close()
        _write_or_print(asdict(snap), args.output, "GDB RSP Dynamic Debugger Snapshot")

    elif args.command == "canvas-cull":
        from reverse_forge.virtualized_canvas_engine import VirtualizedCanvasEngine, GraphNodeBox, ViewportBox
        vc = VirtualizedCanvasEngine()
        for i in range(args.nodes):
            vc.add_node(GraphNodeBox(i, f"sub_{0x401000 + i*16:x}", float((i % 20) * 320), float((i // 20) * 180), 260.0, 120.0, 0.4, ["push rbp", "ret"], []))
        frame = vc.render_viewport_frame(ViewportBox(0.0, 0.0, 1920.0, 1080.0, zoom_scale=args.zoom))
        _write_or_print(frame, args.output, "Virtualized Canvas Quadtree Viewport Frame")

    elif args.command == "recursive-disasm":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.recursive_disassembler import RecursiveDescentDisassembler
        with open(args.input, "rb") as f:
            data = f.read()
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        meta = (
            PEAnalyzer(data).analyze() if fmt == "PE"
            else (ELFAnalyzer(data).analyze() if fmt == "ELF"
                  else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {}))
        )
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, meta)
        base_va = entry_va or 0x401000
        ins_map = RecursiveDescentDisassembler(arch=args.arch).disassemble_recursive(code_slice[:4096], base_va=base_va)
        _write_or_print({"instructions_count": len(ins_map), "instructions": {hex(k): asdict(v) for k, v in ins_map.items()}}, args.output, "Recursive Descent Disassembly")

    elif args.command == "go-rust-recover":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.go_rust_reconstructor import GoRustReconstructor
        with open(args.input, "rb") as f:
            data = f.read()
        rec = GoRustReconstructor()
        go_rep = rec.parse_go_pclntab(data)
        rust_rep = rec.reconstruct_rust_metadata(data)
        _write_or_print({"go_pclntab": asdict(go_rep), "rust_metadata": asdict(rust_rep)}, args.output, "Go & Rust Semantic Reconstruction")

    elif args.command == "decompile-full":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.unified_decompiler_pipeline import UnifiedDecompilerPipeline
        with open(args.input, "rb") as f:
            data = f.read()
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        meta = (
            PEAnalyzer(data).analyze() if fmt == "PE"
            else (ELFAnalyzer(data).analyze() if fmt == "ELF"
                  else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {}))
        )
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, meta)
        res = UnifiedDecompilerPipeline(arch=args.arch).decompile_function_bytes(code_slice, base_va=entry_va or 0x401000)
        _write_or_print(asdict(res), args.output, "Unified 8-Pass Decompilation")

    elif args.command == "vuln-scan":
        _require_existing_file(args.input)
        from reverse_forge.binary_intel_engine import BinaryIntelEngine
        with open(args.input, "rb") as f:
            data = f.read()
        dos = BinaryIntelEngine(data, filepath=args.input).get_full_dossier()
        _write_or_print({
            "vulnerabilities_count": dos.get("vulnerabilities_count", 0),
            "risk_rating": dos.get("vulnerability_risk_rating", "CLEAN"),
            "vulnerabilities": dos.get("vulnerabilities", []),
        }, args.output, "Automated CWE Vulnerability Scan")

    elif args.command == "bytecode-audit":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.bytecode_clr_dex_wasm_engine import BytecodeManagedEngine
        with open(args.input, "rb") as f:
            data = f.read()
        rep = BytecodeManagedEngine().analyze_binary(data)
        _write_or_print(asdict(rep), args.output, "Multi-Runtime Bytecode & Managed Assembly Audit")

    elif args.command == "emulate-cpu":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.cpu_emulator_engine import DeterministicCPUEmulator
        with open(args.input, "rb") as f:
            data = f.read()
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        meta = (
            PEAnalyzer(data).analyze() if fmt == "PE"
            else (ELFAnalyzer(data).analyze() if fmt == "ELF"
                  else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {}))
        )
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, meta)
        rep = DeterministicCPUEmulator(base_va=entry_va or 0x401000).emulate_bytes(code_slice[:1024], max_steps=args.steps)
        _write_or_print(asdict(rep), args.output, "Deterministic CPU & API Stub Emulation")

    elif args.command == "abi-recover":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.abi_frame_recovery_engine import ABIAndStackFrameEngine
        from reverse_forge.recursive_disassembler import RecursiveDescentDisassembler
        with open(args.input, "rb") as f:
            data = f.read()
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        meta = (
            PEAnalyzer(data).analyze() if fmt == "PE"
            else (ELFAnalyzer(data).analyze() if fmt == "ELF"
                  else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {}))
        )
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, meta)
        base_va = entry_va or 0x401000
        dmap = RecursiveDescentDisassembler().disassemble_recursive(code_slice[:1024], base_va=base_va)
        ins_tuples = [(a, i.mnemonic, i.op_str) for a, i in sorted(dmap.items())]
        sig = ABIAndStackFrameEngine().recover_function_abi(ins_tuples, func_name="entry_main", os_format=fmt)
        _write_or_print(asdict(sig), args.output, "ABI Calling Convention & Stack-Frame Recovery")

    elif args.command == "extract-config":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.config_crypto_extractor import ConfigAndCryptoExtractorEngine
        with open(args.input, "rb") as f:
            data = f.read()
        rep = ConfigAndCryptoExtractorEngine().extract_all(data)
        _write_or_print(asdict(rep), args.output, "C2 Configuration, Custom Base64 & RC4 Extractor")

    elif args.command == "container-triage":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.archive_container_triage_engine import ArchiveContainerTriageEngine
        with open(args.input, "rb") as f:
            data = f.read()
        rep = ArchiveContainerTriageEngine().triage_container(data)
        _write_or_print(asdict(rep), args.output, "Multi-Container & Dropper Recursive Triage")

    elif args.command == "generate-yara":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.binary_intel_engine import BinaryIntelEngine
        from reverse_forge.yara_sigma_ioc_generator import YaraSigmaIOCGenerator
        with open(args.input, "rb") as f:
            data = f.read()
        intel = BinaryIntelEngine(data, filepath=args.input)
        code_slice, _ = CorrelationEngine._resolve_disassembly_slice(data, intel.metadata)
        bundle = YaraSigmaIOCGenerator().generate_all(data, intel.get_full_dossier(), code_slice=code_slice)
        _write_or_print(asdict(bundle), args.output, "Automated YARA, SIGMA & STIX 2.1 Threat-Intel Bundle")

    elif args.command == "export-bridge":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.binary_intel_engine import BinaryIntelEngine
        from reverse_forge.tier2_bridge_exporter import Tier2BridgeExporter
        with open(args.input, "rb") as f:
            data = f.read()
        intel = BinaryIntelEngine(data, filepath=args.input)
        pkg = Tier2BridgeExporter().export_bridge_package(intel.get_full_dossier())
        _write_or_print(asdict(pkg), args.output, "Layer-1 to Layer-2 Bridge Package (IDA/Ghidra/Binja/x64dbg)")

    elif args.command == "force-exec":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.underconstrained_visor_engine import UnderConstrainedMicroVisor
        with open(args.input, "rb") as f:
            data = f.read()
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        meta = (
            PEAnalyzer(data).analyze() if fmt == "PE"
            else (ELFAnalyzer(data).analyze() if fmt == "ELF"
                  else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {}))
        )
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, meta)
        rep = UnderConstrainedMicroVisor(base_va=entry_va or 0x401000).force_execute_function(code_slice[:1024], max_paths=args.paths)
        _write_or_print(asdict(rep), args.output, "Under-Constrained Force-Execution & Auto-Paging Visor")

    elif args.command == "decompile-fuse":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.multi_decompiler_fusion_engine import MultiDecompilerFusionEngine
        with open(args.input, "rb") as f:
            data = f.read()
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        meta = (
            PEAnalyzer(data).analyze() if fmt == "PE"
            else (ELFAnalyzer(data).analyze() if fmt == "ELF"
                  else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {}))
        )
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, meta)
        rep = MultiDecompilerFusionEngine().decompile_with_fusion(code_slice, base_va=entry_va or 0x401000)
        _write_or_print(asdict(rep), args.output, "Multi-Decompiler AST Fusion & Visor Verification")

    elif args.command == "memory-dump":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.live_memory_dump_engine import LiveMemoryAndDumpEngine
        with open(args.input, "rb") as f:
            data = f.read()
        rep = LiveMemoryAndDumpEngine().analyze_dump(data)
        _write_or_print(asdict(rep), args.output, "Memory Dump & In-Memory PE Forensics")

    elif args.command == "rust-bench":
        from dataclasses import asdict
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        rep = NativeRustAccelerator.benchmark_rust_vs_python(args.size)
        _write_or_print(asdict(rep), args.output, "Native Rust / C-ABI Zero-Copy Benchmark")

    elif args.command == "rust-decompile":
        _require_existing_file(args.input)
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        with open(args.input, "rb") as f:
            data = f.read()
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        meta = (
            PEAnalyzer(data).analyze() if fmt == "PE"
            else (ELFAnalyzer(data).analyze() if fmt == "ELF"
                  else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {}))
        )
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, meta)
        c_out = NativeRustAccelerator.native_ghidra_pcode_decompile(code_slice[:512], base_va=entry_va or 0x401000)
        v_out = NativeRustAccelerator.native_visor_exec(code_slice[:512], base_va=entry_va or 0x401000)
        _write_or_print({"pcode_decompiled_c": c_out, "visor_execution": v_out}, args.output, "Native Rust Ghidra P-Code Decompilation")

    elif args.command == "pcap-dissect":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.omni_toolkit_16cat import OmniToolkit16CatEngine
        with open(args.input, "rb") as f:
            data = f.read()
        rep = OmniToolkit16CatEngine().dissect_pcap_and_infer_protocol(data)
        _write_or_print(asdict(rep), args.output, "PCAP Dissection & Netzob Protocol Grammar")

    elif args.command == "imhex-eval":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.omni_toolkit_16cat import OmniToolkit16CatEngine
        with open(args.input, "rb") as f:
            data = f.read()
        fields = OmniToolkit16CatEngine().evaluate_imhex_pattern(data, args.pattern, args.offset)
        _write_or_print({"fields_count": len(fields), "fields": [asdict(x) for x in fields]}, args.output, "ImHex Struct Pattern Evaluation")

    elif args.command == "jvm-decompile":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.omni_toolkit_16cat import OmniToolkit16CatEngine
        with open(args.input, "rb") as f:
            data = f.read()
        rep = OmniToolkit16CatEngine().decompile_jvm_class(data)
        _write_or_print(asdict(rep), args.output, "JVM .class Constant-Pool Decompilation")

    elif args.command == "binwalk-carve":
        _require_existing_file(args.input)
        from dataclasses import asdict
        from reverse_forge.omni_toolkit_16cat import OmniToolkit16CatEngine
        with open(args.input, "rb") as f:
            data = f.read()
        hits = OmniToolkit16CatEngine().carve_firmware_partitions(data)
        _write_or_print({"partitions_count": len(hits), "partitions": [asdict(x) for x in hits]}, args.output, "Binwalk Firmware Partition Carving")


if __name__ == "__main__":
    main()
