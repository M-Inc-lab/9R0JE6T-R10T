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


if __name__ == "__main__":
    main()
