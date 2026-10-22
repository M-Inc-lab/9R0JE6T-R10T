import argparse
import hashlib
import json
import os
import re
import sys
from typing import Dict, Any, List

from reverse_forge.pe_analyzer import PEAnalyzer
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.macho_analyzer import MachOAnalyzer
from reverse_forge.tool_installer import ToolchainInstaller
from reverse_forge.correlation_engine import CorrelationEngine

def hash_file(filepath: str) -> Dict[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}

def extract_strings(filepath: str, min_len: int = 5) -> Dict[str, List[str]]:
    with open(filepath, "rb") as f:
        data = f.read()

    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
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

def main():
    parser = argparse.ArgumentParser(description="R3V3R53//F0RG3 Autonomous Multi-Tool Cross-Platform Reverse Engineering Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # detect-tools
    subparsers.add_parser("detect-tools", help="Discover local/managed reverse engineering toolchain")

    # bootstrap
    boot_p = subparsers.add_parser("bootstrap", help="Automatically download and install required analysis tools")
    boot_p.add_argument("--tool", choices=["r2", "capstone", "all"], default="all", help="Tool to provision")

    # inspect / triage
    triage_p = subparsers.add_parser("triage", help="Perform cross-platform format triage (PE, ELF, Mach-O)")
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
        if not os.path.exists(args.input):
            sys.exit(f"Error: Artifact not found: {args.input}")
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
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=2)
            print(f"Success: Triage analysis written to {args.output}")
        else:
            print(json.dumps(res, indent=2))

    elif args.command == "correlate":
        engine = CorrelationEngine()
        res = engine.analyze_artifact(args.input)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=2)
            print(f"Success: Correlated analysis written to {args.output}")
        else:
            print(json.dumps(res, indent=2))

    elif args.command == "strings":
        res = extract_strings(args.input, min_len=args.min_len)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=2)
            print(f"Success: Strings extracted to {args.output}")
        else:
            print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
