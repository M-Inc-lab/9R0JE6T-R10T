import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from typing import Dict, Any, List

from reverse_forge.pe_analyzer import PEAnalyzer

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

def detect_tools() -> Dict[str, Any]:
    tools = {
        "ghidra": shutil.which("analyzeHeadless") or shutil.which("ghidra"),
        "radare2": shutil.which("r2") or shutil.which("radare2"),
        "ida_pro": shutil.which("ida64") or shutil.which("idat64"),
        "cutter": shutil.which("cutter"),
        "dumpbin": shutil.which("dumpbin"),
        "sigcheck": shutil.which("sigcheck") or shutil.which("sigcheck64"),
        "powershell": shutil.which("pwsh") or shutil.which("powershell"),
        "gdb": shutil.which("gdb"),
        "python": sys.executable
    }
    return {k: {"available": bool(v), "path": v} for k, v in tools.items()}

def triage_binary(filepath: str) -> Dict[str, Any]:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Artifact not found: {filepath}")

    size = os.path.getsize(filepath)
    hashes = hash_file(filepath)

    with open(filepath, "rb") as f:
        content = f.read()

    pe_info = PEAnalyzer(content).analyze()

    is_high_entropy = pe_info.get("entropy", 0.0) > 7.0
    pack_indicator = "Potential Packer / Compression detected (Entropy > 7.0)" if is_high_entropy else "Standard entropy"

    return {
        "artifact": os.path.abspath(filepath),
        "filename": os.path.basename(filepath),
        "size_bytes": size,
        "hashes": hashes,
        "pe_metadata": pe_info,
        "heuristic_pack_check": pack_indicator,
        "tools_status": detect_tools()
    }

def main():
    parser = argparse.ArgumentParser(description="R3V3R53//F0RG3 Autonomous Triage & Reverse Engineering Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # detect-tools
    subparsers.add_parser("detect-tools", help="Discover local reverse engineering toolchain")

    # triage
    triage_p = subparsers.add_parser("triage", help="Perform Stage 0-3 static triage on an artifact")
    triage_p.add_argument("--input", "-i", required=True, help="Target binary artifact path")
    triage_p.add_argument("--output", "-o", help="Path to write JSON results")

    # strings
    str_p = subparsers.add_parser("strings", help="Extract and categorize strings from binary")
    str_p.add_argument("--input", "-i", required=True, help="Target binary artifact path")
    str_p.add_argument("--output", "-o", help="Path to write JSON results")
    str_p.add_argument("--min-len", type=int, default=5, help="Minimum string length")

    args = parser.parse_args()

    if args.command == "detect-tools":
        results = detect_tools()
        print(json.dumps(results, indent=2))

    elif args.command == "triage":
        res = triage_binary(args.input)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=2)
            print(f"Success: Triage analysis written to {args.output}")
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
