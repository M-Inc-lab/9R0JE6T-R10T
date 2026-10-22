"""
R3V3R53//F0RG3 — Headless IDA Pro & Multi-Decompiler Consensus Engine (§02.2, §02.4)
Orchestrates IDA Pro ('idat' / 'idat64') in batch mode, extracts Hex-Rays pseudocode and FLIRT symbols,
and computes multi-decompiler consensus across IDA Pro, Ghidra, and Radare2.
"""

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

IDA_BATCH_SCRIPT = r"""# -*- coding: utf-8 -*-
# R3V3R53//F0RG3 Headless IDAPython Export Script (IDA 7.x / 8.x / 9.x)
import json
import os
import idaapi
import idautils
import idc

def export_ida_analysis():
    idaapi.auto_wait()
    out_path = os.environ.get("RF_IDA_OUTPUT_JSON", "ida_export.json")

    functions = []
    decompiled = []
    has_hexrays = False
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            has_hexrays = True
    except Exception:
        has_hexrays = False

    for ea in idautils.Functions():
        fname = idc.get_func_name(ea)
        flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
        is_lib = bool(flags & idc.FUNC_LIB)
        is_thunk = bool(flags & idc.FUNC_THUNK)
        end_ea = idc.get_func_attr(ea, idc.FUNCATTR_END)
        size = max(0, end_ea - ea)

        if len(functions) < 500:
            functions.append({
                "name": fname,
                "entry": hex(ea),
                "size": size,
                "is_library_flirt": is_lib,
                "is_thunk": is_thunk,
            })

        if has_hexrays and not is_lib and not is_thunk and len(decompiled) < 15:
            try:
                cfunc = idaapi.decompile(ea)
                if cfunc:
                    decompiled.append({
                        "function": fname,
                        "entry": hex(ea),
                        "pseudocode": str(cfunc)[:4000],
                    })
            except Exception:
                pass

    payload = {
        "processor": idaapi.get_inf_structure().procname if hasattr(idaapi, "get_inf_structure") else "unknown",
        "hexrays_available": has_hexrays,
        "functions_total": len(functions),
        "flirt_library_functions": sum(1 for f in functions if f["is_library_flirt"]),
        "functions": functions,
        "decompiled_functions": decompiled,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

export_ida_analysis()
idc.qexit(0)
"""


class IDAHeadlessAnalyzer:
    """Headless IDA Pro ('idat64' / 'idat') orchestrator and multi-decompiler consensus engine."""

    def __init__(self, ida_headless_path: Optional[str] = None):
        self.ida_bin = (
            ida_headless_path
            or os.environ.get("IDA_HEADLESS_PATH")
            or shutil.which("idat64")
            or shutil.which("idat")
        )

    def is_available(self) -> bool:
        return bool(self.ida_bin and os.path.exists(self.ida_bin))

    def analyze(self, filepath: str, timeout: int = 120) -> Dict[str, Any]:
        abs_target = os.path.abspath(filepath)
        if not os.path.exists(abs_target):
            raise FileNotFoundError(f"Artifact not found: {abs_target}")

        if not self.is_available():
            return {
                "status": "skipped",
                "reason": "IDA Pro headless binary (idat64/idat) not found in PATH or IDA_HEADLESS_PATH",
            }

        assert self.ida_bin is not None
        with tempfile.TemporaryDirectory(prefix="rf_ida_") as tmpdir:
            script_path = os.path.join(tmpdir, "rf_ida_export.py")
            out_json = os.path.join(tmpdir, "ida_export.json")
            work_target = os.path.join(tmpdir, os.path.basename(abs_target))
            shutil.copy2(abs_target, work_target)

            with open(script_path, "w", encoding="utf-8") as sf:
                sf.write(IDA_BATCH_SCRIPT)

            env = os.environ.copy()
            env["RF_IDA_OUTPUT_JSON"] = out_json
            cmd = [self.ida_bin, "-A", f"-S{script_path}", work_target]

            try:
                proc = subprocess.run(
                    cmd,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env,
                )
                if os.path.exists(out_json):
                    with open(out_json, "r", encoding="utf-8") as jf:
                        data = json.load(jf)
                    return {
                        "status": "success",
                        "headless_binary": self.ida_bin,
                        "returncode": proc.returncode,
                        "analysis": data,
                    }
                return {
                    "status": "error",
                    "headless_binary": self.ida_bin,
                    "returncode": proc.returncode,
                    "stderr": proc.stderr[-2000:] if proc.stderr else "No export JSON generated",
                }
            except Exception as exc:
                return {"status": "error", "headless_binary": self.ida_bin, "exception": str(exc)}

    @staticmethod
    def compute_decompiler_consensus(
        ghidra_res: Dict[str, Any],
        ida_res: Dict[str, Any],
        r2_res: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Cross-validate functions and decompiled pseudocode across Ghidra, IDA Pro, and Radare2."""
        g_funcs = {
            f.get("entry", "").lower().lstrip("0x"): f.get("name")
            for f in ghidra_res.get("analysis", {}).get("functions", [])
            if f.get("entry")
        }
        i_funcs = {
            f.get("entry", "").lower().replace("0x", "").lstrip("0"): f.get("name")
            for f in ida_res.get("analysis", {}).get("functions", [])
            if f.get("entry")
        }
        r_funcs = {
            hex(f.get("offset", 0)).replace("0x", "").lstrip("0"): f.get("name")
            for f in r2_res.get("functions_sample", [])
            if isinstance(f, dict) and "offset" in f
        }

        normalize_g = {k.lstrip("0") or "0": v for k, v in g_funcs.items()}
        normalize_i = {k or "0": v for k, v in i_funcs.items()}
        normalize_r = {k or "0": v for k, v in r_funcs.items()}

        all_addrs = set(normalize_g.keys()) | set(normalize_i.keys()) | set(normalize_r.keys())
        agreed_addrs = []
        divergent_addrs = []

        for addr in sorted(all_addrs):
            engines_present = []
            if addr in normalize_g:
                engines_present.append("Ghidra")
            if addr in normalize_i:
                engines_present.append("IDA")
            if addr in normalize_r:
                engines_present.append("Radare2")
            if len(engines_present) >= 2:
                agreed_addrs.append({"entry_offset": f"0x{addr}", "confirmed_by": engines_present})
            else:
                divergent_addrs.append({"entry_offset": f"0x{addr}", "only_in": engines_present})

        return {
            "total_unique_functions": len(all_addrs),
            "multi_engine_confirmed_count": len(agreed_addrs),
            "single_engine_divergent_count": len(divergent_addrs),
            "confirmed_functions": agreed_addrs[:50],
            "divergent_functions": divergent_addrs[:50],
        }
