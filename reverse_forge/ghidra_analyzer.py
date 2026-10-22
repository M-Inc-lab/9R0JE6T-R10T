import json
import os
import subprocess
import tempfile
from typing import Dict, Any, List, Optional

from reverse_forge.tool_installer import ToolchainInstaller

GHIDRA_POST_SCRIPT = r'''# -*- coding: utf-8 -*-
# R3V3R53//F0RG3 Headless Ghidra Export Script (Jython / PyGhidra compatible)
# @category ReverseForge
import json
import sys

DANGEROUS_SINKS = set([
    "strcpy", "_strcpy", "strcat", "_strcat", "sprintf", "_sprintf",
    "vsprintf", "_vsprintf", "gets", "_gets", "scanf", "_scanf",
    "system", "_system", "popen", "_popen", "execve", "_execve",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "NtMapViewOfSection",
    "dlopen", "_dlopen", "LoadLibraryA", "LoadLibraryW", "GetProcAddress"
])

def run_export():
    args = getScriptArgs()
    if not args or len(args) < 1:
        print("[-] Missing output JSON path argument")
        return

    out_path = args[0]
    prog = currentProgram
    fm = prog.getFunctionManager()
    rm = prog.getReferenceManager()
    sym_tab = prog.getSymbolTable()

    functions_list = []
    sink_xrefs = []
    candidate_decompile_funcs = []

    funcs_iter = fm.getFunctions(True)
    for func in funcs_iter:
        fname = func.getName()
        entry_str = str(func.getEntryPoint())
        is_thunk = bool(func.isThunk())
        is_ext = bool(func.isExternal())
        size_bytes = int(func.getBody().getNumAddresses()) if func.getBody() else 0

        if len(functions_list) < 250:
            functions_list.append({
                "name": fname,
                "entry": entry_str,
                "size": size_bytes,
                "is_thunk": is_thunk,
                "is_external": is_ext,
                "calling_convention": str(func.getCallingConventionName())
            })

        clean_name = fname.lstrip("_")
        if fname in DANGEROUS_SINKS or clean_name in DANGEROUS_SINKS:
            refs = rm.getReferencesTo(func.getEntryPoint())
            for ref in refs:
                from_addr = ref.getFromAddress()
                caller = fm.getFunctionContaining(from_addr)
                caller_name = caller.getName() if caller else "unknown"
                sink_xrefs.append({
                    "sink": fname,
                    "sink_address": entry_str,
                    "call_site": str(from_addr),
                    "caller_function": caller_name,
                    "caller_entry": str(caller.getEntryPoint()) if caller else None
                })
                if caller and caller not in candidate_decompile_funcs and len(candidate_decompile_funcs) < 10:
                    candidate_decompile_funcs.append(caller)

        if fname in ("main", "_main", "entry", "_start", "WinMain", "wWinMain", "DllMain"):
            if func not in candidate_decompile_funcs and len(candidate_decompile_funcs) < 10:
                candidate_decompile_funcs.append(func)

    decompiled_samples = []
    try:
        from ghidra.app.decompiler import DecompInterface
        decomp = DecompInterface()
        decomp.openProgram(prog)
        for target_fn in candidate_decompile_funcs[:10]:
            res = decomp.decompileFunction(target_fn, 15, monitor)
            if res and res.decompileCompleted():
                c_code = res.getDecompiledFunction().getC()
                decompiled_samples.append({
                    "function": target_fn.getName(),
                    "entry": str(target_fn.getEntryPoint()),
                    "pseudocode": c_code[:4000]
                })
        decomp.dispose()
    except Exception as e:
        pass

    payload = {
        "program_name": str(prog.getName()),
        "executable_format": str(prog.getExecutableFormat()),
        "language_id": str(prog.getLanguageID()),
        "compiler_spec": str(prog.getCompilerSpec().getCompilerSpecID()),
        "image_base": str(prog.getImageBase()),
        "functions_total": fm.getFunctionCount(),
        "functions": functions_list,
        "dangerous_sink_xrefs": sink_xrefs,
        "decompiled_functions": decompiled_samples
    }

    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)

run_export()
'''


class GhidraHeadlessAnalyzer:
    """Headless Ghidra ('analyzeHeadless') orchestrator for function, xref, and decompilation recovery."""

    def __init__(self, ghidra_headless_path: Optional[str] = None):
        self.installer = ToolchainInstaller()
        self.ghidra_bin = ghidra_headless_path or os.environ.get("GHIDRA_HEADLESS_PATH")
        if not self.ghidra_bin:
            ghidra_info = self.installer.detect_all().get("ghidra", {})
            if ghidra_info.get("available") and ghidra_info.get("path"):
                self.ghidra_bin = ghidra_info["path"]

    def is_available(self) -> bool:
        return bool(self.ghidra_bin and os.path.exists(self.ghidra_bin))

    def analyze(self, filepath: str, timeout: int = 120) -> Dict[str, Any]:
        """Run headless Ghidra import, auto-analysis, and structured JSON export."""
        abs_target = os.path.abspath(filepath)
        if not os.path.exists(abs_target):
            raise FileNotFoundError(f"Artifact not found: {abs_target}")

        if not self.is_available():
            return {
                "status": "skipped",
                "reason": "Ghidra analyzeHeadless binary not found in PATH, GHIDRA_HEADLESS_PATH, or managed bin/"
            }

        assert self.ghidra_bin is not None
        with tempfile.TemporaryDirectory(prefix="rf_ghidra_") as tmpdir:
            proj_dir = os.path.join(tmpdir, "project")
            script_dir = os.path.join(tmpdir, "scripts")
            out_json = os.path.join(tmpdir, "ghidra_export.json")
            os.makedirs(proj_dir, exist_ok=True)
            os.makedirs(script_dir, exist_ok=True)

            script_path = os.path.join(script_dir, "rf_ghidra_export.py")
            with open(script_path, "w", encoding="utf-8") as sf:
                sf.write(GHIDRA_POST_SCRIPT)

            cmd = [
                self.ghidra_bin,
                proj_dir,
                "RFTempProject",
                "-import",
                abs_target,
                "-scriptPath",
                script_dir,
                "-postScript",
                "rf_ghidra_export.py",
                out_json,
                "-deleteProject",
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                if os.path.exists(out_json):
                    with open(out_json, "r", encoding="utf-8") as jf:
                        export_data = json.load(jf)
                    sink_map: Dict[str, List[str]] = {}
                    for item in export_data.get("dangerous_sink_xrefs", []):
                        s_name = item.get("sink", "").lstrip("_")
                        caller = item.get("caller_function") or "unknown"
                        if s_name:
                            sink_map.setdefault(s_name, []).append(caller)
                    return {
                        "status": "success",
                        "headless_binary": self.ghidra_bin,
                        "returncode": proc.returncode,
                        "analysis": export_data,
                        "sink_xrefs": sink_map,
                        "decompiled_functions": export_data.get("decompiled_functions", []),
                    }
                return {
                    "status": "error",
                    "headless_binary": self.ghidra_bin,
                    "returncode": proc.returncode,
                    "stderr": proc.stderr[-2000:] if proc.stderr else "No export JSON generated",
                }
            except subprocess.TimeoutExpired:
                return {
                    "status": "timeout",
                    "headless_binary": self.ghidra_bin,
                    "reason": f"Ghidra headless analysis exceeded {timeout}s timeout",
                }
            except Exception as exc:
                return {
                    "status": "error",
                    "headless_binary": self.ghidra_bin,
                    "exception": str(exc),
                }
