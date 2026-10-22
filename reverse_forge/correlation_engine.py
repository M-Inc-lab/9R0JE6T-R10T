import json
import os
import subprocess
from typing import Dict, Any, List, Optional

from reverse_forge.pe_analyzer import PEAnalyzer
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.macho_analyzer import MachOAnalyzer
from reverse_forge.tool_installer import ToolchainInstaller

class CorrelationEngine:
    """Multi-tool orchestrator combining format parsers, radare2, and capstone disassembly."""

    def __init__(self):
        self.installer = ToolchainInstaller()

    def identify_format(self, data: bytes) -> str:
        if len(data) >= 2 and data[:2] == b"MZ":
            return "PE"
        if len(data) >= 4 and data[:4] == b"\x7fELF":
            return "ELF"
        if len(data) >= 4:
            import struct
            magic = struct.unpack_from(">I", data, 0)[0]
            if magic in (0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA):
                return "Mach-O"
        return "Unknown"

    def analyze_artifact(self, filepath: str) -> Dict[str, Any]:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Artifact not found: {filepath}")

        with open(filepath, "rb") as f:
            data = f.read()

        fmt = self.identify_format(data)
        format_info: Dict[str, Any] = {}

        if fmt == "PE":
            format_info = PEAnalyzer(data).analyze()
        elif fmt == "ELF":
            format_info = ELFAnalyzer(data).analyze()
        elif fmt == "Mach-O":
            format_info = MachOAnalyzer(data).analyze()
        else:
            format_info = {
                "format": "Unknown/Raw Binary",
                "entropy": PEAnalyzer.calculate_entropy(data)
            }

        # Run multi-tool combinational inspection
        r2_info = self._run_r2_analysis(filepath)
        capstone_info = self._run_capstone_disassembly(data, format_info)

        # Cross-correlate findings
        correlation = self._correlate_results(format_info, r2_info, capstone_info)

        return {
            "artifact": os.path.abspath(filepath),
            "detected_format": fmt,
            "structural_analysis": format_info,
            "tool_radare2": r2_info,
            "tool_capstone": capstone_info,
            "correlation_summary": correlation
        }

    def _run_r2_analysis(self, filepath: str) -> Dict[str, Any]:
        """Execute radare2 in JSON batch mode if present."""
        tools = self.installer.detect_all()
        r2_meta = tools.get("radare2", {})

        if not r2_meta.get("available") or not r2_meta.get("path"):
            return {"status": "skipped", "reason": "Radare2 not available"}

        r2_bin = r2_meta["path"]
        try:
            # -q = quiet, -c "iIj; aflj" = get binary info JSON and function list JSON
            cmd = [r2_bin, "-q", "-c", "iIj; aflj", filepath]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if proc.returncode == 0:
                raw_out = proc.stdout.strip().split("\n")
                info_json = {}
                funcs_json = []
                for line in raw_out:
                    try:
                        parsed = json.loads(line)
                        if isinstance(parsed, dict) and "arch" in parsed:
                            info_json = parsed
                        elif isinstance(parsed, list):
                            funcs_json = parsed
                    except Exception:
                        continue
                return {
                    "status": "success",
                    "binary_info": info_json,
                    "functions_count": len(funcs_json),
                    "functions_sample": funcs_json[:10]
                }
            else:
                return {"status": "error", "stderr": proc.stderr}
        except Exception as e:
            return {"status": "error", "exception": str(e)}

    def _run_capstone_disassembly(self, data: bytes, format_info: Dict[str, Any]) -> Dict[str, Any]:
        """Disassemble entry point bytes via Capstone if available."""
        try:
            import capstone
        except ImportError:
            return {"status": "skipped", "reason": "Capstone library not installed"}

        arch_str = format_info.get("architecture", "")
        entry_hex = format_info.get("entry_point", "0")
        try:
            entry_int = int(entry_hex, 16) if isinstance(entry_hex, str) else int(entry_hex)
        except Exception:
            entry_int = 0

        # Map architecture to capstone mode
        cs_arch = capstone.CS_ARCH_X86
        cs_mode = capstone.CS_MODE_64 if ("64" in arch_str or "AMD64" in arch_str) else capstone.CS_MODE_32

        if "ARM64" in arch_str or "AArch64" in arch_str:
            cs_arch = capstone.CS_ARCH_ARM64
            cs_mode = capstone.CS_MODE_ARM
        elif "ARM" in arch_str:
            cs_arch = capstone.CS_ARCH_ARM
            cs_mode = capstone.CS_MODE_ARM

        try:
            md = capstone.Cs(cs_arch, cs_mode)
            # Find candidate code bytes (around entry offset or beginning of executable section)
            sample_bytes = data[:512]
            for sec in format_info.get("sections", []):
                if sec.get("executable") and "raw_offset" in sec:
                    try:
                        off = int(sec["raw_offset"], 16) if isinstance(sec["raw_offset"], str) else sec["raw_offset"]
                        if off < len(data):
                            sample_bytes = data[off:off + 64]
                            break
                    except Exception:
                        pass

            instructions = []
            for instr in md.disasm(sample_bytes, entry_int):
                instructions.append(f"0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
                if len(instructions) >= 15:
                    break

            return {
                "status": "success",
                "disassembled_instructions": instructions
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _correlate_results(self, fmt_info: Dict[str, Any], r2_info: Dict[str, Any], cs_info: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate independently acquired tool outputs."""
        evidence = []
        conflicts = []

        arch_primary = fmt_info.get("architecture", "Unknown")
        r2_arch = r2_info.get("binary_info", {}).get("arch", None)

        if r2_arch:
            if r2_arch.lower() in arch_primary.lower() or arch_primary.lower() in r2_arch.lower():
                evidence.append(f"Architecture confirmed independently by Native Parser and Radare2: {arch_primary}")
            else:
                conflicts.append(f"Architecture mismatch: Native={arch_primary} vs Radare2={r2_arch}")
        else:
            evidence.append(f"Architecture inferred by Native Parser: {arch_primary}")

        entropy = fmt_info.get("entropy", 0.0)
        packed = entropy > 7.1

        confidence = "HIGH" if (len(evidence) > 1 and len(conflicts) == 0) else "MEDIUM"

        return {
            "evidence": evidence,
            "conflicts": conflicts,
            "is_likely_packed": packed,
            "overall_confidence": confidence
        }
