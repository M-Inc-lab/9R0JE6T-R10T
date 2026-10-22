import json
import os
import struct
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
            magic = struct.unpack_from(">I", data, 0)[0]
            if magic in (0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE):
                return "Mach-O"
            if magic in (0xCAFEBABE, 0xBEBAFECA):
                if MachOAnalyzer.is_fat_macho(data):
                    return "Mach-O"
                if magic == 0xCAFEBABE and len(data) >= 8:
                    _, major_ver = struct.unpack_from(">HH", data, 4)
                    if 45 <= major_ver <= 75:
                        return "JVM Class"
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
        elif fmt == "JVM Class":
            minor_ver, major_ver = struct.unpack_from(">HH", data, 4)
            format_info = {
                "format": "JVM Class Bytecode",
                "architecture": "JVM",
                "class_version": f"{major_ver}.{minor_ver}",
                "entropy": PEAnalyzer.calculate_entropy(data),
            }
        else:
            format_info = {
                "format": "Unknown/Raw Binary",
                "entropy": PEAnalyzer.calculate_entropy(data)
            }

        r2_info = self._run_r2_analysis(filepath)
        capstone_info = self._run_capstone_disassembly(data, format_info)
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
        """Execute radare2 in JSON batch mode with function analysis ('aa; iIj; aflj')."""
        tools = self.installer.detect_all()
        r2_meta = tools.get("radare2", {})

        if not r2_meta.get("available") or not r2_meta.get("path"):
            return {"status": "skipped", "reason": "Radare2 not available"}

        r2_bin = r2_meta["path"]
        try:
            cmd = [r2_bin, "-q", "-c", "aa; iIj; aflj", filepath]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
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
            return {"status": "error", "stderr": proc.stderr}
        except Exception as e:
            return {"status": "error", "exception": str(e)}

    @staticmethod
    def _resolve_disassembly_slice(data: bytes, format_info: Dict[str, Any]) -> tuple[bytes, int]:
        """Resolve the accurate file offset and virtual address for entry-point disassembly."""
        entry_hex = format_info.get("entry_point", 0)
        try:
            entry_va = int(entry_hex, 16) if isinstance(entry_hex, str) else int(entry_hex)
        except Exception:
            entry_va = 0

        entry_file_off_raw = format_info.get("entry_file_offset")
        if entry_file_off_raw is not None:
            try:
                off = int(entry_file_off_raw, 16) if isinstance(entry_file_off_raw, str) else int(entry_file_off_raw)
                if 0 <= off < len(data):
                    return data[off:off + 64], entry_va
            except Exception:
                pass

        for sec in format_info.get("sections", []):
            if not sec.get("executable"):
                continue
            off_val = sec.get("raw_offset") or sec.get("offset")
            vaddr_val = sec.get("virtual_address") or sec.get("address")
            size_val = sec.get("raw_size") or sec.get("size") or 0
            try:
                sec_off = int(off_val, 16) if isinstance(off_val, str) else int(off_val)
                sec_va = int(vaddr_val, 16) if isinstance(vaddr_val, str) else int(vaddr_val or 0)
                sec_sz = int(size_val)
                if entry_va > 0 and sec_sz > 0 and sec_va <= entry_va < sec_va + sec_sz:
                    mapped = sec_off + (entry_va - sec_va)
                    if 0 <= mapped < len(data):
                        return data[mapped:mapped + 64], entry_va
                if 0 <= sec_off < len(data):
                    return data[sec_off:sec_off + 64], (sec_va or entry_va)
            except Exception:
                continue

        return data[:64], entry_va

    def _run_capstone_disassembly(self, data: bytes, format_info: Dict[str, Any]) -> Dict[str, Any]:
        """Disassemble entry point bytes via Capstone if available."""
        try:
            import capstone
        except ImportError:
            return {"status": "skipped", "reason": "Capstone library not installed"}

        arch_str = format_info.get("architecture", "")
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
            sample_bytes, disasm_addr = self._resolve_disassembly_slice(data, format_info)

            instructions = []
            for instr in md.disasm(sample_bytes, disasm_addr):
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
