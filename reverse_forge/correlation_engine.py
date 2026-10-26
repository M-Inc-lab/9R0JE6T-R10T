import json
import os
import struct
import subprocess
from typing import Dict, Any, List, Optional

from reverse_forge.pe_analyzer import PEAnalyzer
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.macho_analyzer import MachOAnalyzer
from reverse_forge.ghidra_analyzer import GhidraHeadlessAnalyzer
from reverse_forge.tool_installer import ToolchainInstaller


class CorrelationEngine:
    """Multi-tool orchestrator combining format parsers, radare2, Ghidra headless, and Capstone disassembly."""

    def __init__(self):
        self.installer = ToolchainInstaller()
        self.ghidra = GhidraHeadlessAnalyzer()

    def identify_format(self, data: bytes) -> str:
        if len(data) >= 2 and data[:2] in (b"MZ", b"ZM"):
            if len(data) >= 0x40:
                pe_off = struct.unpack_from("<I", data, 0x3C)[0]
                if 0 < pe_off + 2 <= len(data):
                    sig2 = data[pe_off : pe_off + 2]
                    if sig2 == b"NE":
                        return "NE (16-bit)"
                    if sig2 in (b"LE", b"LX"):
                        return "LE/LX (VxD/OS2)"
            return "PE"
        if len(data) >= 4 and data[:4] == b"\x7fELF":
            return "ELF"
        if len(data) >= 4 and data[:4] == b"\x00asm":
            return "WASM"
        if len(data) >= 4 and data[:4] in (b"dex\n", b"dey\n"):
            return "Android DEX"
        if len(data) >= 4:
            magic = struct.unpack_from(">I", data, 0)[0]
            if magic in (0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE):
                return "Mach-O"
            if magic in (0xCAFEBABE, 0xBEBAFECA):
                if MachOAnalyzer.is_fat_macho(data):
                    return "Mach-O"
                if magic == 0xCAFEBABE and len(data) >= 8:
                    _, major_ver = struct.unpack_from(">HH", data, 4)
                    if 44 <= major_ver <= 75:
                        return "JVM Class"
            if magic == 0x27051956:
                return "U-Boot uImage"
            if magic == 0xD00DFEED:
                return "Flattened Device Tree (DTB/FIT)"
        # Additional IDA Pro format signatures
        prefix_map = [
            (b"UF2\n", "UF2 Firmware"),
            (b"ANDROID!", "Android Boot Image"),
            (b"MDMP", "Windows Minidump (MDMP)"),
            (b"Microsoft C/C++ MSF 7.00", "Microsoft PDB"),
            (b"!<arch>\n", "AR Static Archive (.a/.lib)"),
            (b"NSO0", "Nintendo Switch NSO0"),
            (b"NRO0", "Nintendo Switch NRO0"),
            (b"XBEH", "Xbox XBE"),
            (b"XEX2", "Xbox 360 XEX2"),
            (b"PS-X EXE", "PlayStation PSX-EXE"),
            (b"\x4f\x15\x3d\x1d", "PlayStation SELF"),
            (b"NES\x1a", "NES iNES ROM"),
            (b"\x1bLua", "Lua Bytecode (.luac)"),
            (b"BC\xc0\xde", "LLVM Bitcode (.bc)"),
            (b"VZ", "UEFI Terse Executable (TE)"),
            (b"dyld_v1", "Apple DYLD Shared Cache"),
            (b"IDA1", "IDA Database (.idb)"),
            (b"IDA2", "IDA 64-bit Database (.i64)"),
        ]
        for sig, name in prefix_map:
            if data.startswith(sig):
                return name
        if len(data) >= 11 and data[0:1] == b":" and all(chr(b) in "0123456789abcdefABCDEF:" for b in data[:11]):
            return "Intel HEX Firmware"
        if len(data) >= 10 and data[0:1] == b"S" and chr(data[1]) in "0123" and all(chr(b) in "0123456789abcdefABCDEF" for b in data[2:10]):
            return "Motorola S-Record Firmware"
        return "Unknown"

    def analyze_artifact(self, filepath: str, run_ghidra: bool = True) -> Dict[str, Any]:
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
        ghidra_info = self.ghidra.analyze(filepath) if run_ghidra else {"status": "skipped", "reason": "Disabled by caller"}
        capstone_info = self._run_capstone_disassembly(data, format_info)
        correlation = self._correlate_results(format_info, r2_info, ghidra_info, capstone_info)

        return {
            "artifact": os.path.abspath(filepath),
            "detected_format": fmt,
            "structural_analysis": format_info,
            "tool_radare2": r2_info,
            "tool_ghidra": ghidra_info,
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
                    return data[off:off + 512], entry_va
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
                        return data[mapped:mapped + 512], entry_va
                if 0 <= sec_off < len(data):
                    return data[sec_off:sec_off + 512], (sec_va or entry_va)
            except Exception:
                continue

        return data[:512], entry_va

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

    def _correlate_results(
        self,
        fmt_info: Dict[str, Any],
        r2_info: Dict[str, Any],
        ghidra_info: Dict[str, Any],
        cs_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Correlate independently acquired tool outputs across Native Parser, Radare2, Ghidra, and Capstone."""
        evidence = []
        conflicts = []

        arch_primary = fmt_info.get("architecture", "Unknown")
        r2_arch = r2_info.get("binary_info", {}).get("arch", None)
        ghidra_lang = ghidra_info.get("analysis", {}).get("language_id", None)

        if r2_arch:
            if r2_arch.lower() in arch_primary.lower() or arch_primary.lower() in r2_arch.lower():
                evidence.append(f"Architecture confirmed by Native Parser and Radare2: {arch_primary}")
            else:
                conflicts.append(f"Architecture mismatch: Native={arch_primary} vs Radare2={r2_arch}")
        else:
            evidence.append(f"Architecture inferred by Native Parser: {arch_primary}")

        if ghidra_lang:
            evidence.append(f"Ghidra headless analysis completed with language ID: {ghidra_lang}")
            sink_xrefs = ghidra_info.get("analysis", {}).get("dangerous_sink_xrefs", [])
            if sink_xrefs:
                evidence.append(f"Ghidra identified {len(sink_xrefs)} dangerous sink cross-reference(s)")

        if cs_info.get("status") == "success" and cs_info.get("disassembled_instructions"):
            evidence.append(
                f"Capstone disassembled {len(cs_info['disassembled_instructions'])} entry-point instructions"
            )

        entropy = fmt_info.get("entropy", 0.0)
        packed = entropy > 7.1

        confidence = "HIGH" if (len(evidence) > 1 and len(conflicts) == 0) else "MEDIUM"

        return {
            "evidence": evidence,
            "conflicts": conflicts,
            "is_likely_packed": packed,
            "overall_confidence": confidence
        }
