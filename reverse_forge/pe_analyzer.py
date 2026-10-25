import math
import struct
from typing import Dict, Any, List, Optional, Tuple


class PEAnalyzer:
    """
    Pure-Python PE32 / PE32+ header, section, Data Directory, Import/Export table,
    TLS Callback, and DllCharacteristics mitigation analyzer (zero external dependencies).
    """

    DATA_DIRECTORY_NAMES = [
        "EXPORT",
        "IMPORT",
        "RESOURCE",
        "EXCEPTION",
        "SECURITY",
        "BASERELOC",
        "DEBUG",
        "ARCHITECTURE",
        "GLOBALPTR",
        "TLS",
        "LOAD_CONFIG",
        "BOUND_IMPORT",
        "IAT",
        "DELAY_IMPORT",
        "COM_DESCRIPTOR",
        "RESERVED",
    ]

    def __init__(self, data: bytes):
        self.data = data
        self.length = len(data)

    @staticmethod
    def rva_to_offset(rva: int, sections: List[Dict[str, Any]], file_len: int) -> Optional[int]:
        """Translate a Relative Virtual Address (RVA) to a physical file offset using section headers."""
        if rva <= 0:
            return None
        for sec in sections:
            try:
                vaddr = int(str(sec.get("virtual_address", "0")), 16)
                vsize = int(sec.get("virtual_size", 0))
                raw_size = int(sec.get("raw_size", 0))
                raw_off = int(str(sec.get("raw_offset", "0")), 16)
                span = max(vsize, raw_size)
                if vaddr <= rva < vaddr + span:
                    off = raw_off + (rva - vaddr)
                    if 0 <= off < file_len:
                        return off
            except Exception:
                continue
        if 0 <= rva < file_len:
            return rva
        return None

    def _read_cstring(self, offset: Optional[int], max_len: int = 128) -> str:
        if offset is None or offset < 0 or offset >= self.length:
            return ""
        end = self.data.find(b"\x00", offset, min(self.length, offset + max_len))
        if end == -1:
            end = min(self.length, offset + max_len)
        raw = self.data[offset:end]
        try:
            text = raw.decode("ascii")
            return text if all(0x20 <= ord(c) <= 0x7E for c in text) else ""
        except Exception:
            return ""

    def _parse_imports(
        self,
        import_rva: int,
        import_size: int,
        sections: List[Dict[str, Any]],
        is_pe64: bool,
    ) -> Tuple[List[str], List[str]]:
        """Parse IMAGE_IMPORT_DESCRIPTOR entries and Hint/Name thunks in pure Python."""
        dlls: List[str] = []
        symbols: List[str] = []
        imp_off = self.rva_to_offset(import_rva, sections, self.length)
        if imp_off is None or import_rva == 0 or import_size < 20:
            return dlls, symbols

        max_descriptors = min(64, import_size // 20 + 1)
        for i in range(max_descriptors):
            desc_off = imp_off + (i * 20)
            if desc_off + 20 > self.length:
                break
            orig_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", self.data, desc_off)
            if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break

            dll_name = self._read_cstring(self.rva_to_offset(name_rva, sections, self.length))
            if dll_name and dll_name not in dlls:
                dlls.append(dll_name)

            thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
            thunk_off = self.rva_to_offset(thunk_rva, sections, self.length)
            if thunk_off is None:
                continue

            ptr_size = 8 if is_pe64 else 4
            ordinal_flag = (1 << 63) if is_pe64 else (1 << 31)
            for t_idx in range(256):
                cur_thunk = thunk_off + (t_idx * ptr_size)
                if cur_thunk + ptr_size > self.length:
                    break
                val = struct.unpack_from("<Q" if is_pe64 else "<I", self.data, cur_thunk)[0]
                if val == 0:
                    break
                if val & ordinal_flag:
                    ord_num = val & 0xFFFF
                    sym = f"{dll_name or 'ord'}!Ordinal_{ord_num}"
                    if sym not in symbols:
                        symbols.append(sym)
                else:
                    hint_name_off = self.rva_to_offset(val & 0x7FFFFFFF, sections, self.length)
                    if hint_name_off is not None and hint_name_off + 2 < self.length:
                        fn_name = self._read_cstring(hint_name_off + 2)
                        if fn_name and fn_name not in symbols:
                            symbols.append(fn_name)

        return dlls, symbols

    def _parse_exports(self, export_rva: int, export_size: int, sections: List[Dict[str, Any]]) -> List[str]:
        """Parse IMAGE_EXPORT_DIRECTORY exported function names in pure Python."""
        exports: List[str] = []
        exp_off = self.rva_to_offset(export_rva, sections, self.length)
        if exp_off is None or export_rva == 0 or export_size < 40 or exp_off + 40 > self.length:
            return exports

        _, _, _, _, _, _, num_funcs, num_names, funcs_rva, names_rva, _ = struct.unpack_from(
            "<IIIIIIIIIII", self.data, exp_off
        )
        names_off = self.rva_to_offset(names_rva, sections, self.length)
        if names_off is None or num_names == 0:
            return exports

        for i in range(min(num_names, 512)):
            ptr_off = names_off + (i * 4)
            if ptr_off + 4 > self.length:
                break
            fn_name_rva = struct.unpack_from("<I", self.data, ptr_off)[0]
            fn_name = self._read_cstring(self.rva_to_offset(fn_name_rva, sections, self.length))
            if fn_name:
                exports.append(fn_name)
        return exports

    def _parse_tls_callbacks(
        self,
        tls_rva: int,
        tls_size: int,
        image_base: int,
        sections: List[Dict[str, Any]],
        is_pe64: bool,
    ) -> List[str]:
        """Extract PE TLS Callback Virtual Addresses (pre-entry execution vectors)."""
        callbacks: List[str] = []
        tls_off = self.rva_to_offset(tls_rva, sections, self.length)
        if tls_off is None or tls_rva == 0:
            return callbacks

        if is_pe64 and tls_off + 40 <= self.length:
            cb_array_va = struct.unpack_from("<Q", self.data, tls_off + 24)[0]
            ptr_sz = 8
        elif not is_pe64 and tls_off + 24 <= self.length:
            cb_array_va = struct.unpack_from("<I", self.data, tls_off + 12)[0]
            ptr_sz = 4
        else:
            return callbacks

        if cb_array_va <= image_base:
            return callbacks
        cb_rva = cb_array_va - image_base
        cb_off = self.rva_to_offset(cb_rva, sections, self.length)
        if cb_off is None:
            return callbacks

        for i in range(16):
            p = cb_off + (i * ptr_sz)
            if p + ptr_sz > self.length:
                break
            fn_va = struct.unpack_from("<Q" if is_pe64 else "<I", self.data, p)[0]
            if fn_va == 0:
                break
            callbacks.append(hex(fn_va))
        return callbacks

    def analyze(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "is_pe": False,
            "architecture": "Unknown",
            "sections": [],
            "characteristics": [],
            "dll_characteristics": [],
            "mitigations": {},
            "data_directories": {},
            "imported_dlls": [],
            "imported_symbols": [],
            "exported_symbols": [],
            "tls_callbacks": [],
            "has_authenticode_signature": False,
            "subsystem": "Unknown",
            "entry_point": 0,
            "entry_file_offset": None,
            "image_base": 0,
            "entropy": self.calculate_entropy(self.data),
            "warnings": [],
        }

        if self.length < 64 or self.data[:2] != b"MZ":
            result["warnings"].append("Missing MZ magic signature")
            return result

        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if e_lfanew + 4 > self.length:
            result["warnings"].append("Invalid PE header pointer (e_lfanew exceeds file size)")
            return result

        if self.data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            result["warnings"].append("Missing PE\\0\\0 signature")
            return result

        result["is_pe"] = True
        coff_offset = e_lfanew + 4
        if coff_offset + 20 > self.length:
            result["warnings"].append("Truncated COFF header")
            return result

        machine, num_sections, timedate, symtab, num_syms, opt_hdr_size, characteristics = struct.unpack_from(
            "<HHIIIHH", self.data, coff_offset
        )

        arch_map = {
            0x014C: "x86 (32-bit)",
            0x8664: "x64 (64-bit AMD64)",
            0x01C0: "ARM",
            0xAA64: "ARM64",
        }
        result["architecture"] = arch_map.get(machine, f"Unknown (0x{machine:04X})")
        result["timestamp"] = timedate

        char_flags = [
            (0x0002, "EXECUTABLE_IMAGE"),
            (0x0020, "LARGE_ADDRESS_AWARE"),
            (0x0100, "32BIT_MACHINE"),
            (0x1000, "SYSTEM"),
            (0x2000, "DLL"),
        ]
        result["characteristics"] = [name for bit, name in char_flags if characteristics & bit]

        entry_rva = 0
        image_base = 0
        is_pe64 = False
        dll_chars = 0
        dd_offset = 0
        num_rva_and_sizes = 0

        opt_offset = coff_offset + 20
        if opt_hdr_size >= 2 and opt_offset + opt_hdr_size <= self.length:
            magic = struct.unpack_from("<H", self.data, opt_offset)[0]
            subsystem = 0
            if magic == 0x10B and opt_hdr_size >= 28 and opt_offset + 28 <= self.length:
                is_pe64 = False
                entry_rva, _, image_base = struct.unpack_from("<III", self.data, opt_offset + 16)
                if opt_hdr_size >= 72 and opt_offset + 72 <= self.length:
                    subsystem, dll_chars = struct.unpack_from("<HH", self.data, opt_offset + 68)
                if opt_hdr_size >= 96 and opt_offset + 96 <= self.length:
                    num_rva_and_sizes = struct.unpack_from("<I", self.data, opt_offset + 92)[0]
                    dd_offset = opt_offset + 96
                result["entry_point"] = hex(entry_rva)
                result["image_base"] = hex(image_base)
            elif magic == 0x20B and opt_hdr_size >= 32 and opt_offset + 32 <= self.length:
                is_pe64 = True
                entry_rva = struct.unpack_from("<I", self.data, opt_offset + 16)[0]
                image_base = struct.unpack_from("<Q", self.data, opt_offset + 24)[0]
                if opt_hdr_size >= 72 and opt_offset + 72 <= self.length:
                    subsystem, dll_chars = struct.unpack_from("<HH", self.data, opt_offset + 68)
                if opt_hdr_size >= 112 and opt_offset + 112 <= self.length:
                    num_rva_and_sizes = struct.unpack_from("<I", self.data, opt_offset + 108)[0]
                    dd_offset = opt_offset + 112
                result["entry_point"] = hex(entry_rva)
                result["image_base"] = hex(image_base)

            subsystems = {
                1: "NATIVE",
                2: "WINDOWS_GUI",
                3: "WINDOWS_CUI",
                7: "POSIX_CUI",
                9: "WINDOWS_CE_GUI",
                10: "EFI_APPLICATION",
            }
            result["subsystem"] = subsystems.get(subsystem, f"Unknown ({subsystem})")

            dll_char_flags = [
                (0x0020, "HIGH_ENTROPY_VA"),
                (0x0040, "DYNAMIC_BASE_ASLR"),
                (0x0080, "FORCE_INTEGRITY"),
                (0x0100, "NX_COMPAT_DEP"),
                (0x0400, "NO_SEH"),
                (0x1000, "APPCONTAINER"),
                (0x4000, "GUARD_CF"),
            ]
            result["dll_characteristics"] = [name for bit, name in dll_char_flags if dll_chars & bit]
            result["mitigations"] = {
                "ASLR": bool(dll_chars & 0x0040),
                "HighEntropyVA": bool(dll_chars & 0x0020),
                "DEP_NX": bool(dll_chars & 0x0100),
                "ControlFlowGuard_CFG": bool(dll_chars & 0x4000),
                "ForceIntegrity": bool(dll_chars & 0x0080),
                "NoSEH": bool(dll_chars & 0x0400),
            }

            if dd_offset > 0 and num_rva_and_sizes > 0:
                max_dirs = min(int(num_rva_and_sizes), 16)
                for d_idx in range(max_dirs):
                    cur_dd = dd_offset + (d_idx * 8)
                    if cur_dd + 8 > opt_offset + opt_hdr_size or cur_dd + 8 > self.length:
                        break
                    dd_rva, dd_size = struct.unpack_from("<II", self.data, cur_dd)
                    if dd_rva != 0 or dd_size != 0:
                        result["data_directories"][self.DATA_DIRECTORY_NAMES[d_idx]] = {
                            "rva": hex(dd_rva),
                            "size": dd_size,
                        }

        sec_offset = opt_offset + opt_hdr_size
        for i in range(min(num_sections, 96)):
            cur = sec_offset + (i * 40)
            if cur + 40 > self.length:
                break
            raw_name = self.data[cur:cur + 8]
            name = raw_name.split(b"\x00")[0].decode("ascii", errors="replace").strip()
            vsize, vaddr, raw_size, raw_offset = struct.unpack_from("<IIII", self.data, cur + 8)
            sec_chars = struct.unpack_from("<I", self.data, cur + 36)[0]

            sec_bytes = self.data[raw_offset:raw_offset + raw_size] if raw_offset + raw_size <= self.length else b""
            sec_entropy = self.calculate_entropy(sec_bytes) if sec_bytes else 0.0

            span = max(vsize, raw_size)
            if entry_rva > 0 and vaddr <= entry_rva < vaddr + span:
                mapped_off = raw_offset + (entry_rva - vaddr)
                if mapped_off < self.length:
                    result["entry_file_offset"] = hex(mapped_off)

            result["sections"].append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": hex(vaddr),
                "raw_size": raw_size,
                "raw_offset": hex(raw_offset),
                "offset": hex(raw_offset),
                "entropy": round(sec_entropy, 2),
                "executable": bool(sec_chars & 0x20000000),
                "readable": bool(sec_chars & 0x40000000),
                "writable": bool(sec_chars & 0x80000000),
            })

        # Parse pure-Python Imports, Exports, TLS Callbacks, and Authenticode presence
        dd = result["data_directories"]
        if "IMPORT" in dd:
            imp_rva = int(dd["IMPORT"]["rva"], 16)
            imp_sz = int(dd["IMPORT"]["size"])
            dlls, syms = self._parse_imports(imp_rva, imp_sz, result["sections"], is_pe64)
            result["imported_dlls"] = dlls
            result["imported_symbols"] = syms

        if "EXPORT" in dd:
            exp_rva = int(dd["EXPORT"]["rva"], 16)
            exp_sz = int(dd["EXPORT"]["size"])
            result["exported_symbols"] = self._parse_exports(exp_rva, exp_sz, result["sections"])

        if "TLS" in dd:
            tls_rva = int(dd["TLS"]["rva"], 16)
            tls_sz = int(dd["TLS"]["size"])
            result["tls_callbacks"] = self._parse_tls_callbacks(
                tls_rva, tls_sz, image_base, result["sections"], is_pe64
            )

        if "SECURITY" in dd and dd["SECURITY"]["size"] > 0:
            result["has_authenticode_signature"] = True

        return result

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        sample = data[:16 * 1024 * 1024]
        entropy = 0.0
        counts = [0] * 256
        for b in sample:
            counts[b] += 1
        total = len(sample)
        for c in counts:
            if c > 0:
                p = c / total
                entropy -= p * math.log2(p)
        return round(entropy, 4)
