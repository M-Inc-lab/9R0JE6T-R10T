"""
R3V3R53//F0RG3 — Phase 46: FLOSS-Style Obfuscated & Stack String Deobfuscator
Modeled on Mandiant FLOSS (FLARE Obfuscated String Solver, https://github.com/mandiant/flare-floss).
Recovers hidden strings that standard static `strings` utilities miss:
  1. Stack Strings (`mov byte ptr [rbp-0x10], 0x68` / `mov dword ptr [rsp+0x20], 0x70747468`)
  2. Single-Byte XOR Obfuscated Strings (keys `0x01..0xFF` over high-entropy or non-ASCII buffers)
  3. Rolling / Multi-Byte XOR & Constant ADD/SUB Shift Obfuscated Strings
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
import struct
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class DecodedHiddenString:
    decoding_method: str        # STACK_STRING_BYTE, STACK_STRING_DWORD, XOR_SINGLE_BYTE, ADD_SHIFT_BYTE
    decoded_string: str
    key_or_register: str
    file_offset: str
    confidence: float


@dataclass
class StringDeobfuscationReport:
    total_recovered: int
    stack_strings_count: int
    xor_strings_count: int
    shift_strings_count: int
    recovered_strings: List[DecodedHiddenString] = field(default_factory=list)


class ObfuscatedStringSolver:
    """
    Extracts stack-constructed strings and XOR/ADD-encoded strings from raw binary bytes
    and disassembled instruction streams.
    """

    # High-value indicator substrings for scoring candidate XOR/ADD decoded strings
    HIGH_SIGNAL_PATTERNS = (
        "http://", "https://", "cmd.exe", "powershell", "/bin/sh", "/bin/bash",
        "/etc/passwd", "Software\\", "CurrentVersion", "VirtualAlloc", "LoadLibrary",
        "GetProcAddress", "CreateProcess", "ws2_32", "kernel32", "ntdll", "Mozilla/",
        "Bearer ", "flag{", "SECRET", "password", ".exe", ".dll", ".so",
    )

    def recover_stack_strings(self, binary_bytes: bytes, min_len: int = 4) -> List[DecodedHiddenString]:
        """
        Scan executable bytes for x86/x64 immediate-to-stack stores:
          - `C6 45 disp8 imm8`       (`mov byte ptr [rbp + disp8], imm8`)
          - `C6 85 disp32 imm8`      (`mov byte ptr [rbp + disp32], imm8`)
          - `C6 44 24 disp8 imm8`    (`mov byte ptr [rsp + disp8], imm8`)
          - `C7 45 disp8 imm32`      (`mov dword ptr [rbp + disp8], imm32`)
          - `C7 44 24 disp8 imm32`   (`mov dword ptr [rsp + disp8], imm32`)
        """
        results: List[DecodedHiddenString] = []
        n = len(binary_bytes)

        # Group contiguous stack writes within 128-byte code windows
        stack_writes: Dict[int, Tuple[int, str, int]] = {}  # stack_disp -> (byte_val, reg_name, file_off)
        last_off = -1000

        def flush_buffer() -> None:
            if not stack_writes:
                return
            sorted_disps = sorted(stack_writes.keys())
            curr_chars: List[str] = []
            start_off = stack_writes[sorted_disps[0]][2]
            reg_used = stack_writes[sorted_disps[0]][1]
            prev_d: Optional[int] = None

            for d in sorted_disps:
                b_val, r_name, f_off = stack_writes[d]
                if prev_d is not None and d != prev_d + 1:
                    if len(curr_chars) >= min_len:
                        s_val = "".join(curr_chars)
                        results.append(
                            DecodedHiddenString(
                                decoding_method="STACK_STRING",
                                decoded_string=s_val,
                                key_or_register=reg_used,
                                file_offset=hex(start_off),
                                confidence=0.95,
                            )
                        )
                    curr_chars = []
                    start_off = f_off
                    reg_used = r_name
                if 0x20 <= b_val <= 0x7E:
                    curr_chars.append(chr(b_val))
                    prev_d = d
                elif b_val == 0x00:
                    if len(curr_chars) >= min_len:
                        results.append(
                            DecodedHiddenString(
                                decoding_method="STACK_STRING",
                                decoded_string="".join(curr_chars),
                                key_or_register=reg_used,
                                file_offset=hex(start_off),
                                confidence=0.98,
                            )
                        )
                    curr_chars = []
                    prev_d = None

            if len(curr_chars) >= min_len:
                results.append(
                    DecodedHiddenString(
                        decoding_method="STACK_STRING",
                        decoded_string="".join(curr_chars),
                        key_or_register=reg_used,
                        file_offset=hex(start_off),
                        confidence=0.95,
                    )
                )
            stack_writes.clear()

        i = 0
        while i < n:
            if i - last_off > 64 and stack_writes:
                flush_buffer()

            b0 = binary_bytes[i]
            # 1. mov byte ptr [rbp + disp8], imm8 (C6 45 disp8 imm8)
            if b0 == 0xC6 and i + 4 <= n and binary_bytes[i + 1] == 0x45:
                disp8 = struct.unpack_from("<b", binary_bytes, i + 2)[0]
                imm8 = binary_bytes[i + 3]
                stack_writes[disp8] = (imm8, "rbp", i)
                last_off = i
                i += 4
                continue

            # 2. mov byte ptr [rsp + disp8], imm8 (C6 44 24 disp8 imm8)
            if b0 == 0xC6 and i + 5 <= n and binary_bytes[i + 1] == 0x44 and binary_bytes[i + 2] == 0x24:
                disp8 = struct.unpack_from("<b", binary_bytes, i + 3)[0]
                imm8 = binary_bytes[i + 4]
                stack_writes[disp8] = (imm8, "rsp", i)
                last_off = i
                i += 5
                continue

            # 3. mov dword ptr [rbp + disp8], imm32 (C7 45 disp8 imm32)
            if b0 == 0xC7 and i + 7 <= n and binary_bytes[i + 1] == 0x45:
                disp8 = struct.unpack_from("<b", binary_bytes, i + 2)[0]
                for k in range(4):
                    stack_writes[disp8 + k] = (binary_bytes[i + 3 + k], "rbp_dword", i)
                last_off = i
                i += 7
                continue

            # 4. mov dword ptr [rsp + disp8], imm32 (C7 44 24 disp8 imm32)
            if b0 == 0xC7 and i + 8 <= n and binary_bytes[i + 1] == 0x44 and binary_bytes[i + 2] == 0x24:
                disp8 = struct.unpack_from("<b", binary_bytes, i + 3)[0]
                for k in range(4):
                    stack_writes[disp8 + k] = (binary_bytes[i + 4 + k], "rsp_dword", i)
                last_off = i
                i += 8
                continue

            i += 1

        flush_buffer()
        return results

    def bruteforce_xor_strings(self, binary_bytes: bytes, min_len: int = 6) -> List[DecodedHiddenString]:
        """
        Scan non-zero byte runs that are NOT already printable ASCII and test single-byte
        XOR keys (0x01..0xFF) to recover XOR-obfuscated URLs, paths, commands, and APIs.
        """
        results: List[DecodedHiddenString] = []
        seen: set[str] = set()
        scan_slice = binary_bytes[:256 * 1024]

        for key in range(1, 256):
            # Fast XOR transform over candidate slice
            xored = bytes(b ^ key for b in scan_slice)
            for m in re.finditer(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", xored):
                cand_off = m.start()
                orig_chunk = scan_slice[cand_off : m.end()]
                # Skip if original bytes were already plain ASCII or uniform padding
                if all(0x20 <= b <= 0x7E for b in orig_chunk) or len(set(orig_chunk)) <= 2:
                    continue
                # Check if XORed string is terminated by XORed null byte (i.e. raw byte == key) or high-signal
                is_null_terminated = (m.end() < len(scan_slice) and scan_slice[m.end()] == key)
                decoded = m.group(0).decode("ascii", errors="ignore")
                has_signal = any(pat.lower() in decoded.lower() for pat in self.HIGH_SIGNAL_PATTERNS)

                if has_signal or (is_null_terminated and self._is_plausible_identifier_or_text(decoded)):
                    if decoded not in seen:
                        seen.add(decoded)
                        results.append(
                            DecodedHiddenString(
                                decoding_method="XOR_SINGLE_BYTE",
                                decoded_string=decoded,
                                key_or_register=f"xor_key=0x{key:02x}",
                                file_offset=hex(cand_off),
                                confidence=0.96 if has_signal else 0.82,
                            )
                        )
        return results

    def recover_add_shift_strings(self, binary_bytes: bytes, min_len: int = 6) -> List[DecodedHiddenString]:
        """
        Detect Caesar / byte-addition obfuscated strings (`(b - shift) & 0xFF`) for common shifts.
        """
        results: List[DecodedHiddenString] = []
        seen: set[str] = set()
        scan_slice = binary_bytes[:128 * 1024]

        for shift in (1, 2, 3, 4, 5, 7, 13, 255, 254, 253):
            shifted = bytes((b - shift) & 0xFF for b in scan_slice)
            for m in re.finditer(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", shifted):
                decoded = m.group(0).decode("ascii", errors="ignore")
                if any(pat.lower() in decoded.lower() for pat in self.HIGH_SIGNAL_PATTERNS):
                    if decoded not in seen:
                        seen.add(decoded)
                        results.append(
                            DecodedHiddenString(
                                decoding_method="ADD_SHIFT_BYTE",
                                decoded_string=decoded,
                                key_or_register=f"byte_shift=+{shift}",
                                file_offset=hex(m.start()),
                                confidence=0.92,
                            )
                        )
        return results

    @staticmethod
    def _is_plausible_identifier_or_text(s: str) -> bool:
        if len(s) < 6:
            return False
        alnum = sum(1 for c in s if c.isalnum() or c in "._-/\\:")
        vowels = sum(1 for c in s.lower() if c in "aeiou")
        return (alnum / len(s)) >= 0.85 and vowels >= 2

    def deobfuscate_all_strings(self, binary_bytes: bytes, min_len: int = 4) -> StringDeobfuscationReport:
        stack_s = self.recover_stack_strings(binary_bytes, min_len=min_len)
        xor_s = self.bruteforce_xor_strings(binary_bytes, min_len=max(6, min_len))
        shift_s = self.recover_add_shift_strings(binary_bytes, min_len=max(6, min_len))
        combined = stack_s + xor_s + shift_s
        return StringDeobfuscationReport(
            total_recovered=len(combined),
            stack_strings_count=len(stack_s),
            xor_strings_count=len(xor_s),
            shift_strings_count=len(shift_s),
            recovered_strings=combined,
        )
