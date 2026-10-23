"""
R3V3R53//F0RG3 — Phase 38: Bare-Metal Firmware Base-Address & RTOS Scanner
Modeled on Binary Ninja's automated base-address detector and `rbasefind`.
Recovers the true memory load address (`image_base`) of raw headerless ROM / IoT /
MCU firmware dumps (ARM Cortex-M, ARM64, MIPS32, RISC-V, x86) by correlating:
  1. Null-terminated ASCII string offsets in the firmware image
  2. 32-bit / 64-bit little-endian pointer tables embedded inside the image
  3. ARM Cortex-M Vector Table validation (Initial MSP + Reset_Handler thumb bit)
"""

from dataclasses import dataclass, field
import struct
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class BaseAddressCandidate:
    base_address: int
    base_hex: str
    pointer_string_matches: int
    vector_table_bonus: int
    confidence_score: float


@dataclass
class FirmwareBaseReport:
    firmware_size_bytes: int
    extracted_string_offsets: int
    extracted_pointer_words: int
    detected_rtos_signatures: List[str]
    best_base_address: int
    best_base_hex: str
    top_candidates: List[BaseAddressCandidate]


class FirmwareBaseEngine:
    """
    Infers the exact memory load base address (`image_base`) of stripped, headerless
    bare-metal firmware blobs using pointer-to-string alignment histograms.
    """

    DEFAULT_CANDIDATE_BASES: List[int] = [
        0x00000000,
        0x00010000,
        0x00400000,
        0x08000000,  # STM32 / ARM Cortex-M Flash base
        0x10000000,
        0x20000000,  # ARM Cortex-M SRAM base
        0x40000000,
        0x80000000,  # MIPS32 KSEG0 / RISC-V DRAM base
        0x80010000,
        0x9FC00000,  # MIPS Boot ROM
        0xBFC00000,
        0xC0000000,  #VxWorks / Linux Kernel base
        0xFFFF0000,
    ]

    RTOS_SIGNATURES: Dict[str, bytes] = {
        "FreeRTOS": b"FreeRTOS",
        "VxWorks": b"VxWorks",
        "Zephyr_RTOS": b"Zephyr",
        "ThreadX": b"ThreadX",
        "uC/OS-II": b"uC/OS",
        "Contiki_NG": b"Contiki",
        "ESP-IDF": b"ESP-IDF",
        "U-Boot_Bootloader": b"U-Boot",
    }

    def extract_string_offsets(self, data: bytes, min_len: int = 4) -> Set[int]:
        """Find file offsets of all null-terminated printable ASCII strings."""
        offsets: Set[int] = set()
        n = len(data)
        start: Optional[int] = None
        for i, b in enumerate(data):
            if 0x20 <= b <= 0x7E:
                if start is None:
                    start = i
            elif b == 0x00 and start is not None:
                if i - start >= min_len:
                    offsets.add(start)
                start = None
            else:
                start = None
        return offsets

    def extract_32bit_words(self, data: bytes) -> List[int]:
        """Extract 4-byte aligned 32-bit little-endian words that could be absolute pointers."""
        words: List[int] = []
        limit = (len(data) // 4) * 4
        for off in range(0, limit, 4):
            w = struct.unpack_from("<I", data, off)[0]
            if w >= 0x1000 and w != 0xFFFFFFFF:
                words.append(w)
        return words

    def scan_firmware_base(
        self,
        firmware_bytes: bytes,
        custom_candidates: Optional[List[int]] = None,
    ) -> FirmwareBaseReport:
        """
        Score candidate base addresses by counting how many 32-bit pointer literals `P`
        satisfy `(P - base_addr) in string_file_offsets`, plus ARM Cortex-M vector table heuristics.
        """
        size = len(firmware_bytes)
        str_offsets = self.extract_string_offsets(firmware_bytes)
        ptr_words = self.extract_32bit_words(firmware_bytes)

        # Also dynamically infer candidate bases by rounding down `(ptr_word - str_off)` to 64 KB page boundaries
        candidates: Set[int] = set(custom_candidates or self.DEFAULT_CANDIDATE_BASES)
        if str_offsets and ptr_words:
            sample_strs = sorted(str_offsets)[:32]
            for pw in ptr_words[:256]:
                for so in sample_strs:
                    if pw >= so:
                        diff = pw - so
                        if (diff & 0xFFFF) == 0:
                            candidates.add(diff)

        # Detect RTOS signatures
        rtos_hits: List[str] = []
        for name, sig in self.RTOS_SIGNATURES.items():
            if sig in firmware_bytes:
                rtos_hits.append(name)

        # Check ARM Cortex-M initial vector table at offset 0: [Initial_SP (0x2000xxxx), Reset_Handler (odd thumb addr)]
        cortex_m_reset_base: Optional[int] = None
        if size >= 8:
            init_sp, reset_vec = struct.unpack_from("<II", firmware_bytes, 0)
            if (init_sp & 0xFFF00000) == 0x20000000 and (reset_vec & 1) == 1:
                cortex_m_reset_base = reset_vec & 0xFFFF0000
                candidates.add(cortex_m_reset_base)

        scored: List[BaseAddressCandidate] = []
        for base in sorted(candidates):
            matches = 0
            for pw in ptr_words:
                rel = pw - base
                if 0 <= rel < size and rel in str_offsets:
                    matches += 1
            vec_bonus = 5 if (cortex_m_reset_base is not None and base == cortex_m_reset_base) else 0
            total_points = matches + vec_bonus
            conf = min(0.99, round(total_points / max(1, len(str_offsets) + 2), 3)) if total_points > 0 else 0.0
            scored.append(
                BaseAddressCandidate(
                    base_address=base,
                    base_hex=hex(base),
                    pointer_string_matches=matches,
                    vector_table_bonus=vec_bonus,
                    confidence_score=conf,
                )
            )

        scored.sort(key=lambda c: (c.pointer_string_matches + c.vector_table_bonus, c.confidence_score), reverse=True)
        top = scored[:5]
        best = top[0] if top else BaseAddressCandidate(0, "0x0", 0, 0, 0.0)

        return FirmwareBaseReport(
            firmware_size_bytes=size,
            extracted_string_offsets=len(str_offsets),
            extracted_pointer_words=len(ptr_words),
            detected_rtos_signatures=rtos_hits,
            best_base_address=best.base_address,
            best_base_hex=best.base_hex,
            top_candidates=top,
        )
