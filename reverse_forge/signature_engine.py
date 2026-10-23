"""
R3V3R53//F0RG3 — Stripped Binary Signature & Wildcard Byte-Pattern Engine (FLIRT / FIDB / YARA style)
Identifies statically linked library routines, compiler/runtime markers, architecture prologues
(including Intel CET ENDBR64 and ARM64e PACIASP), and estimates function boundaries in stripped binaries.
"""

import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SignatureRule:
    rule_id: str
    name: str
    category: str
    pattern_hex: str
    architecture: str = "any"
    description: str = ""


@dataclass
class SignatureMatch:
    rule_id: str
    name: str
    category: str
    architecture: str
    offset: int
    matched_hex: str
    description: str


class SignatureEngine:
    """Wildcard hex byte-pattern matcher and stripped-binary function prologue scanner."""

    BUILTIN_RULES: List[SignatureRule] = [
        SignatureRule(
            rule_id="SIG-ARCH-X64-CET",
            name="x86_64_cet_endbr64_prologue",
            category="Architecture & Hardening Prologue",
            pattern_hex="F3 0F 1E FA 55 48 89 E5",
            architecture="x86_64",
            description="Intel CET Indirect Branch Tracking (ENDBR64) followed by standard frame pointer setup.",
        ),
        SignatureRule(
            rule_id="SIG-ARCH-X64-SYSV",
            name="x86_64_standard_frame_prologue",
            category="Function Prologue",
            pattern_hex="55 48 89 E5 48 83 EC ??",
            architecture="x86_64",
            description="Standard x86_64 frame setup (push rbp; mov rbp, rsp; sub rsp, imm8).",
        ),
        SignatureRule(
            rule_id="SIG-ARCH-ARM64E-PAC",
            name="arm64e_pointer_auth_paciasp",
            category="Architecture & Hardening Prologue",
            pattern_hex="7F 23 03 D5 FD 7B ?? A9",
            architecture="ARM64e",
            description="ARM64e Pointer Authentication (PACIASP) instruction followed by frame pair store (STP X29, X30).",
        ),
        SignatureRule(
            rule_id="SIG-CRYPTO-CHACHA20",
            name="chacha20_constant_expand_32_byte_k",
            category="Cryptographic Constant",
            pattern_hex="65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B",
            architecture="any",
            description="ChaCha20 / Salsa20 stream cipher 256-bit state constant ('expand 32-byte k').",
        ),
        SignatureRule(
            rule_id="SIG-CRYPTO-SALSA20-16",
            name="salsa20_constant_expand_16_byte_k",
            category="Cryptographic Constant",
            pattern_hex="65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 20 6B",
            architecture="any",
            description="Salsa20 stream cipher 128-bit state constant ('expand 16-byte k').",
        ),
        SignatureRule(
            rule_id="SIG-RUNTIME-RUST",
            name="rust_core_panicking_marker",
            category="Compiler & Runtime Identification",
            pattern_hex="72 75 73 74 5F 62 65 67 69 6E 5F 75 6E 77 69 6E 64",
            architecture="any",
            description="Rust standard library unwind marker ('rust_begin_unwind').",
        ),
        SignatureRule(
            rule_id="SIG-RUNTIME-GOLANG",
            name="golang_buildid_header",
            category="Compiler & Runtime Identification",
            pattern_hex="FF 20 47 6F 20 62 75 69 6C 64 69 64 3A 20",
            architecture="any",
            description="Go toolchain embedded build ID header ('\xff Go buildid: ').",
        ),
    ]

    def __init__(self, extra_rules: Optional[List[SignatureRule]] = None):
        self.rules: List[SignatureRule] = list(self.BUILTIN_RULES)
        if extra_rules:
            self.rules.extend(extra_rules)

    def load_rules_from_json(self, json_path: str) -> int:
        if not os.path.exists(json_path):
            raise FileNotFoundError(f"Signature rules file not found: {json_path}")
        with open(json_path, "r", encoding="utf-8") as f:
            raw_list = json.load(f)
        added = 0
        for item in raw_list:
            self.rules.append(SignatureRule(**item))
            added += 1
        return added

    @staticmethod
    def compile_wildcard_pattern(pattern_hex: str) -> re.Pattern:
        """
        Convert a hex byte pattern with '??' wildcards (e.g. '55 48 89 E5 ?? ??')
        into a compiled bytes regex with DOTALL enabled.
        """
        tokens = pattern_hex.strip().split()
        if not tokens:
            raise ValueError("Empty hex pattern")
        regex_parts: List[bytes] = []
        for tok in tokens:
            if tok == "??":
                regex_parts.append(b".")
            else:
                if len(tok) != 2 or not all(c in "0123456789abcdefABCDEF" for c in tok):
                    raise ValueError(f"Invalid hex byte token in signature: {tok!r}")
                byte_val = int(tok, 16)
                regex_parts.append(re.escape(bytes([byte_val])))
        return re.compile(b"".join(regex_parts), re.DOTALL)

    def scan_bytes(self, data: bytes, max_matches_per_rule: int = 25) -> List[SignatureMatch]:
        matches: List[SignatureMatch] = []
        for rule in self.rules:
            pat = self.compile_wildcard_pattern(rule.pattern_hex)
            count = 0
            for m in pat.finditer(data):
                raw = m.group(0)
                matches.append(SignatureMatch(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    category=rule.category,
                    architecture=rule.architecture,
                    offset=m.start(),
                    matched_hex=raw.hex(),
                    description=rule.description,
                ))
                count += 1
                if count >= max_matches_per_rule:
                    break
        return matches

    def estimate_stripped_functions(self, data: bytes, max_candidates: int = 250) -> Dict[str, Any]:
        """Estimate function entry offsets in stripped binaries using common prologue patterns."""
        prologue_patterns = {
            "x86_64_cet_endbr64": self.compile_wildcard_pattern("F3 0F 1E FA"),
            "x86_64_frame_setup": self.compile_wildcard_pattern("55 48 89 E5"),
            "x86_32_frame_setup": self.compile_wildcard_pattern("55 89 E5"),
            "arm64_paciasp": self.compile_wildcard_pattern("7F 23 03 D5"),
            "arm64_stp_fp_lr": self.compile_wildcard_pattern("FD 7B ?? A9"),
        }
        candidate_offsets: List[Dict[str, Any]] = []
        seen_offsets: set[int] = set()
        counts_by_type: Dict[str, int] = {}

        for p_name, pat in prologue_patterns.items():
            p_count = 0
            for m in pat.finditer(data):
                off = m.start()
                p_count += 1
                if off not in seen_offsets and len(candidate_offsets) < max_candidates:
                    seen_offsets.add(off)
                    candidate_offsets.append({
                        "offset": hex(off),
                        "prologue_type": p_name,
                    })
            if p_count > 0:
                counts_by_type[p_name] = p_count

        candidate_offsets.sort(key=lambda x: int(x["offset"], 16))
        return {
            "estimated_function_prologues_total": sum(counts_by_type.values()),
            "prologue_breakdown": counts_by_type,
            "sample_candidate_entries": candidate_offsets[:50],
            "has_cet_ibt": counts_by_type.get("x86_64_cet_endbr64", 0) > 0,
            "has_arm64_pac": counts_by_type.get("arm64_paciasp", 0) > 0,
        }

    def full_signature_scan(self, data: bytes) -> Dict[str, Any]:
        matches = self.scan_bytes(data)
        prologue_summary = self.estimate_stripped_functions(data)
        return {
            "total_signature_matches": len(matches),
            "matches": [asdict(m) for m in matches],
            "stripped_function_recovery": prologue_summary,
        }
