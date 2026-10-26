"""
R3V3R53//F0RG3 — Phase 74: Advanced C2 Configuration, Custom Base64 & RC4 KSA Extractor Engine
(`config_crypto_extractor.py`)
Automates extraction of deep cryptographic and command-and-control (C2) artifacts from binaries:
  1. Custom Base64 Alphabet Detector & Automatic Decoder:
     - Scans for 64-byte permutation tables containing `A-Z`, `a-z`, `0-9`, and 2 punctuation symbols
       in non-standard order, and decodes adjacent custom-Base64 encoded strings!
  2. RC4 Key-Scheduling Algorithm (KSA) & Stream Cipher Detector:
     - Detects 256-iteration identity S-box initialization patterns (`cmp reg, 0x100` / `0xff`)
  3. Structured Embedded Configuration Extractor:
     - Extracts embedded JSON/INI/KV configuration blobs, C2 URLs/IP:Port pairs, User-Agent strings,
       Mutex identifiers (`Global\\...`, `Local\\...`), and PEM/SSH cryptographic key headers.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CustomBase64Finding:
    file_offset: str
    alphabet: str
    is_non_standard: bool
    decoded_samples: List[str] = field(default_factory=list)


@dataclass
class ConfigAndCryptoReport:
    custom_base64_tables: List[CustomBase64Finding] = field(default_factory=list)
    rc4_ksa_candidates: List[str] = field(default_factory=list)
    c2_endpoints: List[str] = field(default_factory=list)
    mutex_names: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    embedded_json_configs: List[str] = field(default_factory=list)
    crypto_key_headers: List[str] = field(default_factory=list)


class ConfigAndCryptoExtractorEngine:
    """
    Extracts custom Base64 alphabets (and decodes custom-encoded payloads), RC4 KSA loops,
    mutexes, User-Agents, C2 endpoints, and embedded JSON configs from binary buffers.
    """

    STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    URLSAFE_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    C2_URL_RE = re.compile(rb"https?://[a-zA-Z0-9._\-]+(?::\d{1,5})?(?:/[a-zA-Z0-9._/\-?&%=]*)?")
    IP_PORT_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b")
    MUTEX_RE = re.compile(rb"(?:Global|Local)\\[A-Za-z0-9_\-\{\}]{4,64}")
    UA_RE = re.compile(rb"Mozilla/[45]\.0 \([^)\r\n]{5,120}\)[A-Za-z0-9 /._\-]{0,80}")
    JSON_CFG_RE = re.compile(rb"\{\s*\"[a-zA-Z0-9_]+\"\s*:\s*[^\}]{4,256}\}")
    PEM_KEY_RE = re.compile(rb"-----BEGIN [A-Z0-9 ]+ KEY-----")
    B64_TOKEN_RE = re.compile(rb"[A-Za-z0-9+/=\-_]{12,128}")

    @classmethod
    def decode_with_custom_alphabet(cls, encoded_str: str, custom_alphabet: str) -> Optional[str]:
        if len(custom_alphabet) != 64:
            return None
        trans = str.maketrans(custom_alphabet, cls.STANDARD_B64)
        std_b64 = encoded_str.translate(trans)
        pad = (4 - (len(std_b64) % 4)) % 4
        std_b64 += "=" * pad
        try:
            raw = base64.b64decode(std_b64, validate=False)
            if raw and all(0x20 <= b <= 0x7E for b in raw):
                return raw.decode("ascii")
        except Exception:
            return None
        return None

    def extract_all(self, binary_bytes: bytes) -> ConfigAndCryptoReport:
        b64_findings: List[CustomBase64Finding] = []
        n = len(binary_bytes)

        # 1. Scan for 64-byte unique printable character runs containing A-Z, a-z, 0-9
        pos = 0
        while pos <= n - 64:
            window = binary_bytes[pos : pos + 64]
            if len(set(window)) == 64 and all(0x21 <= b <= 0x7E for b in window):
                s_alpha = window.decode("ascii", errors="ignore")
                has_upper = sum(1 for c in s_alpha if "A" <= c <= "Z") == 26
                has_lower = sum(1 for c in s_alpha if "a" <= c <= "z") == 26
                has_digit = sum(1 for c in s_alpha if "0" <= c <= "9") == 10
                if has_upper and has_lower and has_digit:
                    is_custom = s_alpha not in (self.STANDARD_B64, self.URLSAFE_B64)
                    decoded_hits: List[str] = []
                    if is_custom:
                        for m_tok in self.B64_TOKEN_RE.finditer(binary_bytes):
                            tok_s = m_tok.group(0).decode("ascii", errors="ignore")
                            if tok_s == s_alpha:
                                continue
                            dec = self.decode_with_custom_alphabet(tok_s, s_alpha)
                            if dec and len(dec) >= 4 and dec not in decoded_hits:
                                decoded_hits.append(dec)
                    b64_findings.append(
                        CustomBase64Finding(
                            file_offset=hex(pos),
                            alphabet=s_alpha,
                            is_non_standard=is_custom,
                            decoded_samples=decoded_hits[:10],
                        )
                    )
                    pos += 64
                    continue
            pos += 1

        # 2. Scan for RC4 256-byte KSA loop signatures (`3D 00 01 00 00` cmp eax, 256 or `81 F9 00 01 00 00` cmp ecx, 256)
        rc4_hits: List[str] = []
        for pat, desc in [
            (b"\x3d\x00\x01\x00\x00", "RC4 KSA 256-byte loop (cmp eax, 0x100)"),
            (b"\x81\xf9\x00\x01\x00\x00", "RC4 KSA 256-byte loop (cmp ecx, 0x100)"),
            (b"\x81\xfe\x00\x01\x00\x00", "RC4 KSA 256-byte loop (cmp esi, 0x100)"),
        ]:
            idx = binary_bytes.find(pat)
            if idx != -1:
                rc4_hits.append(f"{desc} @ {hex(idx)}")

        # 3. Extract C2 URLs, IP:Ports, Mutexes, User-Agents, JSON Configs, and PEM Keys
        c2_list = [m.group(0).decode("ascii", errors="ignore") for m in self.C2_URL_RE.finditer(binary_bytes)]
        for m_ip in self.IP_PORT_RE.finditer(binary_bytes):
            s_ip = m_ip.group(0).decode("ascii", errors="ignore")
            if s_ip not in c2_list:
                c2_list.append(s_ip)

        mutexes = list(dict.fromkeys(m.group(0).decode("ascii", errors="ignore") for m in self.MUTEX_RE.finditer(binary_bytes)))
        uas = list(dict.fromkeys(m.group(0).decode("ascii", errors="ignore") for m in self.UA_RE.finditer(binary_bytes)))
        jsons = list(dict.fromkeys(m.group(0).decode("ascii", errors="ignore") for m in self.JSON_CFG_RE.finditer(binary_bytes)))
        pems = list(dict.fromkeys(m.group(0).decode("ascii", errors="ignore") for m in self.PEM_KEY_RE.finditer(binary_bytes)))

        return ConfigAndCryptoReport(
            custom_base64_tables=b64_findings,
            rc4_ksa_candidates=rc4_hits,
            c2_endpoints=c2_list[:25],
            mutex_names=mutexes[:20],
            user_agents=uas[:10],
            embedded_json_configs=jsons[:10],
            crypto_key_headers=pems[:10],
        )
