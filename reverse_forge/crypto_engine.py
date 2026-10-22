"""
R3V3R53//F0RG3 — Cryptographic Primitives, Hardcoded Secrets & Key Material Discovery Engine (§14)
Identifies standard cryptographic constant tables, weak hashes/ciphers,
and scans for hardcoded API keys, JWTs, private keys, and entropy-concentrated blobs.
"""

import math
import re
import struct
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CryptoPrimitiveMatch:
    primitive_name: str
    algorithm_family: str
    offset: int
    confidence: str  # CONFIRMED, PROBABLE, POSSIBLE
    description: str


@dataclass
class SecretFinding:
    secret_type: str
    matched_value_masked: str
    offset: int
    entropy: float
    confidence: str
    description: str


class CryptoSecretEngine:
    """Detects cryptographic algorithms and embedded secret material."""

    # Cryptographic Constant S-Boxes & Initialization Vectors
    CRYPTO_SIGNATURES: Dict[str, Tuple[str, bytes, str]] = {
        "MD5_IV": (
            "MD5 Hash (Weak/Broken)",
            struct.pack("<IIII", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476),
            "MD5 initialization constants detected. High risk of collision attacks (CWE-328)."
        ),
        "SHA1_IV": (
            "SHA-1 Hash (Weak/Deprecated)",
            struct.pack(">IIIII", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0),
            "SHA-1 initialization vector detected. Prone to practical collision attacks (CWE-328)."
        ),
        "SHA256_IV": (
            "SHA-256 Hash",
            struct.pack(">IIII", 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A),
            "Standard SHA-256 state initialization constants detected."
        ),
        "AES_RCON": (
            "AES Symmetric Cipher",
            bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]),
            "AES Rijndael round constant (Rcon) table detected."
        ),
        "AES_SBOX_PREFIX": (
            "AES Symmetric Cipher",
            bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01]),
            "AES Forward Substitution Box (S-Box) byte prefix detected."
        ),
    }

    SECRET_REGEXES: Dict[str, Tuple[re.Pattern, str]] = {
        "RSA_PRIVATE_KEY": (
            re.compile(rb"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
            "Embedded OpenSSL / PEM Private Key header (CWE-312/CWE-798)."
        ),
        "AWS_ACCESS_KEY": (
            re.compile(rb"\b(AKIA[0-9A-Z]{16})\b"),
            "Hardcoded AWS Access Key ID detected (CWE-798)."
        ),
        "GENERIC_API_KEY": (
            re.compile(rb"(?i)(?:api_key|apikey|secret_key|access_token)[\s=:\'\"]{1,5}([0-9a-zA-Z\-_]{20,64})"),
            "Hardcoded secret token or credential assignment discovered (CWE-798)."
        ),
        "JWT_BEARER_TOKEN": (
            re.compile(rb"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
            "Hardcoded JSON Web Token (JWT) session credential found in binary (CWE-798)."
        ),
    }

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def scan_crypto_primitives(self, data: bytes) -> List[CryptoPrimitiveMatch]:
        matches: List[CryptoPrimitiveMatch] = []
        for name, (algo, sig, desc) in self.CRYPTO_SIGNATURES.items():
            idx = 0
            while (idx := data.find(sig, idx)) != -1:
                matches.append(CryptoPrimitiveMatch(
                    primitive_name=name,
                    algorithm_family=algo,
                    offset=idx,
                    confidence="CONFIRMED",
                    description=desc
                ))
                idx += len(sig)
        return matches

    def scan_hardcoded_secrets(self, data: bytes) -> List[SecretFinding]:
        findings: List[SecretFinding] = []
        for sec_type, (pat, desc) in self.SECRET_REGEXES.items():
            for m in pat.finditer(data):
                raw_match = m.group(1) if m.groups() else m.group(0)
                offset = m.start()
                ent = self.calculate_shannon_entropy(raw_match)
                # Mask secret value to prevent credential leaking in logs
                masked = raw_match[:4].decode("ascii", errors="ignore") + "..." + raw_match[-4:].decode("ascii", errors="ignore")
                findings.append(SecretFinding(
                    secret_type=sec_type,
                    matched_value_masked=masked,
                    offset=offset,
                    entropy=round(ent, 2),
                    confidence="CONFIRMED" if ent > 3.0 else "PROBABLE",
                    description=desc
                ))
        return findings

    def full_crypto_audit(self, data: bytes) -> Dict[str, Any]:
        primitives = self.scan_crypto_primitives(data)
        secrets = self.scan_hardcoded_secrets(data)
        weak_ciphers = [p for p in primitives if "Weak" in p.algorithm_family]

        return {
            "primitives_detected": [asdict(p) for p in primitives],
            "secrets_detected": [asdict(s) for s in secrets],
            "weak_algorithms_count": len(weak_ciphers),
            "high_risk_secrets_count": len(secrets),
            "crypto_hygiene_status": "VULNERABLE" if weak_ciphers or secrets else "ACCEPTABLE"
        }
