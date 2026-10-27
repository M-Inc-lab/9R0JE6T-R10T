"""
R3V3R53//F0RG3 — Phase 77: Automated YARA Rule, SIGMA Detection & STIX 2.1 Threat-Intel Generator
(`yara_sigma_ioc_generator.py`)
Amplifies Reverse-Forge's core superpower as an automated first-response triage engine by
converting binary triage findings into immediately deployable detection artifacts:
  1. High-Specificity YARA Rule Synthesizer (`generate_yara_rule`):
     - Filters out generic OS/CRT strings (`kernel32.dll`, `GetProcAddress`, `.text`, `MZ`)
     - Selects high-specificity ASCII/UTF-16 strings, C2 indicators, mutexes, and masked entry-point
       opcode sequences (wildcarding relocatable displacements with `??`)
  2. SIGMA Behavioral Detection YAML Generator (`generate_sigma_rule`)
  3. STIX 2.1 Threat Intelligence Bundle Exporter (`generate_stix21_bundle`)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import re
import uuid
from typing import Any, Dict, List, Optional


@dataclass
class DetectionArtifactsBundle:
    rule_identifier: str
    binary_sha256: str
    binary_format: str
    yara_rule_source: str
    sigma_rule_yaml: str
    stix21_bundle_json: Dict[str, Any]
    high_specificity_strings: List[str] = field(default_factory=list)
    masked_opcode_pattern: str = ""


class YaraSigmaIOCGenerator:
    """
    Synthesizes production-ready YARA rules, SIGMA YAML rules, and STIX 2.1 JSON bundles
    from first-response binary triage data.
    """

    GENERIC_NOISE_STRINGS = {
        "kernel32.dll", "ntdll.dll", "user32.dll", "msvcrt.dll", "advapi32.dll",
        "ws2_32.dll", "libc.so.6", "ld-linux-x86-64.so.2", "libsystem.b.dylib",
        "getprocaddress", "loadlibrarya", "loadlibraryw", "virtualalloc", "exitprocess",
        ".text", ".rdata", ".data", ".pdata", ".reloc", ".rsrc", ".bss", "this program cannot be run in dos mode",
    }

    @staticmethod
    def _escape_yara_str(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")

    @staticmethod
    def _mask_entry_opcodes(code_slice: bytes, max_len: int = 16) -> str:
        """
        Convert an entry-point instruction slice into a YARA hex pattern, wildcarding
        relative call/jump displacements (`E8 ?? ?? ?? ??`, `E9 ?? ?? ?? ??`).
        """
        window = code_slice[:max_len]
        if not window:
            return "55 48 89 E5"
        tokens: List[str] = []
        i = 0
        n = len(window)
        while i < n:
            b = window[i]
            if b in (0xE8, 0xE9) and i + 5 <= n:
                tokens.extend([f"{b:02X}", "??", "??", "??", "??"])
                i += 5
            else:
                tokens.append(f"{b:02X}")
                i += 1
        return " ".join(tokens)

    def generate_all(
        self,
        binary_bytes: bytes,
        dossier: Dict[str, Any],
        code_slice: bytes = b"",
    ) -> DetectionArtifactsBundle:
        sha256 = dossier.get("sha256") or hashlib.sha256(binary_bytes).hexdigest()
        fmt = str(dossier.get("format", "PE"))
        arch = str(dossier.get("architecture", "x64"))
        size_bytes = int(dossier.get("size_bytes", len(binary_bytes)))
        raw_name = str(dossier.get("artifact", "sample")).replace("\\", "/").split("/")[-1]
        safe_id = re.sub(r"[^a-zA-Z0-9_]", "_", raw_name.split(".")[0]) or "Suspicious_Artifact"
        rule_name = f"RF_Triage_{safe_id}_{sha256[:8]}"

        # Collect high-specificity strings (C2 endpoints, mutexes, deobfuscated strings, non-noise strings)
        candidates: List[str] = []
        cfg_crypto = dossier.get("config_and_crypto", {})
        for u in cfg_crypto.get("c2_endpoints", []):
            if u not in candidates:
                candidates.append(u)
        for m in cfg_crypto.get("mutex_names", []):
            if m not in candidates:
                candidates.append(m)
        for b64_f in cfg_crypto.get("custom_base64_tables", []):
            for dec in b64_f.get("decoded_samples", []):
                if dec not in candidates:
                    candidates.append(dec)

        deob = dossier.get("deobfuscated_strings", {})
        for rec in deob.get("recovered_strings", []):
            v = rec.get("plaintext", "")
            if len(v) >= 4 and v.lower() not in self.GENERIC_NOISE_STRINGS and v not in candidates:
                candidates.append(v)

        cat_strs = dossier.get("categorized_strings", {})
        for cat in ("urls", "ips", "registry", "paths", "high_interest"):
            for s in cat_strs.get(cat, []):
                if isinstance(s, str) and len(s) >= 5 and s.lower() not in self.GENERIC_NOISE_STRINGS and s not in candidates:
                    candidates.append(s)

        # Fallback: extract printable ASCII strings >= 6 chars from binary_bytes
        if len(candidates) < 4:
            for m_str in re.finditer(rb"[\x20-\x7e]{6,64}", binary_bytes):
                s_val = m_str.group(0).decode("ascii", errors="ignore").strip()
                if s_val.lower() not in self.GENERIC_NOISE_STRINGS and s_val not in candidates:
                    candidates.append(s_val)
                if len(candidates) >= 8:
                    break

        selected_strs = candidates[:8]
        op_hex = self._mask_entry_opcodes(code_slice or binary_bytes[:16])
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # 1. Build YARA Rule
        yara_lines = [
            f"rule {rule_name} {{",
            "    meta:",
            f'        author = "R3V3R53//F0RG3 Automated Layer-1 Triage"',
            f'        date = "{now_iso}"',
            f'        sha256 = "{sha256}"',
            f'        format = "{fmt} ({arch})"',
            f'        risk_rating = "{dossier.get("vulnerability_risk_rating", "TRIAGED")}"',
            "    strings:",
        ]
        if fmt == "PE":
            yara_lines.append("        $magic = { 4D 5A }")
        elif fmt == "ELF":
            yara_lines.append("        $magic = { 7F 45 4C 46 }")
        elif fmt == "WASM":
            yara_lines.append("        $magic = { 00 61 73 6D }")
        elif fmt == "Android DEX":
            yara_lines.append("        $magic = { 64 65 78 0A }")

        yara_lines.append(f"        $ep_opcodes = {{ {op_hex} }}")
        for idx, s_val in enumerate(selected_strs):
            yara_lines.append(f'        $s{idx+1} = "{self._escape_yara_str(s_val)}" ascii wide')

        max_sz = max(4096, size_bytes * 2)
        cond_parts = [f"filesize < {max_sz}"]
        if any("$magic" in ln for ln in yara_lines):
            cond_parts.append("$magic at 0")
        if selected_strs:
            cond_parts.append(f"($ep_opcodes or {max(1, min(2, len(selected_strs)))} of ($s*))")
        else:
            cond_parts.append("$ep_opcodes")

        yara_lines.extend([
            "    condition:",
            "        " + " and ".join(cond_parts),
            "}",
        ])
        yara_src = "\n".join(yara_lines)

        # 2. Build SIGMA YAML Detection Rule
        caps = [c.get("name", "Binary Execution") for c in dossier.get("capabilities", [])[:4]]
        sigma_lines = [
            f"title: R3V3R53-F0RG3 Automated Detection for {raw_name}",
            f"id: {uuid.uuid5(uuid.NAMESPACE_DNS, sha256)}",
            "status: experimental",
            f"description: Auto-synthesized Layer-1 triage detection rule for {fmt} artifact ({sha256[:16]})",
            "author: R3V3R53//F0RG3",
            f"date: {now_iso}",
            "logsource:",
            "    category: process_creation",
            f"    product: {'windows' if fmt == 'PE' else 'linux'}",
            "detection:",
            "    selection_hash:",
            f"        Hashes|contains: '{sha256}'",
        ]
        if selected_strs:
            sigma_lines.append("    selection_indicators:")
            sigma_lines.append("        CommandLine|contains:")
            for s_val in selected_strs[:4]:
                sigma_lines.append(f"            - '{s_val}'")
            sigma_lines.append("    condition: selection_hash or selection_indicators")
        else:
            sigma_lines.append("    condition: selection_hash")
        if caps:
            sigma_lines.append("tags:")
            for c_name in caps:
                slug = re.sub(r"[^a-z0-9_]", "_", c_name.lower())
                sigma_lines.append(f"    - attack.{slug[:32]}")
        sigma_yaml = "\n".join(sigma_lines)

        # 3. Build STIX 2.1 Threat-Intel Bundle
        ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, 'ind:' + sha256)}"
        mal_id = f"malware--{uuid.uuid5(uuid.NAMESPACE_URL, 'mal:' + sha256)}"
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, 'bundle:' + sha256)}",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": datetime.now(timezone.utc).isoformat(),
                    "name": f"File Hash & YARA Indicator for {raw_name}",
                    "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
                    "pattern_type": "stix",
                },
                {
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": mal_id,
                    "name": raw_name,
                    "is_family": False,
                    "capabilities": [c.get("name", "") for c in dossier.get("capabilities", [])[:10]],
                },
            ],
        }

        bundle = DetectionArtifactsBundle(
            rule_identifier=rule_name,
            binary_sha256=sha256,
            binary_format=fmt,
            yara_rule_source=yara_src,
            sigma_rule_yaml=sigma_yaml,
            stix21_bundle_json=stix_bundle,
            high_specificity_strings=selected_strs,
            masked_opcode_pattern=op_hex,
        )

        ok, validation_errs = self.validate_bundle_quality(bundle)
        if not ok:
            # Attach validation warnings into bundle metadata
            bundle.stix21_bundle_json["validation_warnings"] = validation_errs

        return bundle

    @classmethod
    def validate_bundle_quality(cls, bundle: DetectionArtifactsBundle) -> Tuple[bool, List[str]]:
        """Rigorous syntax and semantic quality gate for generated detection artifacts."""
        errors: List[str] = []

        # 1. YARA Syntax Validation
        yara = bundle.yara_rule_source.strip()
        if not yara.startswith("rule "):
            errors.append("YARA rule must begin with 'rule <identifier>' header")
        if yara.count("{") != yara.count("}") or "condition:" not in yara:
            errors.append("YARA rule has unbalanced braces or missing 'condition:' section")

        # 2. SIGMA Structure Validation
        sigma = bundle.sigma_rule_yaml
        required_sigma_keys = ("title:", "logsource:", "detection:", "condition:", "level:")
        for rk in required_sigma_keys:
            if rk not in sigma:
                errors.append(f"SIGMA YAML missing required top-level attribute: {rk}")

        # 3. STIX 2.1 Specification Validation
        stix = bundle.stix21_bundle_json
        if not isinstance(stix, dict) or stix.get("type") != "bundle":
            errors.append("STIX artifact must be a JSON object with type 'bundle'")
        if not isinstance(stix.get("objects"), list) or len(stix["objects"]) == 0:
            errors.append("STIX bundle must contain at least one valid SDO object")

        return len(errors) == 0, errors
