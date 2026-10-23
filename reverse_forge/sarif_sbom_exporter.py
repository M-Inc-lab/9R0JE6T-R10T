"""
R3V3R53//F0RG3 — OASIS SARIF v2.1.0 & CycloneDX v1.5 Binary SBOM Exporter (§02.5, §19)
Exports pipeline findings to GitHub Code Scanning / SARIF v2.1.0 format and constructs
CycloneDX v1.5 Software Bill of Materials (SBOM) from discovered DLLs, ELF DT_NEEDED, Mach-O dylibs,
and runtime signature markers.
"""

import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


class SARIFExporter:
    """Serializes R3V3R53//F0RG3 findings into OASIS SARIF v2.1.0 JSON format."""

    SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

    @staticmethod
    def _cvss_to_level(score: float) -> str:
        if score >= 7.0:
            return "error"
        if score >= 4.0:
            return "warning"
        return "note"

    @classmethod
    def to_sarif(cls, pipeline_state: Dict[str, Any]) -> Dict[str, Any]:
        report_json = pipeline_state.get("report_json", {})
        findings = report_json.get("findings", [])
        artifact_name = str(pipeline_state.get("artifact", "unknown"))
        sha256 = str(pipeline_state.get("sha256", ""))

        rules_map: Dict[str, Dict[str, Any]] = {}
        results_list: List[Dict[str, Any]] = []

        for f in findings:
            fid = str(f.get("finding_id", "RF-FINDING"))
            title = str(f.get("title", "Security Finding"))
            cvss = float(f.get("cvss_score", 5.0))
            cwe = str(f.get("cwe_id", "CWE-693"))
            what = str(f.get("what", ""))
            why = str(f.get("why", ""))
            rem = str(f.get("remediation", ""))
            fn_sym = str(f.get("function_symbol", "unknown"))
            addr = str(f.get("address_or_offset", "0x0"))

            if fid not in rules_map:
                rules_map[fid] = {
                    "id": fid,
                    "name": re.sub(r"[^A-Za-z0-9]", "", title)[:64] or fid,
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": f"{what} {why}".strip() or title},
                    "help": {"text": rem, "markdown": rem},
                    "properties": {
                        "tags": ["security", "binary-analysis", cwe],
                        "security-severity": f"{cvss:.1f}",
                    },
                }

            results_list.append({
                "ruleId": fid,
                "level": cls._cvss_to_level(cvss),
                "message": {"text": f"[{cwe}] {title}: {what} (Location: {fn_sym} @ {addr})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_name},
                        },
                        "logicalLocations": [
                            {
                                "name": fn_sym,
                                "FullyQualifiedName": f"{artifact_name}!{fn_sym}@{addr}",
                                "kind": "function",
                            }
                        ],
                    }
                ],
                "fingerprints": {
                    "primaryLocationLineHash": f"{sha256[:16]}:{fid}:{addr}",
                },
            })

        return {
            "$schema": cls.SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "R3V3R53//F0RG3",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/M-Inc-lab/9R0JE6T-R10T",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "artifacts": [
                        {
                            "location": {"uri": artifact_name},
                            "hashes": {"sha-256": sha256} if sha256 else {},
                        }
                    ],
                    "results": results_list,
                }
            ],
        }


class CycloneDXExporter:
    """Builds a CycloneDX v1.5 Software Bill of Materials (SBOM) from binary dependencies & findings."""

    @staticmethod
    def _extract_cwe_int(cwe_str: str) -> List[int]:
        m = re.search(r"CWE-(\d+)", str(cwe_str), re.IGNORECASE)
        return [int(m.group(1))] if m else []

    @classmethod
    def to_cyclonedx(
        cls,
        pipeline_state: Dict[str, Any],
        static_metadata: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        static_metadata = static_metadata or {}
        report_json = pipeline_state.get("report_json", {})
        findings = report_json.get("findings", [])
        artifact_name = str(pipeline_state.get("artifact", "unknown"))
        sha256 = str(pipeline_state.get("sha256", ""))
        root_ref = f"pkg:generic/{os.path.basename(artifact_name)}@{sha256[:12] or '1.0.0'}"

        # Collect linked libraries across ELF, Mach-O, and PE
        dep_names: List[str] = []
        for lib in static_metadata.get("shared_libraries", []):
            dep_names.append(str(lib))
        for dylib in static_metadata.get("dylibs", []):
            dep_names.append(str(dylib))
        for dll_obj in static_metadata.get("imported_dlls", []):
            if isinstance(dll_obj, dict) and dll_obj.get("dll"):
                dep_names.append(str(dll_obj["dll"]))
            elif isinstance(dll_obj, str):
                dep_names.append(dll_obj)

        # Also include runtime/crypto markers from signature_scan
        sig_matches = static_metadata.get("signature_scan", {}).get("matches", [])
        for sm in sig_matches:
            if sm.get("category") in ("Compiler & Runtime Identification", "Cryptographic Constant"):
                dep_names.append(str(sm.get("name")))

        dep_names = list(dict.fromkeys(dep_names))

        components: List[Dict[str, Any]] = []
        dep_refs: List[str] = []
        for dname in dep_names:
            clean_name = os.path.basename(dname.replace("\\", "/")) or dname
            bref = f"pkg:generic/{clean_name}"
            dep_refs.append(bref)
            components.append({
                "type": "library",
                "bom-ref": bref,
                "name": dname,
                "purl": bref,
            })

        vulnerabilities: List[Dict[str, Any]] = []
        for f in findings:
            fid = str(f.get("finding_id", "RF-VULN"))
            cvss = float(f.get("cvss_score", 5.0))
            sev = "critical" if cvss >= 9.0 else ("high" if cvss >= 7.0 else ("medium" if cvss >= 4.0 else "low"))
            vulnerabilities.append({
                "id": fid,
                "source": {"name": "R3V3R53//F0RG3"},
                "ratings": [
                    {
                        "score": cvss,
                        "severity": sev,
                        "method": "CVSSv4",
                    }
                ],
                "cwes": cls._extract_cwe_int(f.get("cwe_id", "")),
                "description": f"{f.get('title', '')}: {f.get('what', '')}",
                "recommendation": str(f.get("remediation", "")),
                "affects": [{"ref": root_ref}],
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"vendor": "M-Inc-lab", "name": "R3V3R53//F0RG3", "version": "1.0.0"}],
                "component": {
                    "type": "application",
                    "bom-ref": root_ref,
                    "name": artifact_name,
                    "hashes": [{"alg": "SHA-256", "content": sha256}] if sha256 else [],
                },
            },
            "components": components,
            "dependencies": [
                {
                    "ref": root_ref,
                    "dependsOn": dep_refs,
                }
            ],
            "vulnerabilities": vulnerabilities,
        }
