"""
R3V3R53//F0RG3 — Dual Executive & Technical Reporting Engine (§06, §18, §19)
Generates high-fidelity structured reports (JSON + Markdown) with CVSS 4.0, CWE taxonomy, and 5WH.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    finding_id: str
    title: str
    vulnerability_class: str
    confidence: str  # Confirmed, Probable, Possible, Not Confirmed
    cvss_score: float
    cwe_id: str
    function_symbol: str
    address_or_offset: str
    what: str
    why: str
    where: str
    when: str
    how: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutiveSummary:
    target_name: str
    sha256: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_posture: str
    key_recommendation: str


class ReportGenerator:
    """Produces dual-target reports: Executive Summary and Deep Technical Triage."""

    def __init__(self, target_name: str, sha256: str):
        self.target_name = target_name
        self.sha256 = sha256
        self.findings: List[Finding] = []
        self.non_findings: List[str] = []
        self.blockers: List[str] = []
        self.metadata: Dict[str, Any] = {}

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_non_finding(self, note: str) -> None:
        self.non_findings.append(note)

    def add_blocker(self, blocker: str) -> None:
        self.blockers.append(blocker)

    def generate_executive_summary(self) -> ExecutiveSummary:
        crit = sum(1 for f in self.findings if f.cvss_score >= 9.0)
        high = sum(1 for f in self.findings if 7.0 <= f.cvss_score < 9.0)
        med = sum(1 for f in self.findings if 4.0 <= f.cvss_score < 7.0)
        low = sum(1 for f in self.findings if f.cvss_score < 4.0)

        if crit > 0:
            posture = "CRITICAL RISK - Imminent Exploitability Potential"
        elif high > 0:
            posture = "HIGH RISK - Multiple High Severity Flaws Detected"
        elif med > 0:
            posture = "MODERATE RISK - Security Hygiene & Defense-in-Depth Required"
        else:
            posture = "SATISFACTORY - Baseline Hardening Mitigations Active"

        recs = []
        if crit + high > 0:
            recs.append("Immediate remediation required for highest scoring memory/logic flaws.")
        if any("DEP" in f.title or "ASLR" in f.title for f in self.findings):
            recs.append("Enable modern toolchain binary mitigations (PIE/ASLR, NX/DEP, RELRO/SafeSEH).")
        if not recs:
            recs.append("Maintain continuous static analysis and runtime regression monitoring.")

        return ExecutiveSummary(
            target_name=self.target_name,
            sha256=self.sha256,
            total_findings=len(self.findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            overall_posture=posture,
            key_recommendation=" ".join(recs),
        )

    def to_json(self) -> Dict[str, Any]:
        exec_sum = asdict(self.generate_executive_summary())
        return {
            "schema_version": "1.0.0",
            "generation_utc": datetime.now(timezone.utc).isoformat(),
            "target": {
                "name": self.target_name,
                "sha256": self.sha256,
            },
            "executive_summary": exec_sum,
            "findings": [asdict(f) for f in self.findings],
            "non_findings": self.non_findings,
            "blockers": self.blockers,
            "metadata": self.metadata,
        }

    def to_markdown(self) -> str:
        exec_sum = self.generate_executive_summary()
        lines = [
            f"# R3V3R53//F0RG3 Security Audit Report",
            f"",
            f"**Target:** `{self.target_name}`  ",
            f"**SHA-256:** `{self.sha256}`  ",
            f"**Audit Date (UTC):** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Overall Posture:** {exec_sum.overall_posture}  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"| Metric | Count |",
            f"| :--- | :--- |",
            f"| Total Hypotheses & Findings | {exec_sum.total_findings} |",
            f"| Critical (CVSS 9.0 - 10.0) | {exec_sum.critical_count} |",
            f"| High (CVSS 7.0 - 8.9) | {exec_sum.high_count} |",
            f"| Medium (CVSS 4.0 - 6.9) | {exec_sum.medium_count} |",
            f"| Low (CVSS 0.1 - 3.9) | {exec_sum.low_count} |",
            f"",
            f"**Core Recommendation:** {exec_sum.key_recommendation}",
            f"",
            f"---",
            f"",
            f"## Detailed Technical Findings",
            f"",
        ]

        if not self.findings:
            lines.append("_No confirmed or probable vulnerability findings identified._\n")
        else:
            for f in self.findings:
                lines.extend([
                    f"### [{f.finding_id}] {f.title}",
                    f"",
                    f"- **Vulnerability Class:** {f.vulnerability_class}",
                    f"- **Confidence Level:** {f.confidence}",
                    f"- **CVSS 4.0 Score:** `{f.cvss_score:.1f}`",
                    f"- **CWE:** {f.cwe_id}",
                    f"- **Location:** `{f.function_symbol}` @ `{f.address_or_offset}`",
                    f"",
                    f"#### 5WH Analysis",
                    f"- **What:** {f.what}",
                    f"- **Why:** {f.why}",
                    f"- **Where:** {f.where}",
                    f"- **When:** {f.when}",
                    f"- **How:** {f.how}",
                    f"",
                    f"#### Defensive Remediation",
                    f"{f.remediation}",
                    f"",
                    f"---",
                    f"",
                ])

        if self.non_findings:
            lines.extend([
                f"## Non-Finding Determinations",
                f"",
            ])
            for nf in self.non_findings:
                lines.append(f"- {nf}")
            lines.append("")

        if self.blockers:
            lines.extend([
                f"## Blockers & Coverage Limits",
                f"",
            ])
            for blk in self.blockers:
                lines.append(f"- {blk}")
            lines.append("")

        return "\n".join(lines)
