"""
R3V3R53//F0RG3 — Zero-Day Heuristic Anomaly Clustering Engine (§27)
Vectorizes disassembled function metrics (cyclomatic complexity, memory store density,
lack of validation guards, unchecked pointer math) to discover novel zero-day vulnerability candidates.
"""

from dataclasses import dataclass, field
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class FunctionMetricVector:
    name: str
    instruction_count: int
    cyclomatic_complexity: int
    memory_write_ratio: float
    guard_density: float
    has_unvalidated_input: bool
    has_dangerous_sink: bool
    anomaly_score: float = 0.0


@dataclass
class ZeroDayCandidate:
    function_name: str
    anomaly_score: float
    cluster_category: str       # UNGUARDED_MEMORY_WRITER, COMPLEX_INPUT_PARSER, DANGEROUS_SINK_CONSUMER, NORMAL
    risk_factors: List[str]
    estimated_cvss: float
    confidence: str            # CONFIRMED, HIGH_PROBABILITY, SUSPICIOUS


class ZeroDayClusterEngine:
    """Detects anomalous, high-risk code patterns that indicate zero-day vulnerability vectors."""

    INPUT_SOURCES = {"recv", "read", "fgets", "fread", "WSARecv", "InternetReadFile", "scanf", "getenv"}
    DANGEROUS_SINKS = {"memcpy", "memmove", "strcpy", "strcat", "sprintf", "system", "popen", "WinExec"}

    GUARD_MNEMONICS = {"cmp", "test", "cbnz", "cbz"}
    WRITE_MNEMONICS = {"mov", "str", "sw", "movzx", "movsx"}

    def __init__(self, anomaly_threshold: float = 0.65):
        self.anomaly_threshold = anomaly_threshold

    def extract_function_metrics(
        self,
        func_name: str,
        instructions: List[str],
        called_functions: Optional[Set[str]] = None,
    ) -> FunctionMetricVector:
        """Computes structural and algorithmic metrics for a single function."""
        clean_lines = [l.strip() for l in instructions if l.strip() and not l.strip().startswith((";", "#"))]
        total_ins = max(1, len(clean_lines))

        # 1. Cyclomatic complexity estimate
        branch_count = sum(
            1 for l in clean_lines
            if any(l.lower().startswith(b) for b in ("j", "b", "ret"))
        )
        cyclomatic = max(1, branch_count + 1)

        # 2. Store / memory write instruction density
        writes = 0
        for l in clean_lines:
            parts = l.split(None, 1)
            op = parts[0].lower() if parts else ""
            if op in self.WRITE_MNEMONICS and ("[" in l or "(" in l or "str" in op or "sw" in op):
                writes += 1
        write_ratio = round(writes / total_ins, 3)

        # 3. Guard / bounds-check density
        guards = sum(1 for l in clean_lines if l.split()[0].lower() in self.GUARD_MNEMONICS) if clean_lines else 0
        guard_ratio = round(guards / total_ins, 3)

        # 4. Input sources and dangerous sinks
        calls = called_functions or set()
        for l in clean_lines:
            if l.lower().startswith(("call", "bl", "jal")):
                parts = l.split()
                if len(parts) > 1:
                    calls.add(parts[1].strip().lstrip("_@"))

        has_input = any(src in calls for src in self.INPUT_SOURCES)
        has_sink = any(snk in calls for snk in self.DANGEROUS_SINKS)

        # 5. Anomaly score calculation
        # High write ratio + low guard density + input source = high anomaly
        score = 0.0
        if write_ratio > 0.30:
            score += 0.35
        if has_input and guard_ratio < 0.05:
            score += 0.30
        if has_sink:
            score += 0.20
        if cyclomatic > 8:
            score += 0.15

        normalized_score = round(min(1.0, score), 3)

        return FunctionMetricVector(
            name=func_name,
            instruction_count=total_ins,
            cyclomatic_complexity=cyclomatic,
            memory_write_ratio=write_ratio,
            guard_density=guard_ratio,
            has_unvalidated_input=has_input,
            has_dangerous_sink=has_sink,
            anomaly_score=normalized_score,
        )

    def analyze_functions(
        self,
        functions_dict: Dict[str, List[str]],
        call_graph: Optional[Dict[str, Set[str]]] = None,
    ) -> List[ZeroDayCandidate]:
        """Analyzes all functions in a binary and clusters anomalies exceeding threshold."""
        candidates: List[ZeroDayCandidate] = []
        calls_map = call_graph or {}

        for func_name, code in functions_dict.items():
            called = calls_map.get(func_name, set())
            vec = self.extract_function_metrics(func_name, code, called)

            if vec.anomaly_score >= self.anomaly_threshold:
                risk_factors: List[str] = []
                cluster = "SUSPICIOUS_HEURISTIC"

                if vec.memory_write_ratio > 0.30 and vec.guard_density < 0.05:
                    cluster = "UNGUARDED_MEMORY_WRITER"
                    risk_factors.append(f"High memory write density ({vec.memory_write_ratio:.1%}) with zero or minimal bounds checks ({vec.guard_density:.1%})")

                if vec.has_unvalidated_input:
                    risk_factors.append("Ingests untrusted external input directly without sanitization")

                if vec.has_dangerous_sink:
                    risk_factors.append("Transfers control or data into high-impact dangerous API sink")

                if vec.cyclomatic_complexity > 8:
                    risk_factors.append(f"Elevated control-flow complexity (cyclomatic: {vec.cyclomatic_complexity})")

                # CVSS estimate based on factors
                cvss = 5.0
                if "UNGUARDED_MEMORY_WRITER" in cluster:
                    cvss += 2.5
                if vec.has_unvalidated_input:
                    cvss += 1.0
                if vec.has_dangerous_sink:
                    cvss += 1.3

                candidates.append(ZeroDayCandidate(
                    function_name=func_name,
                    anomaly_score=vec.anomaly_score,
                    cluster_category=cluster,
                    risk_factors=risk_factors,
                    estimated_cvss=round(min(9.8, cvss), 1),
                    confidence="HIGH_PROBABILITY" if vec.anomaly_score >= 0.8 else "SUSPICIOUS",
                ))

        # Sort by anomaly score descending
        candidates.sort(key=lambda c: c.anomaly_score, reverse=True)
        return candidates
