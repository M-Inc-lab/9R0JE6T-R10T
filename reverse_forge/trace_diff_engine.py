"""
R3V3R53//F0RG3 — Phase 40: Differential Execution Trace & Crash Root-Cause Aligner
Modeled on Tenet / Lighthouse differential trace analysis.
Compares two dynamic execution traces (a baseline/benign trace vs. a failing/divergent trace)
using Longest Common Subsequence (LCS) alignment and pinpoints:
  1. The exact last common instruction address (`divergence_point_address`)
  2. The first divergent target branch address (`baseline_next_addr` vs. `divergent_next_addr`)
  3. The register state delta (`register_deltas`) at the moment of divergence
  4. Unique basic blocks executed exclusively in the failing trace (`unique_divergent_addresses`)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class TraceStep:
    address: int
    mnemonic: str = ""
    registers: Dict[str, int] = field(default_factory=dict)


@dataclass
class DifferentialTraceReport:
    baseline_steps: int
    divergent_steps: int
    shared_prefix_length: int
    lcs_similarity_ratio: float
    divergence_point_address: Optional[int]
    divergence_instruction: str
    baseline_next_address: Optional[int]
    divergent_next_address: Optional[int]
    register_deltas_at_divergence: Dict[str, Tuple[Optional[int], Optional[int]]]
    unique_divergent_addresses: List[int]
    root_cause_summary: str


class TraceDiffEngine:
    """
    Aligns two instruction-level execution traces to isolate the exact branch predicate
    and register mutation responsible for a crash or behavioral divergence.
    """

    def align_and_diff_traces(
        self,
        baseline_trace: List[TraceStep],
        divergent_trace: List[TraceStep],
    ) -> DifferentialTraceReport:
        if not baseline_trace or not divergent_trace:
            return DifferentialTraceReport(
                baseline_steps=len(baseline_trace),
                divergent_steps=len(divergent_trace),
                shared_prefix_length=0,
                lcs_similarity_ratio=0.0,
                divergence_point_address=None,
                divergence_instruction="",
                baseline_next_address=None,
                divergent_next_address=None,
                register_deltas_at_divergence={},
                unique_divergent_addresses=[],
                root_cause_summary="Insufficient trace data for alignment.",
            )

        # 1. Find exact shared execution prefix and first control-flow split
        prefix_len = 0
        min_len = min(len(baseline_trace), len(divergent_trace))
        while prefix_len < min_len and baseline_trace[prefix_len].address == divergent_trace[prefix_len].address:
            prefix_len += 1

        div_idx = prefix_len - 1 if prefix_len > 0 else 0
        div_addr = baseline_trace[div_idx].address
        div_insn = baseline_trace[div_idx].mnemonic or f"insn@{hex(div_addr)}"

        base_next = baseline_trace[prefix_len].address if prefix_len < len(baseline_trace) else None
        div_next = divergent_trace[prefix_len].address if prefix_len < len(divergent_trace) else None

        # 2. Compute register state delta at the divergence point
        base_regs = baseline_trace[div_idx].registers
        div_regs = divergent_trace[div_idx].registers
        reg_deltas: Dict[str, Tuple[Optional[int], Optional[int]]] = {}
        for r_key in sorted(set(base_regs.keys()) | set(div_regs.keys())):
            b_val = base_regs.get(r_key)
            d_val = div_regs.get(r_key)
            if b_val != d_val:
                reg_deltas[r_key] = (b_val, d_val)

        # 3. Compute Longest Common Subsequence (LCS) similarity over address sequences
        seq_a = [s.address for s in baseline_trace[:256]]
        seq_b = [s.address for s in divergent_trace[:256]]
        lcs_len = self._compute_lcs_length(seq_a, seq_b)
        sim_ratio = round((2.0 * lcs_len) / max(1, len(seq_a) + len(seq_b)), 4)

        # 4. Identify addresses visited only in the divergent trace
        base_set = {s.address for s in baseline_trace}
        unique_div = sorted({s.address for s in divergent_trace if s.address not in base_set})

        delta_desc = ", ".join(
            f"{k}: {hex(v[0]) if v[0] is not None else 'None'} -> {hex(v[1]) if v[1] is not None else 'None'}"
            for k, v in reg_deltas.items()
        ) or "identical register state"

        summary = (
            f"Execution diverged after {prefix_len} shared step(s) at {hex(div_addr)} ({div_insn}): "
            f"baseline branched to {hex(base_next) if base_next else 'EXIT'}, whereas divergent trace "
            f"branched to {hex(div_next) if div_next else 'EXIT'} with register delta [{delta_desc}]."
        )

        return DifferentialTraceReport(
            baseline_steps=len(baseline_trace),
            divergent_steps=len(divergent_trace),
            shared_prefix_length=prefix_len,
            lcs_similarity_ratio=sim_ratio,
            divergence_point_address=div_addr,
            divergence_instruction=div_insn,
            baseline_next_address=base_next,
            divergent_next_address=div_next,
            register_deltas_at_divergence=reg_deltas,
            unique_divergent_addresses=unique_div,
            root_cause_summary=summary,
        )

    @staticmethod
    def _compute_lcs_length(a: List[int], b: List[int]) -> int:
        m, n = len(a), len(b)
        dp = [0] * (n + 1)
        for i in range(1, m + 1):
            prev = 0
            for j in range(1, n + 1):
                temp = dp[j]
                if a[i - 1] == b[j - 1]:
                    dp[j] = prev + 1
                else:
                    dp[j] = max(dp[j], dp[j - 1])
                prev = temp
        return dp[n]
