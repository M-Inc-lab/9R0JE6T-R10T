"""
R3V3R53//F0RG3 — SSA Intermediate Representation & Symbolic Interval Constraint Solver
Lifts operations into Static Single Assignment (SSA) form, tracks symbolic value intervals [low, high]
across arithmetic and branch guards, and mathematically verifies whether buffer operations are bounded.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SymbolicInterval:
    low: int
    high: int

    def add(self, other: "SymbolicInterval") -> "SymbolicInterval":
        return SymbolicInterval(self.low + other.low, self.high + other.high)

    def sub(self, other: "SymbolicInterval") -> "SymbolicInterval":
        return SymbolicInterval(self.low - other.high, self.high - other.low)

    def bitwise_and(self, mask: int) -> "SymbolicInterval":
        if mask >= 0:
            return SymbolicInterval(0, min(max(0, self.high), mask))
        return self

    def clamp_upper(self, max_allowed: int) -> "SymbolicInterval":
        return SymbolicInterval(self.low, min(self.high, max_allowed))

    def clamp_lower(self, min_allowed: int) -> "SymbolicInterval":
        return SymbolicInterval(max(self.low, min_allowed), self.high)

    def is_satisfiable(self) -> bool:
        return self.low <= self.high


@dataclass
class SSAOperation:
    op: str                     # INPUT, CONST, ADD, SUB, AND, ASSERT_LT, ASSERT_LE, BUFFER_WRITE
    dest: str
    src1: Optional[str] = None
    src2_or_imm: Optional[ Any ] = None
    buffer_capacity: Optional[int] = None


@dataclass
class SymbolicVerificationResult:
    sink_variable: str
    buffer_capacity: int
    computed_interval: Tuple[int, int]
    status: str                 # PROVEN_SAFE, PROVABLY_UNSAFE, UNREACHABLE_PATH
    cwe_id: Optional[str]
    proof_trace: List[str]


class SymbolicIREngine:
    """Performs abstract interpretation & interval constraint solving over SSA operations."""

    DEFAULT_UNTRUSTED_INTERVAL = SymbolicInterval(0, 0xFFFF)

    def __init__(self):
        self.env: Dict[str, SymbolicInterval] = {}
        self.trace: List[str] = []

    def evaluate_ssa_block(self, operations: List[SSAOperation]) -> List[SymbolicVerificationResult]:
        self.env = {}
        self.trace = []
        results: List[SymbolicVerificationResult] = []

        for step_idx, insn in enumerate(operations):
            op = insn.op.upper()
            if op == "INPUT":
                max_in = int(insn.src2_or_imm) if insn.src2_or_imm is not None else 0xFFFF
                self.env[insn.dest] = SymbolicInterval(0, max_in)
                self.trace.append(f"Step {step_idx}: {insn.dest} = UNTRUSTED_INPUT [0, {max_in}]")

            elif op == "CONST":
                val = int(insn.src2_or_imm or 0)
                self.env[insn.dest] = SymbolicInterval(val, val)
                self.trace.append(f"Step {step_idx}: {insn.dest} = CONST [{val}, {val}]")

            elif op == "ADD" and insn.src1:
                lhs = self.env.get(insn.src1, self.DEFAULT_UNTRUSTED_INTERVAL)
                rhs = (
                    SymbolicInterval(int(insn.src2_or_imm), int(insn.src2_or_imm))
                    if isinstance(insn.src2_or_imm, int)
                    else self.env.get(str(insn.src2_or_imm), SymbolicInterval(0, 0))
                )
                self.env[insn.dest] = lhs.add(rhs)
                self.trace.append(f"Step {step_idx}: {insn.dest} = {insn.src1} + {insn.src2_or_imm} -> [{self.env[insn.dest].low}, {self.env[insn.dest].high}]")

            elif op == "SUB" and insn.src1:
                lhs = self.env.get(insn.src1, self.DEFAULT_UNTRUSTED_INTERVAL)
                rhs = (
                    SymbolicInterval(int(insn.src2_or_imm), int(insn.src2_or_imm))
                    if isinstance(insn.src2_or_imm, int)
                    else self.env.get(str(insn.src2_or_imm), SymbolicInterval(0, 0))
                )
                self.env[insn.dest] = lhs.sub(rhs)
                self.trace.append(f"Step {step_idx}: {insn.dest} = {insn.src1} - {insn.src2_or_imm} -> [{self.env[insn.dest].low}, {self.env[insn.dest].high}]")

            elif op == "AND" and insn.src1:
                lhs = self.env.get(insn.src1, self.DEFAULT_UNTRUSTED_INTERVAL)
                mask = int(insn.src2_or_imm or 0xFFFF)
                self.env[insn.dest] = lhs.bitwise_and(mask)
                self.trace.append(f"Step {step_idx}: {insn.dest} = {insn.src1} & 0x{mask:x} -> [{self.env[insn.dest].low}, {self.env[insn.dest].high}]")

            elif op in ("ASSERT_LT", "ASSERT_LE"):
                bound = int(insn.src2_or_imm or 0)
                limit = bound - 1 if op == "ASSERT_LT" else bound
                cur = self.env.get(insn.dest, self.DEFAULT_UNTRUSTED_INTERVAL)
                clamped = cur.clamp_upper(limit)
                self.env[insn.dest] = clamped
                self.trace.append(f"Step {step_idx}: Guard {op}({insn.dest}, {bound}) narrows {insn.dest} -> [{clamped.low}, {clamped.high}]")

            elif op == "BUFFER_WRITE":
                cap = int(insn.buffer_capacity or 64)
                length_iv = self.env.get(insn.src1 or insn.dest, self.DEFAULT_UNTRUSTED_INTERVAL)
                if not length_iv.is_satisfiable():
                    status = "UNREACHABLE_PATH"
                    cwe = None
                elif length_iv.low >= 0 and length_iv.high <= cap:
                    status = "PROVEN_SAFE"
                    cwe = None
                elif length_iv.low < 0:
                    status = "PROVABLY_UNSAFE"
                    cwe = "CWE-191"  # Integer Underflow
                else:
                    status = "PROVABLY_UNSAFE"
                    cwe = "CWE-787"  # Out-of-bounds Write

                results.append(SymbolicVerificationResult(
                    sink_variable=insn.src1 or insn.dest,
                    buffer_capacity=cap,
                    computed_interval=(length_iv.low, length_iv.high),
                    status=status,
                    cwe_id=cwe,
                    proof_trace=list(self.trace),
                ))

        return results
