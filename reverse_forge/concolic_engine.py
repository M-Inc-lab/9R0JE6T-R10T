"""
R3V3R53//F0RG3 — Concolic Path Exploration & SAT Exploit Synthesizer (§21, §22)
Combines concrete disassembly execution with symbolic AST tracking to generate
mathematically proven exploit trigger payloads and mathematically prove unreachability.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from reverse_forge.smt_solver_engine import SMTSolverEngine, PathConstraint, SMTSolveResult


@dataclass
class ConcolicBranch:
    branch_id: str
    condition_var: str
    op: str
    boundary_val: int
    direction_taken: bool


@dataclass
class ExploitSynthesisResult:
    target_sink: str
    is_satisfiable: bool
    payload_input: Dict[str, int]
    cwe_classification: str
    solver_notes: str


class ConcolicPathPruner:
    """
    Explores path branches concolically, pruning provably infeasible paths (UNSAT)
    and synthesizing boundary input models (SAT) for out-of-bounds sinks.
    """

    def __init__(self, solver: Optional[SMTSolverEngine] = None):
        self.solver = solver or SMTSolverEngine()

    def evaluate_branch_feasibility(
        self,
        current_constraints: List[PathConstraint],
        candidate_constraint: PathConstraint,
    ) -> Tuple[bool, Optional[Dict[str, int]]]:
        """Check if taking candidate branch condition is mathematically possible."""
        test_constraints = list(current_constraints) + [candidate_constraint]
        res: SMTSolveResult = self.solver.solve_constraints(test_constraints)
        return res.is_feasible, res.model if res.is_feasible else None

    def synthesize_exploit_trigger(
        self,
        path_constraints: List[PathConstraint],
        length_var: str,
        buffer_capacity: int,
        sink_name: str = "strcpy",
    ) -> ExploitSynthesisResult:
        """
        Synthesizes a concrete variable mapping that violates buffer bounds (length > capacity)
        while strictly satisfying all preceding branch guards on the path.
        """
        # Try to find input where length > capacity
        target_constraint = PathConstraint(var=length_var, op="GT", value=buffer_capacity)
        res = self.solver.solve_constraints(list(path_constraints) + [target_constraint])

        if res.is_feasible:
            return ExploitSynthesisResult(
                target_sink=sink_name,
                is_satisfiable=True,
                payload_input=res.model,
                cwe_classification="CWE-787: Out-of-bounds Write",
                solver_notes=f"Found concrete trigger payload: {length_var}={res.model.get(length_var)} exceeds capacity {buffer_capacity}",
            )

        # Try signed underflow/negative boundary condition
        neg_constraint = PathConstraint(var=length_var, op="LT", value=0)
        res_neg = self.solver.solve_constraints(list(path_constraints) + [neg_constraint])
        if res_neg.is_feasible:
            return ExploitSynthesisResult(
                target_sink=sink_name,
                is_satisfiable=True,
                payload_input=res_neg.model,
                cwe_classification="CWE-191: Integer Underflow (Wrap Around)",
                solver_notes=f"Found signed underflow trigger: {length_var}={res_neg.model.get(length_var)}",
            )

        return ExploitSynthesisResult(
            target_sink=sink_name,
            is_satisfiable=False,
            payload_input={},
            cwe_classification="SAFE_PATH",
            solver_notes="Branch guards mathematically constrain input within safe bounds.",
        )
