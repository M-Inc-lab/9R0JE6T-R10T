"""
R3V3R53//F0RG3 — SMT Path Feasibility & Branch Guard Completeness Solver (§08, §09, §20)
Uses Z3 ('z3-solver') when available with a deterministic pure-Python constraint solver fallback
to prove path reachability (SAT/UNSAT) and verify whether branch guards prevent out-of-bounds access.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

try:
    import z3  # type: ignore
except ImportError:
    z3 = None


@dataclass
class PathConstraint:
    var: str
    op: str         # EQ, NE, LT, LE, GT, GE, MOD_EQ, BIT_AND_EQ, XOR_EQ
    value: int
    modulus_or_mask: Optional[int] = None


@dataclass
class RelationalConstraint:
    lhs_var: str
    op: str
    rhs_var: str
    rhs_offset: int = 0


@dataclass
class SMTSolveResult:
    status: str     # SAT, UNSAT, UNKNOWN
    is_feasible: bool
    model: Dict[str, int] = field(default_factory=dict)
    solver_backend: str = "pure-python"
    notes: str = ""


class SMTSolverEngine:
    """Solves symbolic branch constraints and verifies boundary guard completeness."""

    def __init__(self, min_domain: int = -1024, max_domain: int = 65536):
        self.min_domain = min_domain
        self.max_domain = max_domain

    def solve_constraints(self, constraints: List[PathConstraint]) -> SMTSolveResult:
        if z3 is not None:
            return self._solve_with_z3(constraints)
        return self._solve_pure_python(constraints)

    def _solve_with_z3(self, constraints: List[PathConstraint]) -> SMTSolveResult:
        assert z3 is not None
        solver = z3.Solver()
        z3_vars: Dict[str, Any] = {}

        for c in constraints:
            if c.var not in z3_vars:
                z3_vars[c.var] = z3.BitVec(c.var, 32)
            v = z3_vars[c.var]
            op = c.op.upper()
            val = int(c.value)
            aux = int(c.modulus_or_mask or 1)

            if op == "EQ":
                solver.add(v == val)
            elif op == "NE":
                solver.add(v != val)
            elif op == "LT":
                solver.add(v < val)
            elif op == "LE":
                solver.add(v <= val)
            elif op == "GT":
                solver.add(v > val)
            elif op == "GE":
                solver.add(v >= val)
            elif op == "MOD_EQ":
                solver.add(z3.SRem(v, aux) == val)
            elif op == "BIT_AND_EQ":
                solver.add((v & aux) == val)
            elif op == "XOR_EQ":
                solver.add((v ^ aux) == val)

        chk = solver.check()
        if chk == z3.sat:
            m = solver.model()
            model_dict = {name: m[var].as_signed_long() for name, var in z3_vars.items() if m[var] is not None}
            return SMTSolveResult(status="SAT", is_feasible=True, model=model_dict, solver_backend="z3-smt")
        if chk == z3.unsat:
            return SMTSolveResult(status="UNSAT", is_feasible=False, model={}, solver_backend="z3-smt")
        return SMTSolveResult(status="UNKNOWN", is_feasible=False, model={}, solver_backend="z3-smt")

    def _solve_pure_python(self, constraints: List[PathConstraint]) -> SMTSolveResult:
        by_var: Dict[str, List[PathConstraint]] = {}
        for c in constraints:
            by_var.setdefault(c.var, []).append(c)

        model: Dict[str, int] = {}
        for var_name, var_constraints in by_var.items():
            low = self.min_domain
            high = self.max_domain
            exact_candidates: Optional[set[int]] = None

            for c in var_constraints:
                op = c.op.upper()
                val = int(c.value)
                aux = int(c.modulus_or_mask or 1)
                if op == "EQ":
                    low = max(low, val)
                    high = min(high, val)
                elif op == "LT":
                    high = min(high, val - 1)
                elif op == "LE":
                    high = min(high, val)
                elif op == "GT":
                    low = max(low, val + 1)
                elif op == "GE":
                    low = max(low, val)
                elif op == "XOR_EQ":
                    target = val ^ aux
                    low = max(low, target)
                    high = min(high, target)

            if low > high:
                return SMTSolveResult(
                    status="UNSAT",
                    is_feasible=False,
                    model={},
                    solver_backend="pure-python-interval",
                    notes=f"Interval contradiction on variable '{var_name}': [{low}, {high}]",
                )

            found_val: Optional[int] = None
            for candidate in range(low, high + 1):
                ok = True
                for c in var_constraints:
                    op = c.op.upper()
                    val = int(c.value)
                    aux = int(c.modulus_or_mask or 1)
                    if op == "NE" and candidate == val:
                        ok = False
                        break
                    if op == "MOD_EQ" and (aux == 0 or (candidate % aux) != val):
                        ok = False
                        break
                    if op == "BIT_AND_EQ" and ((candidate & aux) != val):
                        ok = False
                        break
                if ok:
                    found_val = candidate
                    break

            if found_val is None:
                return SMTSolveResult(
                    status="UNSAT",
                    is_feasible=False,
                    model={},
                    solver_backend="pure-python-interval",
                    notes=f"No integer in [{low}, {high}] satisfies modular/bitwise constraints for '{var_name}'",
                )
            model[var_name] = found_val

        return SMTSolveResult(
            status="SAT",
            is_feasible=True,
            model=model,
            solver_backend="pure-python-interval",
        )

    def verify_guard_completeness(
        self,
        path_constraints: List[PathConstraint],
        length_var: str,
        buffer_capacity: int,
    ) -> Dict[str, Any]:
        """
        Check whether path_constraints permit length_var > buffer_capacity (CWE-787)
        or length_var < 0 (CWE-191).
        """
        overflow_query = list(path_constraints) + [
            PathConstraint(var=length_var, op="GT", value=buffer_capacity)
        ]
        over_res = self.solve_constraints(overflow_query)
        if over_res.is_feasible:
            return {
                "guard_status": "INCOMPLETE_GUARD",
                "cwe_id": "CWE-787",
                "counterexample": over_res.model,
                "solver_backend": over_res.solver_backend,
                "explanation": (
                    f"Branch guards permit {length_var}={over_res.model.get(length_var)} "
                    f"which exceeds buffer capacity ({buffer_capacity} bytes)."
                ),
            }

        underflow_query = list(path_constraints) + [
            PathConstraint(var=length_var, op="LT", value=0)
        ]
        under_res = self.solve_constraints(underflow_query)
        if under_res.is_feasible:
            return {
                "guard_status": "INCOMPLETE_GUARD",
                "cwe_id": "CWE-191",
                "counterexample": under_res.model,
                "solver_backend": under_res.solver_backend,
                "explanation": (
                    f"Branch guards permit negative {length_var}={under_res.model.get(length_var)} "
                    f"(signedness/underflow defect)."
                ),
            }

        return {
            "guard_status": "GUARD_COMPLETE",
            "cwe_id": None,
            "counterexample": {},
            "solver_backend": over_res.solver_backend,
            "explanation": f"Path constraints strictly bound '{length_var}' within [0, {buffer_capacity}].",
        }

    def verify_modular_wrap_and_relational_guards(
        self,
        path_constraints: List[PathConstraint],
        relational_constraints: Optional[List[RelationalConstraint]] = None,
        length_var: str = "input_len",
        added_header_size: int = 0,
        buffer_capacity: int = 512,
        bit_width: int = 64,
    ) -> Dict[str, Any]:
        """
        Phase 35: 64-bit Modular Bit-Vector & Two-Variable Relational Guard Verification.
        Detects CWE-190 integer wraparound where `(length_var + added_header_size) <= buffer_capacity`
        is checked in modular 2^bit_width arithmetic without checking `length_var <= buffer_capacity`,
        allowing `length_var = 2^bit_width - added_header_size` to wrap around to 0!
        """
        modulus = 1 << bit_width
        max_uint = modulus - 1

        # 1. Check 64-bit modular addition wrap-around (CWE-190 -> CWE-122)
        if added_header_size > 0:
            wrap_candidate = modulus - added_header_size
            # Check if path_constraints forbid unsigned values near 2^bit_width
            has_strict_upper_bound = False
            for c in path_constraints:
                if c.var == length_var and c.op.upper() in ("LT", "LE") and c.value <= buffer_capacity:
                    has_strict_upper_bound = True
                    break
            if not has_strict_upper_bound:
                wrapped_sum = (wrap_candidate + added_header_size) % modulus
                if wrapped_sum <= buffer_capacity:
                    return {
                        "guard_status": "MODULAR_WRAP_VULNERABLE",
                        "cwe_id": "CWE-190",
                        "bit_width": bit_width,
                        "counterexample": {
                            length_var: wrap_candidate,
                            "wrapped_allocation_size": wrapped_sum,
                        },
                        "explanation": (
                            f"{bit_width}-bit modular addition ({length_var} + {added_header_size}) wraps around "
                            f"at {length_var}=0x{wrap_candidate:x} to {wrapped_sum} <= {buffer_capacity} (CWE-190 -> CWE-122)."
                        ),
                    }

        # 2. Evaluate two-variable relational constraints (e.g., idx < buf_cap)
        if relational_constraints:
            var_bounds: Dict[str, List[int]] = {}
            for c in path_constraints:
                lo, hi = var_bounds.get(c.var, [0, buffer_capacity * 2])
                if c.op == "GE":
                    lo = max(lo, c.value)
                elif c.op == "GT":
                    lo = max(lo, c.value + 1)
                elif c.op == "LE":
                    hi = min(hi, c.value)
                elif c.op == "LT":
                    hi = min(hi, c.value - 1)
                elif c.op == "EQ":
                    lo, hi = c.value, c.value
                var_bounds[c.var] = [lo, hi]

            for rc in relational_constraints:
                rhs_lo, rhs_hi = var_bounds.get(rc.rhs_var, [0, buffer_capacity])
                lhs_lo, lhs_hi = var_bounds.get(rc.lhs_var, [0, buffer_capacity * 2])
                if rc.op == "LT":
                    lhs_hi = min(lhs_hi, rhs_hi + rc.rhs_offset - 1)
                elif rc.op == "LE":
                    lhs_hi = min(lhs_hi, rhs_hi + rc.rhs_offset)
                var_bounds[rc.lhs_var] = [lhs_lo, lhs_hi]

            final_lo, final_hi = var_bounds.get(length_var, [0, buffer_capacity * 2])
            if final_hi <= buffer_capacity and final_lo >= 0:
                return {
                    "guard_status": "GUARD_COMPLETE_RELATIONAL",
                    "cwe_id": None,
                    "bit_width": bit_width,
                    "counterexample": {},
                    "explanation": f"Relational constraints bound '{length_var}' within [{final_lo}, {final_hi}] <= {buffer_capacity}.",
                }

        return self.verify_guard_completeness(path_constraints, length_var, buffer_capacity)

