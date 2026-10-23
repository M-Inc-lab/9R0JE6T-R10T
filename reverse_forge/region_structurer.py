"""
R3V3R53//F0RG3 — Phase 33: Pattern-Independent Region-Based Control-Flow Structurer
Modeled on DREAM ("No More Gotos", NDSS 2015) and angr's Clinic decompiler pipeline.
Computes post-dominator trees (ipdom), identifies natural loop regions (while, do-while,
infinite loops with break), collapses compound short-circuit boolean conditions (&& / ||),
and recovers structured if / else if / else and switch statements with zero goto labels.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from reverse_forge.decompiler_engine import BasicBlock


@dataclass
class StructuredRegionReport:
    entry_addr: int
    total_blocks: int
    goto_count: int
    recovered_loops: int
    recovered_conditionals: int
    recovered_switches: int
    compound_predicates: int
    post_dominators: Dict[int, int]
    structured_c: str


class ControlFlowRegionStructurer:
    """
    Transforms a BasicBlock CFG into goto-free structured ANSI C using
    immediate post-dominators (ipdom), natural loop back-edge analysis,
    and short-circuit boolean condition coalescing.
    """

    COND_OP_MAP = {
        "je": "==", "jz": "==",
        "jne": "!=", "jnz": "!=",
        "jg": ">", "ja": ">", "bgt": ">",
        "jge": ">=", "jae": ">=", "bge": ">=",
        "jl": "<", "jb": "<", "blt": "<",
        "jle": "<=", "jbe": "<=", "ble": "<=",
        "beq": "==", "bne": "!=",
    }

    INVERT_OP = {
        "==": "!=", "!=": "==",
        ">": "<=", "<=": ">",
        "<": ">=", ">=": "<",
    }

    def compute_post_dominators(self, cfg: Dict[int, BasicBlock]) -> Dict[int, int]:
        """
        Compute immediate post-dominator (ipdom) for each BasicBlock by running
        iterative dominator intersection on the reversed CFG from exit nodes.
        """
        if not cfg:
            return {}

        exit_nodes = [addr for addr, b in cfg.items() if not b.successors]
        if not exit_nodes:
            exit_nodes = [max(cfg.keys())]

        VIRTUAL_EXIT = -1
        rev_preds: Dict[int, List[int]] = {addr: list(b.successors) for addr, b in cfg.items()}
        for ex in exit_nodes:
            if VIRTUAL_EXIT not in rev_preds[ex]:
                rev_preds[ex].append(VIRTUAL_EXIT)
        rev_preds[VIRTUAL_EXIT] = []

        rev_succs: Dict[int, List[int]] = {addr: list(b.predecessors) for addr, b in cfg.items()}
        rev_succs[VIRTUAL_EXIT] = list(exit_nodes)

        visited: Set[int] = set()
        postorder: List[int] = []

        def dfs(n: int) -> None:
            visited.add(n)
            for s in rev_succs.get(n, []):
                if s in rev_succs and s not in visited:
                    dfs(s)
            postorder.append(n)

        dfs(VIRTUAL_EXIT)
        rpo = list(reversed(postorder))
        rpo_idx = {n: i for i, n in enumerate(rpo)}

        pdoms: Dict[int, int] = {VIRTUAL_EXIT: VIRTUAL_EXIT}

        def intersect(b1: int, b2: int) -> int:
            f1, f2 = b1, b2
            while f1 != f2:
                while rpo_idx.get(f1, 999999) > rpo_idx.get(f2, 999999):
                    f1 = pdoms[f1]
                while rpo_idx.get(f2, 999999) > rpo_idx.get(f1, 999999):
                    f2 = pdoms[f2]
            return f1

        changed = True
        while changed:
            changed = False
            for n in rpo:
                if n == VIRTUAL_EXIT:
                    continue
                preds = [p for p in rev_preds.get(n, []) if p in pdoms]
                if not preds:
                    continue
                new_ipdom = preds[0]
                for p in preds[1:]:
                    new_ipdom = intersect(p, new_ipdom)
                if pdoms.get(n) != new_ipdom:
                    pdoms[n] = new_ipdom
                    changed = True

        return {k: v for k, v in pdoms.items() if k != VIRTUAL_EXIT}

    def _extract_block_predicate(self, blk: BasicBlock) -> Tuple[Optional[str], List[Tuple[int, str, str]]]:
        """Extract the trailing branch predicate (e.g. 'var_rdi == 0x10') and body instructions."""
        if not blk.instructions:
            return None, []

        last_addr, last_mnem, last_ops = blk.instructions[-1]
        lm = last_mnem.lower()
        if lm not in self.COND_OP_MAP:
            return None, list(blk.instructions)

        rel_op = self.COND_OP_MAP[lm]
        lhs, rhs = "cond_flag", "0"
        body_end = len(blk.instructions) - 1

        if len(blk.instructions) >= 2:
            prev_addr, prev_mnem, prev_ops = blk.instructions[-2]
            pm = prev_mnem.lower()
            if pm in ("cmp", "test"):
                parts = [p.strip() for p in prev_ops.split(",")]
                if len(parts) >= 2:
                    lhs = self._reg_to_var(parts[0])
                    rhs = "0" if (pm == "test" and parts[0] == parts[1]) else self._reg_to_var(parts[1])
                body_end = len(blk.instructions) - 2

        return f"{lhs} {rel_op} {rhs}", list(blk.instructions[:body_end])

    @classmethod
    def _invert_predicate(cls, pred: str) -> str:
        for op, inv in sorted(cls.INVERT_OP.items(), key=lambda x: -len(x[0])):
            token = f" {op} "
            if token in pred:
                lhs, rhs = pred.split(token, 1)
                return f"{lhs} {inv} {rhs}"
        return f"!({pred})"

    @staticmethod
    def _reg_to_var(op: str) -> str:
        op = op.strip()
        if not op:
            return "0"
        if op.startswith("0x") or op.lstrip("-").isdigit():
            return op
        reg_map = {
            "rdi": "arg1", "edi": "arg1", "x0": "arg1",
            "rsi": "arg2", "esi": "arg2", "x1": "arg2",
            "rdx": "arg3", "edx": "arg3", "x2": "arg3",
            "rcx": "arg4", "ecx": "arg4", "x3": "arg4",
            "rax": "var_eax", "eax": "var_eax",
            "rbx": "var_ebx", "ebx": "var_ebx",
        }
        clean = op.lower().lstrip("%$")
        return reg_map.get(clean, f"var_{clean}" if clean.isalnum() else op)

    def _emit_linear_statements(self, insns: List[Tuple[int, str, str]], indent: str) -> List[str]:
        lines: List[str] = []
        for addr, mnem, ops in insns:
            m = mnem.lower()
            if m in ("push", "pop", "nop", "endbr64", "leave"):
                continue
            parts = [p.strip() for p in ops.split(",") if p.strip()]
            if m in ("mov", "movzx", "movsx") and len(parts) >= 2:
                if parts[0] in ("rbp", "rsp", "ebp", "esp") and parts[1] in ("rbp", "rsp", "ebp", "esp"):
                    continue
                lines.append(f"{indent}{self._reg_to_var(parts[0])} = {self._reg_to_var(parts[1])};")
            elif m in ("add", "sub", "imul", "and", "or", "xor", "shl", "shr") and len(parts) >= 2:
                op_sym = {"add": "+", "sub": "-", "imul": "*", "and": "&", "or": "|", "xor": "^", "shl": "<<", "shr": ">>"}[m]
                dst = self._reg_to_var(parts[0])
                src = self._reg_to_var(parts[1])
                if m == "xor" and parts[0].lower() == parts[1].lower():
                    lines.append(f"{indent}{dst} = 0;")
                else:
                    lines.append(f"{indent}{dst} = {dst} {op_sym} {src};")
            elif m in ("call", "bl", "blr"):
                target = parts[0] if parts else "sub_unk"
                lines.append(f"{indent}var_eax = {target}();")
            elif m in ("ret", "retn", "bx lr"):
                lines.append(f"{indent}return var_eax;")
        return lines

    def structure_cfg(self, cfg: Dict[int, BasicBlock], func_name: str = "sub_structured") -> StructuredRegionReport:
        """
        Structure an arbitrary BasicBlock graph into readable, goto-free ANSI C.
        """
        if not cfg:
            return StructuredRegionReport(
                entry_addr=0,
                total_blocks=0,
                goto_count=0,
                recovered_loops=0,
                recovered_conditionals=0,
                recovered_switches=0,
                compound_predicates=0,
                post_dominators={},
                structured_c=f"int {func_name}(void) {{\n    return 0;\n}}",
            )

        entry_addr = min(cfg.keys())
        ipdom = self.compute_post_dominators(cfg)

        # Identify natural loop headers and latches (back-edge: succ <= b_addr)
        loop_latches: Dict[int, Set[int]] = {}
        for b_addr, blk in cfg.items():
            for succ in blk.successors:
                if succ <= b_addr and succ in cfg:
                    loop_latches.setdefault(succ, set()).add(b_addr)

        visited: Set[int] = set()
        stats = {"loops": 0, "conditionals": 0, "switches": 0, "compound": 0}

        def render_region(curr_addr: Optional[int], stop_addr: Optional[int], indent: str) -> List[str]:
            out: List[str] = []
            while curr_addr is not None and curr_addr != stop_addr and curr_addr in cfg and curr_addr not in visited:
                visited.add(curr_addr)
                blk = cfg[curr_addr]
                pred_expr, body_insns = self._extract_block_predicate(blk)

                # Case 1: Natural Loop Header
                if curr_addr in loop_latches:
                    stats["loops"] += 1
                    latches = loop_latches[curr_addr]
                    out.extend(self._emit_linear_statements(body_insns, indent))
                    if len(blk.successors) == 2 and pred_expr:
                        true_target, false_target = blk.successors[0], blk.successors[1]
                        # Pre-tested while loop: one branch exits loop, one enters body
                        if true_target > curr_addr and false_target > max(latches):
                            loop_cond = self._invert_predicate(pred_expr)
                            out.append(f"{indent}while ({loop_cond}) {{")
                            out.extend(render_region(false_target, curr_addr, indent + "    "))
                            out.append(f"{indent}}}")
                            curr_addr = true_target
                            continue
                        elif false_target > curr_addr and true_target > max(latches):
                            out.append(f"{indent}while ({pred_expr}) {{")
                            out.extend(render_region(true_target, curr_addr, indent + "    "))
                            out.append(f"{indent}}}")
                            curr_addr = false_target
                            continue
                        elif curr_addr in latches and true_target == curr_addr:
                            # Self do-while loop
                            out.append(f"{indent}do {{")
                            for l_stmt in self._emit_linear_statements(body_insns, indent + "    "):
                                out.append(l_stmt)
                            out.append(f"{indent}}} while ({pred_expr});")
                            curr_addr = false_target
                            continue
                    # General structured while(1) with break
                    out.append(f"{indent}while (1) {{")
                    if len(blk.successors) == 2 and pred_expr:
                        out.append(f"{indent}    if ({pred_expr}) {{")
                        out.append(f"{indent}        break;")
                        out.append(f"{indent}    }}")
                        next_body = blk.successors[1]
                        out.extend(render_region(next_body, curr_addr, indent + "    "))
                        out.append(f"{indent}}}")
                        curr_addr = blk.successors[0]
                    else:
                        out.append(f"{indent}    break;")
                        out.append(f"{indent}}}")
                        curr_addr = blk.successors[0] if blk.successors else None
                    continue

                # Emit non-branch instructions in current block
                out.extend(self._emit_linear_statements(body_insns, indent))

                # Case 2: Multi-way Switch Region (>= 3 successors)
                if len(blk.successors) >= 3:
                    stats["switches"] += 1
                    merge_node = ipdom.get(curr_addr, -1)
                    out.append(f"{indent}switch (arg1) {{")
                    for case_idx, succ_target in enumerate(blk.successors):
                        out.append(f"{indent}    case {case_idx}:")
                        case_body = render_region(succ_target, merge_node if merge_node != -1 else None, indent + "        ")
                        out.extend(case_body)
                        out.append(f"{indent}        break;")
                    out.append(f"{indent}}}")
                    curr_addr = merge_node if (merge_node != -1 and merge_node in cfg) else None
                    continue

                # Case 3: Conditional Branch (2 successors)
                if len(blk.successors) == 2 and pred_expr:
                    stats["conditionals"] += 1
                    taken_target, fall_target = blk.successors[0], blk.successors[1]
                    merge_node = ipdom.get(curr_addr, -1)
                    effective_stop = merge_node if (merge_node != -1 and merge_node in cfg) else stop_addr

                    # Check for short-circuit compound boolean condition (A && B or A || B)
                    if fall_target in cfg and fall_target not in visited:
                        fall_blk = cfg[fall_target]
                        fall_pred, fall_body = self._extract_block_predicate(fall_blk)
                        if not fall_body and len(fall_blk.successors) == 2 and fall_pred:
                            if fall_blk.successors[0] == taken_target:
                                # Both branches jump to taken_target -> short-circuit OR
                                stats["compound"] += 1
                                visited.add(fall_target)
                                pred_expr = f"({pred_expr}) || ({fall_pred})"
                                fall_target = fall_blk.successors[1]
                            elif fall_blk.successors[1] == taken_target:
                                # First false and second true jump to same target -> short-circuit AND
                                stats["compound"] += 1
                                visited.add(fall_target)
                                pred_expr = f"({ self._invert_predicate(pred_expr) }) && ({fall_pred})"
                                taken_target, fall_target = fall_blk.successors[0], taken_target

                    if taken_target == effective_stop:
                        # Only fallthrough has a body -> invert condition
                        inv_cond = self._invert_predicate(pred_expr)
                        out.append(f"{indent}if ({inv_cond}) {{")
                        out.extend(render_region(fall_target, effective_stop, indent + "    "))
                        out.append(f"{indent}}}")
                    elif fall_target == effective_stop:
                        # Only taken branch has a body
                        out.append(f"{indent}if ({pred_expr}) {{")
                        out.extend(render_region(taken_target, effective_stop, indent + "    "))
                        out.append(f"{indent}}}")
                    else:
                        # Full if-else diamond
                        out.append(f"{indent}if ({pred_expr}) {{")
                        out.extend(render_region(taken_target, effective_stop, indent + "    "))
                        out.append(f"{indent}}} else {{")
                        out.extend(render_region(fall_target, effective_stop, indent + "    "))
                        out.append(f"{indent}}}")

                    curr_addr = effective_stop
                    continue

                # Case 4: Single successor or exit
                if len(blk.successors) == 1:
                    next_s = blk.successors[0]
                    curr_addr = next_s if next_s != stop_addr else None
                else:
                    curr_addr = None

            return out

        body_lines = render_region(entry_addr, None, "    ")
        if not body_lines or not body_lines[-1].strip().startswith("return"):
            body_lines.append("    return var_eax;")

        header = [
            f"int {func_name}(long arg1, long arg2, long arg3) {{",
            "    int var_eax = 0;",
        ]
        full_c = "\n".join(header + body_lines + ["}"])
        goto_count = sum(1 for ln in body_lines if "goto " in ln)

        return StructuredRegionReport(
            entry_addr=entry_addr,
            total_blocks=len(cfg),
            goto_count=goto_count,
            recovered_loops=stats["loops"],
            recovered_conditionals=stats["conditionals"],
            recovered_switches=stats["switches"],
            compound_predicates=stats["compound"],
            post_dominators=ipdom,
            structured_c=full_c,
        )
