"""
R3V3R53//F0RG3 — Phase 32: Cytron Static Single Assignment (SSA) Lifter & Algebraic Optimizer
Lifts UnifiedIL (UILInstruction) basic-block control-flow graphs into Static Single Assignment
form with explicit PHI nodes at dominance frontiers, and runs algebraic SSA optimization passes:
  1. Dominance Tree & Dominance Frontier Computation (Cooper-Harvey-Kennedy / Cytron et al.)
  2. Minimal PHI-Node Placement & Dominator-Tree Variable Renaming (v -> v#1, v#2, ...)
  3. SSA Constant Propagation & Trivial PHI Folding
  4. SSA Def-Use Copy Propagation
  5. SSA Dead-Store Elimination (Iterative Worklist over Def-Use Chains)
"""

from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Set, Tuple
from reverse_forge.unified_il_lifter import UILInstruction


@dataclass
class SSABasicBlock:
    block_id: int
    instructions: List[UILInstruction] = field(default_factory=list)
    phi_nodes: List[UILInstruction] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)


@dataclass
class SSAOptimizationReport:
    entry_block: int
    total_blocks: int
    phi_nodes_inserted: int
    constants_propagated: int
    copies_propagated: int
    dead_stores_eliminated: int
    dominators: Dict[int, int]
    dominance_frontiers: Dict[int, List[int]]
    blocks: Dict[int, SSABasicBlock]


class SSALifterAndOptimizer:
    """
    Constructs SSA form over UILInstruction basic-block graphs and executes
    def-use algebraic optimizations without regex fragility.
    """

    IMM_INT_RE = re.compile(r"^-?(?:0x[0-9a-fA-F]+|\d+)$")

    @classmethod
    def _parse_int(cls, token: Optional[str]) -> Optional[int]:
        if token is None:
            return None
        s = token.strip()
        if not cls.IMM_INT_RE.match(s):
            return None
        try:
            return int(s, 16) if s.lower().startswith(("0x", "-0x")) else int(s, 10)
        except ValueError:
            return None

    @staticmethod
    def _is_variable(token: Optional[str]) -> bool:
        if not token:
            return False
        s = token.strip()
        if not s or s[0].isdigit() or s.startswith("-"):
            return False
        if s.startswith("0x") or s.startswith("PHI("):
            return False
        return True

    @staticmethod
    def _base_var_name(versioned_name: str) -> str:
        return versioned_name.split("#", 1)[0]

    def compute_dominators(self, blocks: Dict[int, SSABasicBlock], entry_id: int) -> Dict[int, int]:
        """
        Iterative dominator tree computation (Cooper, Harvey, and Kennedy algorithm).
        Returns mapping block_id -> immediate dominator block_id (entry maps to itself).
        """
        if not blocks or entry_id not in blocks:
            return {}

        # Reverse post-order traversal
        visited: Set[int] = set()
        postorder: List[int] = []

        def dfs(b_id: int) -> None:
            visited.add(b_id)
            blk = blocks.get(b_id)
            if blk:
                for succ in blk.successors:
                    if succ in blocks and succ not in visited:
                        dfs(succ)
            postorder.append(b_id)

        dfs(entry_id)
        rpo = list(reversed(postorder))
        rpo_idx = {b_id: idx for idx, b_id in enumerate(rpo)}

        doms: Dict[int, int] = {entry_id: entry_id}

        def intersect(b1: int, b2: int) -> int:
            finger1, finger2 = b1, b2
            while finger1 != finger2:
                while rpo_idx.get(finger1, 999999) > rpo_idx.get(finger2, 999999):
                    finger1 = doms[finger1]
                while rpo_idx.get(finger2, 999999) > rpo_idx.get(finger1, 999999):
                    finger2 = doms[finger2]
            return finger1

        changed = True
        while changed:
            changed = False
            for b_id in rpo:
                if b_id == entry_id:
                    continue
                preds = [p for p in blocks[b_id].predecessors if p in doms]
                if not preds:
                    continue
                new_idom = preds[0]
                for p in preds[1:]:
                    new_idom = intersect(p, new_idom)
                if doms.get(b_id) != new_idom:
                    doms[b_id] = new_idom
                    changed = True

        # For any unreachable block, set self as idom
        for b_id in blocks:
            if b_id not in doms:
                doms[b_id] = b_id

        return doms

    def compute_dominance_frontiers(
        self, blocks: Dict[int, SSABasicBlock], idom: Dict[int, int]
    ) -> Dict[int, Set[int]]:
        """Compute Cytron dominance frontier DF[b] for every basic block in the CFG."""
        df: Dict[int, Set[int]] = {b_id: set() for b_id in blocks}
        for b_id, blk in blocks.items():
            valid_preds = [p for p in blk.predecessors if p in blocks]
            if len(valid_preds) >= 2:
                for p in valid_preds:
                    runner = p
                    while runner != idom.get(b_id, b_id):
                        df[runner].add(b_id)
                        next_runner = idom.get(runner, runner)
                        if next_runner == runner:
                            break
                        runner = next_runner
        return df

    def lift_to_ssa(
        self, raw_blocks: Dict[int, SSABasicBlock], entry_id: int
    ) -> Tuple[Dict[int, SSABasicBlock], Dict[int, int], Dict[int, Set[int]], int]:
        """
        Insert minimal PHI functions at iterated dominance frontiers and rename all
        variables into unique SSA versions (var#1, var#2, ...).
        """
        blocks: Dict[int, SSABasicBlock] = {
            b_id: SSABasicBlock(
                block_id=b_id,
                instructions=[
                    UILInstruction(
                        opcode=ins.opcode,
                        dest=ins.dest,
                        src1=ins.src1,
                        src2=ins.src2,
                        offset=ins.offset,
                        size_bytes=ins.size_bytes,
                        raw_assembly=ins.raw_assembly,
                    )
                    for ins in blk.instructions
                ],
                phi_nodes=[],
                predecessors=list(blk.predecessors),
                successors=list(blk.successors),
            )
            for b_id, blk in raw_blocks.items()
        }

        if not blocks or entry_id not in blocks:
            return blocks, {}, {}, 0

        idom = self.compute_dominators(blocks, entry_id)
        df = self.compute_dominance_frontiers(blocks, idom)

        # Build dominator tree children map
        dom_children: Dict[int, List[int]] = {b_id: [] for b_id in blocks}
        for b_id, parent in idom.items():
            if b_id != parent and parent in dom_children:
                dom_children[parent].append(b_id)
        for ch_list in dom_children.values():
            ch_list.sort()

        # 1. Discover global variables and definition blocks
        def_blocks_per_var: Dict[str, Set[int]] = {}
        all_vars: Set[str] = set()
        for b_id, blk in blocks.items():
            for ins in blk.instructions:
                if ins.opcode in ("ASSIGN", "LOAD", "ADD", "SUB", "MUL", "AND", "OR", "XOR", "SHL", "SHR"):
                    if self._is_variable(ins.dest):
                        var = self._base_var_name(str(ins.dest))
                        all_vars.add(var)
                        def_blocks_per_var.setdefault(var, set()).add(b_id)
                for s in (ins.src1, ins.src2):
                    if self._is_variable(s):
                        all_vars.add(self._base_var_name(str(s)))

        # 2. Place PHI nodes at iterated dominance frontiers
        phi_count = 0
        has_phi: Dict[Tuple[int, str], bool] = {}
        for var, def_sites in sorted(def_blocks_per_var.items()):
            worklist = list(def_sites)
            visited_work = set(worklist)
            while worklist:
                n = worklist.pop(0)
                for y in sorted(df.get(n, set())):
                    if not has_phi.get((y, var), False):
                        preds = blocks[y].predecessors
                        placeholder_args = ", ".join(f"{p}:{var}#0" for p in preds)
                        blocks[y].phi_nodes.append(
                            UILInstruction(
                                opcode="PHI",
                                dest=var,
                                src1=placeholder_args,
                                raw_assembly=f"{var} = PHI({placeholder_args})",
                            )
                        )
                        has_phi[(y, var)] = True
                        phi_count += 1
                        if y not in visited_work:
                            visited_work.add(y)
                            worklist.append(y)

        # 3. Dominator-tree variable renaming
        counters: Dict[str, int] = {v: 0 for v in all_vars}
        stacks: Dict[str, List[str]] = {v: [f"{v}#0"] for v in all_vars}

        def new_version(v: str) -> str:
            counters[v] = counters.get(v, 0) + 1
            ver = f"{v}#{counters[v]}"
            stacks.setdefault(v, [f"{v}#0"]).append(ver)
            return ver

        def current_version(v: str) -> str:
            stk = stacks.get(v)
            return stk[-1] if stk else f"{v}#0"

        def rename_block(b_id: int) -> None:
            blk = blocks[b_id]
            pushed_vars: List[str] = []

            # Rename LHS of PHI nodes
            for phi in blk.phi_nodes:
                if phi.dest:
                    base = self._base_var_name(phi.dest)
                    phi.dest = new_version(base)
                    pushed_vars.append(base)

            # Rename instructions inside block
            for ins in blk.instructions:
                # Rename uses (src1, src2, and STORE dest base pointer)
                if ins.opcode == "STORE":
                    if self._is_variable(ins.dest):
                        ins.dest = current_version(self._base_var_name(str(ins.dest)))
                    if self._is_variable(ins.src1):
                        ins.src1 = current_version(self._base_var_name(str(ins.src1)))
                else:
                    if self._is_variable(ins.src1) and ins.opcode != "CJUMP":
                        ins.src1 = current_version(self._base_var_name(str(ins.src1)))
                    elif ins.opcode == "CJUMP" and self._is_variable(ins.src1) and ins.src1 != "nzcv":
                        ins.src1 = current_version(self._base_var_name(str(ins.src1)))
                    if self._is_variable(ins.src2):
                        ins.src2 = current_version(self._base_var_name(str(ins.src2)))

                    # Rename definition (dest)
                    if ins.opcode in ("ASSIGN", "LOAD", "ADD", "SUB", "MUL", "AND", "OR", "XOR", "SHL", "SHR"):
                        if self._is_variable(ins.dest):
                            base = self._base_var_name(str(ins.dest))
                            ins.dest = new_version(base)
                            pushed_vars.append(base)

            # Update PHI arguments in successor blocks
            for succ_id in blk.successors:
                if succ_id not in blocks:
                    continue
                for phi in blocks[succ_id].phi_nodes:
                    base = self._base_var_name(str(phi.dest))
                    cur_ver = current_version(base)
                    parts = [p.strip() for p in (phi.src1 or "").split(",") if p.strip()]
                    updated_parts = []
                    for p_entry in parts:
                        if ":" in p_entry:
                            pred_str, old_val = p_entry.split(":", 1)
                            if int(pred_str) == b_id:
                                updated_parts.append(f"{b_id}:{cur_ver}")
                            else:
                                updated_parts.append(p_entry)
                        else:
                            updated_parts.append(p_entry)
                    phi.src1 = ", ".join(updated_parts)
                    phi.raw_assembly = f"{phi.dest} = PHI({phi.src1})"

            # Recurse over dominator-tree children
            for child_id in dom_children.get(b_id, []):
                rename_block(child_id)

            # Pop versions pushed in this block
            for base in pushed_vars:
                stacks[base].pop()

        rename_block(entry_id)
        return blocks, idom, df, phi_count

    def optimize_ssa_blocks(self, raw_blocks: Dict[int, SSABasicBlock], entry_id: int) -> SSAOptimizationReport:
        """
        Lift raw UIL blocks to SSA form and execute:
          1. Constant propagation & arithmetic constant folding (including trivial PHI folding)
          2. Def-use copy propagation across basic blocks
          3. Iterative dead-store elimination over SSA variables
        """
        blocks, idom, df, phi_count = self.lift_to_ssa(raw_blocks, entry_id)
        constants_propagated = 0
        copies_propagated = 0
        dead_stores_eliminated = 0

        # Pass 1 & 2: Iterative Constant & Copy Propagation to Fixed Point
        const_map: Dict[str, int] = {}
        copy_map: Dict[str, str] = {}

        changed = True
        while changed:
            changed = False
            for b_id in sorted(blocks.keys()):
                blk = blocks[b_id]

                # Check PHI nodes for trivial constant or identical-variable collapse
                for phi in blk.phi_nodes:
                    if not phi.dest or not phi.src1:
                        continue
                    rhs_vals: List[str] = []
                    for item in phi.src1.split(","):
                        if ":" in item:
                            _, v_tok = item.split(":", 1)
                            v_tok = v_tok.strip()
                            if v_tok in const_map:
                                rhs_vals.append(str(const_map[v_tok]))
                            elif v_tok in copy_map:
                                rhs_vals.append(copy_map[v_tok])
                            else:
                                rhs_vals.append(v_tok)
                    unique_non_self = {v for v in rhs_vals if v != phi.dest}
                    if len(unique_non_self) == 1:
                        sole_val = next(iter(unique_non_self))
                        c_int = self._parse_int(sole_val)
                        if c_int is not None and phi.dest not in const_map:
                            const_map[phi.dest] = c_int
                            constants_propagated += 1
                            changed = True
                        elif c_int is None and phi.dest not in copy_map:
                            copy_map[phi.dest] = sole_val
                            copies_propagated += 1
                            changed = True

                for ins in blk.instructions:
                    # Substitute known copies & constants into src1 and src2
                    for attr in ("src1", "src2"):
                        val = getattr(ins, attr)
                        if not val:
                            continue
                        if val in const_map:
                            setattr(ins, attr, str(const_map[val]))
                            constants_propagated += 1
                            changed = True
                        elif val in copy_map:
                            setattr(ins, attr, copy_map[val])
                            copies_propagated += 1
                            changed = True

                    if ins.opcode == "STORE" and ins.dest in copy_map:
                        ins.dest = copy_map[ins.dest]
                        copies_propagated += 1
                        changed = True

                    # Evaluate constant expressions or record copy
                    if ins.opcode == "ASSIGN" and ins.dest and ins.src1:
                        c1 = self._parse_int(ins.src1)
                        if c1 is not None:
                            if ins.dest not in const_map:
                                const_map[ins.dest] = c1
                                changed = True
                        elif self._is_variable(ins.src1) and ins.dest not in copy_map:
                            copy_map[ins.dest] = ins.src1
                            changed = True

                    elif ins.opcode in ("ADD", "SUB", "MUL", "AND", "OR", "XOR", "SHL", "SHR") and ins.dest:
                        c1 = self._parse_int(ins.src1)
                        c2 = self._parse_int(ins.src2)
                        if c1 is not None and c2 is not None:
                            folded_val = self._eval_binop(ins.opcode, c1, c2)
                            ins.opcode = "ASSIGN"
                            ins.src1 = str(folded_val)
                            ins.src2 = None
                            if ins.dest not in const_map:
                                const_map[ins.dest] = folded_val
                                constants_propagated += 1
                                changed = True
                        elif ins.opcode == "XOR" and ins.src1 and ins.src1 == ins.src2:
                            ins.opcode = "ASSIGN"
                            ins.src1 = "0"
                            ins.src2 = None
                            if ins.dest not in const_map:
                                const_map[ins.dest] = 0
                                constants_propagated += 1
                                changed = True

        # Pass 3: Iterative SSA Dead-Store Elimination over Def-Use Graph
        dse_changed = True
        while dse_changed:
            dse_changed = False
            used_vars: Set[str] = set()
            for blk in blocks.values():
                for phi in blk.phi_nodes:
                    for item in (phi.src1 or "").split(","):
                        if ":" in item:
                            _, v_tok = item.split(":", 1)
                            v_tok = v_tok.strip()
                            if v_tok != phi.dest:
                                used_vars.add(v_tok)
                for ins in blk.instructions:
                    if ins.opcode == "STORE":
                        if ins.dest:
                            used_vars.add(ins.dest)
                        if ins.src1:
                            used_vars.add(ins.src1)
                    else:
                        if ins.src1:
                            used_vars.add(ins.src1)
                        if ins.src2:
                            used_vars.add(ins.src2)
                        # Preserve final return register definitions in exit blocks
                        if ins.opcode == "RET" and ins.dest:
                            used_vars.add(ins.dest)

            for blk in blocks.values():
                surviving_phis: List[UILInstruction] = []
                for phi in blk.phi_nodes:
                    if phi.dest and phi.dest not in used_vars:
                        dead_stores_eliminated += 1
                        dse_changed = True
                    else:
                        surviving_phis.append(phi)
                blk.phi_nodes = surviving_phis

                surviving_ins: List[UILInstruction] = []
                for ins in blk.instructions:
                    if ins.opcode in ("ASSIGN", "ADD", "SUB", "MUL", "AND", "OR", "XOR", "SHL", "SHR"):
                        if ins.dest and ins.dest not in used_vars:
                            dead_stores_eliminated += 1
                            dse_changed = True
                            continue
                    surviving_ins.append(ins)
                blk.instructions = surviving_ins

        return SSAOptimizationReport(
            entry_block=entry_id,
            total_blocks=len(blocks),
            phi_nodes_inserted=phi_count,
            constants_propagated=constants_propagated,
            copies_propagated=copies_propagated,
            dead_stores_eliminated=dead_stores_eliminated,
            dominators=idom,
            dominance_frontiers={k: sorted(v) for k, v in df.items()},
            blocks=blocks,
        )

    @staticmethod
    def _eval_binop(opcode: str, c1: int, c2: int) -> int:
        if opcode == "ADD":
            return c1 + c2
        if opcode == "SUB":
            return c1 - c2
        if opcode == "MUL":
            return c1 * c2
        if opcode == "AND":
            return c1 & c2
        if opcode == "OR":
            return c1 | c2
        if opcode == "XOR":
            return c1 ^ c2
        if opcode == "SHL":
            return c1 << max(0, min(63, c2))
        if opcode == "SHR":
            return c1 >> max(0, min(63, c2))
        return c1
