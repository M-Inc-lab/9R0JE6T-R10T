"""
R3V3R53//F0RG3 — Fine-Grained Assembly & Memory Taint Propagation Engine (§23)
Tracks register and memory slot taint across low-level instructions (x86/x64/ARM),
enforcing taint rules across data-movement, pointer calculations, and sink arguments.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Set, Tuple


class TaintTag(IntEnum):
    CLEAN = 0
    TAINTED_INPUT = 1
    TAINTED_LENGTH = 2
    TAINTED_POINTER = 3


@dataclass
class TaintSinkViolation:
    sink_name: str
    violation_type: str
    cwe_id: str
    trigger_instruction: str
    tainted_operand: str
    taint_source: str
    taint_tag_name: str
    trace_log: List[str] = field(default_factory=list)


@dataclass
class FunctionTaintSummary:
    function_name: str
    param_to_return_taint: Set[int] = field(default_factory=set)
    param_to_sink_violations: Dict[int, List[Tuple[str, str, str]]] = field(default_factory=dict)


class FineGrainedTaintTracker:
    """
    Performs instruction-level taint propagation across registers and abstract memory cells.
    Detects when untrusted inputs flow unchecked into length, pointer, command, or format sinks.
    """

    # Register sets for x86/x64 aliases
    REG_ALIASES: Dict[str, str] = {
        "rax": "rax", "eax": "rax", "ax": "rax", "al": "rax",
        "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx",
        "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx",
        "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx",
        "rsi": "rsi", "esi": "rsi", "si": "rsi",
        "rdi": "rdi", "edi": "rdi", "di": "rdi",
        "rbp": "rbp", "ebp": "rbp", "bp": "rbp",
        "rsp": "rsp", "esp": "rsp", "sp": "rsp",
        "r8": "r8", "r8d": "r8", "r8w": "r8", "r8b": "r8",
        "r9": "r9", "r9d": "r9", "r9w": "r9", "r9b": "r9",
        "r10": "r10", "r10d": "r10", "r11": "r11", "r11d": "r11",
        "r12": "r12", "r12d": "r12", "r13": "r13", "r13d": "r13",
        "r14": "r14", "r14d": "r14", "r15": "r15", "r15d": "r15",
    }

    # High-risk security sink definitions: (sink_name -> {param_idx: (expected_tag, cwe, violation_name)})
    # Calling convention default: AMD64 (rdi=0, rsi=1, rdx=2, rcx=3, r8=4, r9=5)
    SINK_RULES: Dict[str, Dict[int, Tuple[str, str]]] = {
        "memcpy": {
            2: ("CWE-119", "TAINTED_LENGTH_ARGUMENT"),  # size parameter in rdx
            1: ("CWE-120", "TAINTED_BUFFER_SOURCE"),   # src buffer in rsi
        },
        "memmove": {
            2: ("CWE-119", "TAINTED_LENGTH_ARGUMENT"),
        },
        "strcpy": {
            1: ("CWE-120", "TAINTED_STRING_COPY"),     # src in rsi
        },
        "strncpy": {
            2: ("CWE-119", "TAINTED_LENGTH_ARGUMENT"), # max length in rdx
        },
        "sprintf": {
            1: ("CWE-134", "TAINTED_FORMAT_STRING"),   # format in rsi
        },
        "printf": {
            0: ("CWE-134", "TAINTED_FORMAT_STRING"),   # format in rdi
        },
        "system": {
            0: ("CWE-78", "TAINTED_COMMAND_EXECUTION"), # cmd in rdi
        },
        "popen": {
            0: ("CWE-78", "TAINTED_COMMAND_EXECUTION"),
        },
        "WinExec": {
            0: ("CWE-78", "TAINTED_COMMAND_EXECUTION"),
        },
    }

    ARG_REGS_AMD64 = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    ARG_REGS_WIN64 = ["rcx", "rdx", "r8", "r9"]

    def __init__(self, calling_convention: str = "amd64"):
        self.calling_convention = calling_convention.lower()
        self.reg_taint: Dict[str, Tuple[TaintTag, str]] = {}
        self.mem_taint: Dict[str, Tuple[TaintTag, str]] = {}
        self.trace_log: List[str] = []

    def _canonical_reg(self, reg_name: str) -> str:
        cleaned = reg_name.strip().lower().lstrip("%$")
        return self.REG_ALIASES.get(cleaned, cleaned)

    @staticmethod
    def _canonical_mem(mem_expr: str) -> str:
        return "".join(mem_expr.strip("[]* ").split()).lower()

    def mark_tainted(
        self,
        target: str,
        tag: TaintTag = TaintTag.TAINTED_INPUT,
        source: str = "external_network_input",
    ) -> None:
        """Explicitly inject a taint marker into a register or memory location."""
        if target.startswith("[") or target.startswith("*"):
            clean_loc = self._canonical_mem(target)
            self.mem_taint[clean_loc] = (tag, source)
            self.trace_log.append(f"TAINT_INJECT: Mem[{clean_loc}] marked as {tag.name} from {source}")
        else:
            canon = self._canonical_reg(target)
            self.reg_taint[canon] = (tag, source)
            self.trace_log.append(f"TAINT_INJECT: Reg[{canon}] marked as {tag.name} from {source}")

    def clear_taint(self, target: str) -> None:
        if target.startswith("[") or target.startswith("*"):
            clean_loc = self._canonical_mem(target)
            if clean_loc in self.mem_taint:
                del self.mem_taint[clean_loc]
                self.trace_log.append(f"TAINT_CLEAR: Mem[{clean_loc}] cleared")
            return
        canon = self._canonical_reg(target)
        if canon in self.reg_taint:
            del self.reg_taint[canon]
            self.trace_log.append(f"TAINT_CLEAR: Reg[{canon}] cleared")

    def get_taint(self, operand: str) -> Tuple[TaintTag, str]:
        cleaned = operand.strip()
        if cleaned.startswith("[") or cleaned.startswith("*"):
            loc = self._canonical_mem(cleaned)
            return self.mem_taint.get(loc, (TaintTag.CLEAN, ""))
        canon = self._canonical_reg(cleaned)
        return self.reg_taint.get(canon, (TaintTag.CLEAN, ""))

    def step_instruction(
        self,
        mnemonic: str,
        operands: List[str],
        raw_text: str = "",
    ) -> Optional[TaintSinkViolation]:
        """
        Processes a single disassembled instruction and propagates or checks taints.
        Returns a TaintSinkViolation if a tainted operand flows into a prohibited sink.
        """
        op = mnemonic.strip().lower()
        display_text = raw_text or f"{mnemonic} {', '.join(operands)}"

        # 1. Zeroing idioms: xor reg, reg or sub reg, reg
        if op in ("xor", "sub", "pxor") and len(operands) >= 2:
            dst = self._canonical_reg(operands[0])
            src = self._canonical_reg(operands[1])
            if dst == src:
                self.clear_taint(dst)
                return None

        # 2. Data movement: mov, movzx, movsx, ldr, str
        if op in ("mov", "movzx", "movsx", "ldr") and len(operands) >= 2:
            dst_str, src_str = operands[0].strip(), operands[1].strip()
            src_tag, src_origin = self.get_taint(src_str)
            if src_tag != TaintTag.CLEAN:
                if dst_str.startswith("["):
                    mem_loc = self._canonical_mem(dst_str)
                    self.mem_taint[mem_loc] = (src_tag, src_origin)
                    self.trace_log.append(f"TAINT_PROPAGATE: {src_str} -> Mem[{mem_loc}] ({src_tag.name})")
                else:
                    canon_dst = self._canonical_reg(dst_str)
                    self.reg_taint[canon_dst] = (src_tag, src_origin)
                    self.trace_log.append(f"TAINT_PROPAGATE: {src_str} -> Reg[{canon_dst}] ({src_tag.name})")
            else:
                # Clean source overwrites destination register or memory cell
                self.clear_taint(dst_str)
            return None

        # 3. Pointer calculation: lea reg, [base + off]
        if op == "lea" and len(operands) >= 2:
            dst_str, src_str = operands[0].strip(), operands[1].strip()
            src_tag, src_origin = self.get_taint(src_str)
            canon_dst = self._canonical_reg(dst_str)
            if src_tag != TaintTag.CLEAN:
                self.reg_taint[canon_dst] = (TaintTag.TAINTED_POINTER, src_origin)
                self.trace_log.append(f"TAINT_LEA: {src_str} -> Reg[{canon_dst}] (TAINTED_POINTER)")
            else:
                self.clear_taint(canon_dst)
            return None

        # 4. Arithmetic propagation: add, sub, mul, imul, shl
        if op in ("add", "sub", "imul", "shl", "shr") and len(operands) >= 2:
            dst_str, src_str = operands[0].strip(), operands[1].strip()
            dst_tag, dst_origin = self.get_taint(dst_str)
            src_tag, src_origin = self.get_taint(src_str)
            canon_dst = self._canonical_reg(dst_str)
            if dst_tag != TaintTag.CLEAN or src_tag != TaintTag.CLEAN:
                dominant_tag = max(dst_tag, src_tag)
                origin = dst_origin or src_origin
                self.reg_taint[canon_dst] = (dominant_tag, origin)
                self.trace_log.append(f"TAINT_ARITH: {op} on {dst_str}, {src_str} yields Reg[{canon_dst}] ({dominant_tag.name})")
            return None

        # 5. Call invocation & dangerous sink check
        if op in ("call", "bl") and operands:
            target_fn = operands[0].strip().lstrip("_@")
            arg_regs = self.ARG_REGS_WIN64 if self.calling_convention == "win64" else self.ARG_REGS_AMD64

            # Check if calling a recognized dangerous sink
            if target_fn in self.SINK_RULES:
                rules = self.SINK_RULES[target_fn]
                for param_idx, (cwe, violation_name) in rules.items():
                    if param_idx < len(arg_regs):
                        reg_name = arg_regs[param_idx]
                        tag, origin = self.get_taint(reg_name)
                        if tag != TaintTag.CLEAN:
                            violation = TaintSinkViolation(
                                sink_name=target_fn,
                                violation_type=violation_name,
                                cwe_id=cwe,
                                trigger_instruction=display_text,
                                tainted_operand=reg_name,
                                taint_source=origin,
                                taint_tag_name=tag.name,
                                trace_log=list(self.trace_log),
                            )
                            self.trace_log.append(f"TAINT_VIOLATION: Sink {target_fn} received {tag.name} in {reg_name}")
                            return violation

            # If calling a source function like 'recv', 'read', return register (rax) becomes tainted
            if target_fn in ("recv", "read", "fgets", "fread", "WSARecv", "scanf"):
                self.reg_taint["rax"] = (TaintTag.TAINTED_LENGTH, target_fn)
                self.trace_log.append(f"TAINT_SOURCE_CALL: {target_fn} tainted return Reg[rax]")

        # 6. Indirect call/jump through tainted register (CWE-822)
        if op in ("call", "jmp") and operands:
            target_op = operands[0].strip()
            canon_target = self._canonical_reg(target_op)
            is_register_or_ptr = (
                canon_target in self.REG_ALIASES
                or target_op.startswith("[")
                or target_op.startswith("*")
            )
            if is_register_or_ptr:
                tag, origin = self.get_taint(target_op)
                if tag in (TaintTag.TAINTED_POINTER, TaintTag.TAINTED_INPUT):
                    return TaintSinkViolation(
                        sink_name="indirect_control_transfer",
                        violation_type="TAINTED_FUNCTION_POINTER_CALL",
                        cwe_id="CWE-822",
                        trigger_instruction=display_text,
                        tainted_operand=target_op,
                        taint_source=origin,
                        taint_tag_name=tag.name,
                        trace_log=list(self.trace_log),
                    )

        return None

    def analyze_linear_trace(
        self,
        instructions: List[Tuple[str, List[str]]],
    ) -> List[TaintSinkViolation]:
        """Execute a linear instruction sequence and collect all sink violations."""
        violations: List[TaintSinkViolation] = []
        for mnemonic, operands in instructions:
            v = self.step_instruction(mnemonic, operands)
            if v:
                violations.append(v)
        return violations

    def get_active_taints(self) -> Dict[str, str]:
        """Return currently tainted registers and memory slots."""
        active: Dict[str, str] = {}
        for reg, (tag, src) in self.reg_taint.items():
            active[f"Reg:{reg}"] = f"{tag.name} (from {src})"
        for mem, (tag, src) in self.mem_taint.items():
            active[f"Mem:{mem}"] = f"{tag.name} (from {src})"
        return active

    ARG_REGS_ARM64 = ["x0", "x1", "x2", "x3", "x4", "x5"]
    ARG_REGS_MIPS = ["a0", "a1", "a2", "a3"]

    def _arg_regs_for_arch(self) -> List[str]:
        if self.calling_convention in ("arm64", "aarch64"):
            return self.ARG_REGS_ARM64
        if self.calling_convention in ("mips", "mips32", "mips64"):
            return self.ARG_REGS_MIPS
        if self.calling_convention == "win64":
            return self.ARG_REGS_WIN64
        return self.ARG_REGS_AMD64

    def _ret_reg_for_arch(self) -> str:
        if self.calling_convention in ("arm64", "aarch64"):
            return "x0"
        if self.calling_convention in ("mips", "mips32", "mips64"):
            return "v0"
        return "rax"

    def step_uil_instruction(
        self,
        uil_ins: Any,
        function_summaries: Optional[Dict[str, "FunctionTaintSummary"]] = None,
    ) -> Optional[TaintSinkViolation]:
        """
        Phase 34: Architecture-agnostic taint propagation directly over UnifiedIL (UILInstruction)
        for x86/x64, ARM64, and MIPS32, with interprocedural function summary application.
        """
        op = uil_ins.opcode.upper()
        dst = (uil_ins.dest or "").strip()
        s1 = (uil_ins.src1 or "").strip()
        s2 = (uil_ins.src2 or "").strip()
        raw = uil_ins.raw_assembly or f"{op} {dst}, {s1}, {s2}"

        if op == "ASSIGN" and dst:
            canon_dst = self._canonical_reg(dst)
            t1, orig1 = self.get_taint(s1) if s1 else (TaintTag.CLEAN, "")
            if t1 != TaintTag.CLEAN:
                self.reg_taint[canon_dst] = (t1, orig1)
                self.trace_log.append(f"UIL_ASSIGN: {s1} -> Reg[{canon_dst}] ({t1.name})")
            else:
                self.clear_taint(canon_dst)
            return None

        if op == "LOAD" and dst and s1:
            mem_key = self._normalize_mem_expr(f"[{self._canonical_reg(s1)}+{uil_ins.offset}]")
            t_mem, orig_mem = self.mem_taint.get(mem_key, (TaintTag.CLEAN, ""))
            if t_mem == TaintTag.CLEAN:
                t_mem, orig_mem = self.get_taint(s1)
            canon_dst = self._canonical_reg(dst)
            if t_mem != TaintTag.CLEAN:
                self.reg_taint[canon_dst] = (t_mem, orig_mem)
                self.trace_log.append(f"UIL_LOAD: {mem_key} -> Reg[{canon_dst}] ({t_mem.name})")
            else:
                self.clear_taint(canon_dst)
            return None

        if op == "STORE" and dst and s1:
            mem_key = self._normalize_mem_expr(f"[{self._canonical_reg(dst)}+{uil_ins.offset}]")
            t_src, orig_src = self.get_taint(s1)
            if t_src != TaintTag.CLEAN:
                self.mem_taint[mem_key] = (t_src, orig_src)
                self.trace_log.append(f"UIL_STORE: Reg[{s1}] -> {mem_key} ({t_src.name})")
            else:
                self.mem_taint.pop(mem_key, None)
            return None

        if op in ("ADD", "SUB", "MUL", "AND", "OR", "XOR", "SHL", "SHR") and dst:
            canon_dst = self._canonical_reg(dst)
            if op == "XOR" and s1 and s2 and self._canonical_reg(s1) == self._canonical_reg(s2):
                self.clear_taint(canon_dst)
                return None
            t1, o1 = self.get_taint(s1) if s1 else (TaintTag.CLEAN, "")
            t2, o2 = self.get_taint(s2) if s2 else (TaintTag.CLEAN, "")
            if t1 != TaintTag.CLEAN or t2 != TaintTag.CLEAN:
                dom_tag = max(t1, t2)
                orig = o1 or o2
                self.reg_taint[canon_dst] = (dom_tag, orig)
                self.trace_log.append(f"UIL_{op}: ({s1}, {s2}) -> Reg[{canon_dst}] ({dom_tag.name})")
            else:
                self.clear_taint(canon_dst)
            return None

        if op == "CALL" and dst:
            target_fn = dst.lstrip("_@")
            arg_regs = self._arg_regs_for_arch()
            ret_reg = self._ret_reg_for_arch()

            # 1. Direct sink check
            if target_fn in self.SINK_RULES:
                for param_idx, (cwe, v_name) in self.SINK_RULES[target_fn].items():
                    if param_idx < len(arg_regs):
                        r_name = arg_regs[param_idx]
                        tag, origin = self.get_taint(r_name)
                        if tag != TaintTag.CLEAN:
                            return TaintSinkViolation(
                                sink_name=target_fn,
                                violation_type=v_name,
                                cwe_id=cwe,
                                trigger_instruction=raw,
                                tainted_operand=r_name,
                                taint_source=origin,
                                taint_tag_name=tag.name,
                                trace_log=list(self.trace_log),
                            )

            # 2. Interprocedural summary application
            if function_summaries and target_fn in function_summaries:
                summary = function_summaries[target_fn]
                for p_idx, sink_list in summary.param_to_sink_violations.items():
                    if p_idx < len(arg_regs):
                        r_name = arg_regs[p_idx]
                        tag, origin = self.get_taint(r_name)
                        if tag != TaintTag.CLEAN and sink_list:
                            sink_fn, cwe, v_name = sink_list[0]
                            return TaintSinkViolation(
                                sink_name=f"{target_fn}->{sink_fn}",
                                violation_type=f"INTERPROCEDURAL_{v_name}",
                                cwe_id=cwe,
                                trigger_instruction=raw,
                                tainted_operand=r_name,
                                taint_source=origin,
                                taint_tag_name=tag.name,
                                trace_log=list(self.trace_log),
                            )
                for p_idx in summary.param_to_return_taint:
                    if p_idx < len(arg_regs):
                        r_name = arg_regs[p_idx]
                        tag, origin = self.get_taint(r_name)
                        if tag != TaintTag.CLEAN:
                            self.reg_taint[self._canonical_reg(ret_reg)] = (tag, f"{origin} via {target_fn}")
                            self.trace_log.append(f"UIL_SUMMARY_RET: {target_fn} propagated param {p_idx} ({r_name}) -> {ret_reg}")

            # 3. Taint sources
            if target_fn in ("recv", "read", "fgets", "fread", "WSARecv", "scanf", "getenv"):
                self.reg_taint[self._canonical_reg(ret_reg)] = (TaintTag.TAINTED_INPUT, target_fn)
                if len(arg_regs) >= 2 and target_fn in ("recv", "read"):
                    self.reg_taint[self._canonical_reg(arg_regs[1])] = (TaintTag.TAINTED_INPUT, target_fn)

        return None

    def analyze_uil_stream(
        self,
        uil_instructions: List[Any],
        function_summaries: Optional[Dict[str, "FunctionTaintSummary"]] = None,
    ) -> List[TaintSinkViolation]:
        """Run architecture-agnostic taint tracking across a list of UILInstruction objects."""
        violations: List[TaintSinkViolation] = []
        for ins in uil_instructions:
            v = self.step_uil_instruction(ins, function_summaries=function_summaries)
            if v:
                violations.append(v)
        return violations

    @classmethod
    def compute_function_summary(
        cls,
        func_name: str,
        uil_instructions: List[Any],
        calling_convention: str = "amd64",
        existing_summaries: Optional[Dict[str, "FunctionTaintSummary"]] = None,
    ) -> "FunctionTaintSummary":
        """
        Phase 34: Bottom-up interprocedural summary generator.
        Tests each parameter register (0..3) with symbolic taint to determine whether
        it reaches the function's return register or triggers an internal security sink.
        """
        summary = FunctionTaintSummary(function_name=func_name)
        probe_tracker = cls(calling_convention=calling_convention)
        arg_regs = probe_tracker._arg_regs_for_arch()
        ret_reg = probe_tracker._canonical_reg(probe_tracker._ret_reg_for_arch())

        for p_idx in range(min(4, len(arg_regs))):
            t = cls(calling_convention=calling_convention)
            t.mark_tainted(arg_regs[p_idx], TaintTag.TAINTED_INPUT, f"param_{p_idx}")
            viols = t.analyze_uil_stream(uil_instructions, function_summaries=existing_summaries)
            if viols:
                summary.param_to_sink_violations[p_idx] = [
                    (v.sink_name, v.cwe_id, v.violation_type) for v in viols
                ]
            ret_tag, _ = t.get_taint(ret_reg)
            if ret_tag != TaintTag.CLEAN:
                summary.param_to_return_taint.add(p_idx)

        return summary


# Backward-compatible alias
FineGrainTaintEngine = FineGrainedTaintTracker
fine_grain_taint_engine = FineGrainedTaintTracker

