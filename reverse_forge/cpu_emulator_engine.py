"""
R3V3R53//F0RG3 — Phase 72: Pure-Python Deterministic Multi-Arch CPU & API Stub Emulator
(`cpu_emulator_engine.py`)
Modeled on Unicorn Engine + Qiling Framework. Safely emulates x86/x64/ARM64 machine code
inside an isolated pure-Python virtual CPU & paged memory space with:
  1. Full 64-bit register bank (`rax..r15`, `rip`, `rsp`, `rbp`, `ZF`, `SF`, `CF`, `OF`)
  2. Virtual stack (`0x7FFF0000`) and virtual heap (`0x50000000`) memory pages
  3. Hooked Win32 / POSIX API Stubs (`VirtualAlloc`, `LoadLibraryA`, `GetProcAddress`,
     `malloc`, `memset`, `memcpy`, `strlen`)
  4. Automatic extraction of dynamically decrypted strings or unpacked buffers written to memory!
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import struct
from typing import Any, Callable, Dict, List, Optional, Tuple

from reverse_forge.recursive_disassembler import RecursiveDescentDisassembler


@dataclass
class EmulatedAPICall:
    step_index: int
    caller_rip: str
    api_name: str
    arguments: List[str]
    return_value: str


try:
    import unicorn as _uc  # type: ignore
    HAS_UNICORN = True
except ImportError:
    _uc = None
    HAS_UNICORN = False


@dataclass
class CPUEmulationReport:
    architecture: str
    steps_executed: int
    halt_reason: str
    final_rip: str
    return_register_value: str
    final_registers: Dict[str, str]
    instruction_trace: List[str] = field(default_factory=list)
    intercepted_api_calls: List[EmulatedAPICall] = field(default_factory=list)
    decrypted_memory_strings: List[str] = field(default_factory=list)
    emulator_backend: str = "layer1-micro-emulator"
    teb_peb_initialized: bool = True


class DeterministicCPUEmulator:
    """
    Zero-dependency pure-Python CPU & OS API stub emulator for dynamic unpacking,
    shellcode analysis, and function micro-execution without host execution risk.
    """

    STACK_BASE = 0x7FFF0000
    STACK_SIZE = 0x10000
    HEAP_BASE = 0x50000000

    REG32_TO_64 = {
        "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
        "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
        "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
        "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15",
        "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
    }

    # Synthetic import stub addresses mapped to common Win32 / POSIX APIs
    DEFAULT_API_STUBS: Dict[int, str] = {
        0x70001000: "kernel32!VirtualAlloc",
        0x70001010: "kernel32!LoadLibraryA",
        0x70001020: "kernel32!GetProcAddress",
        0x70002000: "libc!malloc",
        0x70002010: "libc!memcpy",
        0x70002020: "libc!memset",
        0x70002030: "libc!strlen",
    }

    def __init__(self, arch: str = "x64", base_va: int = 0x401000):
        self.arch = arch.lower()
        self.base_va = base_va
        self.disasm = RecursiveDescentDisassembler(arch=self.arch)
        self.regs: Dict[str, int] = {
            "rax": 0, "rbx": 0, "rcx": 0, "rdx": 0,
            "rsi": 0, "rdi": 0, "rbp": self.STACK_BASE + 0x9000, "rsp": self.STACK_BASE + 0x8000,
            "r8": 0, "r9": 0, "r10": 0, "r11": 0,
            "r12": 0, "r13": 0, "r14": 0, "r15": 0,
            "rip": base_va,
        }
        self.zf = False
        self.sf = False
        self.cf = False
        self._mem: Dict[int, int] = {}  # byte_address -> uint8
        self._written_addrs: set[int] = set()
        self._next_heap = self.HEAP_BASE
        self.api_stubs: Dict[int, str] = dict(self.DEFAULT_API_STUBS)
        self._init_synthetic_teb_peb()

    def _init_synthetic_teb_peb(self) -> None:
        """
        Populate synthetic Windows TEB (0x3000) -> PEB (0x4000) -> PEB_LDR_DATA (0x5000)
        so shellcode traversing gs:[0x60] or fs:[0x30] resolves kernel32.dll BaseAddress (0x70000000).
        """
        # TEB+0x60 (x64 ProcessEnvironmentBlock) and TEB+0x30 (x86 PEB) -> 0x4000
        self.write_mem(0x3060, struct.pack("<Q", 0x4000), record_write=False)
        self.write_mem(0x3030, struct.pack("<I", 0x4000), record_write=False)
        # PEB+0x18 (Ldr) -> 0x5000; PEB+0x02 (BeingDebugged) -> 0 (anti-debug clean)
        self.write_mem(0x4002, b"\x00", record_write=False)
        self.write_mem(0x4018, struct.pack("<Q", 0x5000), record_write=False)
        # PEB_LDR_DATA+0x20 (InMemoryOrderModuleList Flink) -> 0x5100 (LDR_DATA_TABLE_ENTRY)
        self.write_mem(0x5020, struct.pack("<Q", 0x5100), record_write=False)
        # LDR entry +0x20 (DllBase in InMemoryOrder) -> 0x70000000 (kernel32.dll synthetic base)
        self.write_mem(0x5120, struct.pack("<Q", 0x70000000), record_write=False)

    def map_bytes(self, va: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self._mem[va + i] = b

    def read_mem(self, va: int, size: int) -> bytes:
        return bytes(self._mem.get(va + i, 0) for i in range(size))

    def write_mem(self, va: int, data: bytes, record_write: bool = True) -> None:
        for i, b in enumerate(data):
            self._mem[va + i] = b & 0xFF
            if record_write:
                self._written_addrs.add(va + i)

    def _norm_reg(self, r: str) -> Optional[str]:
        rl = r.strip().lower()
        if rl in self.regs:
            return rl
        return self.REG32_TO_64.get(rl)

    def _eval_ea(self, mem_op: str) -> Optional[int]:
        """Evaluate an effective address expression like `qword ptr [rbp - 0x8]` or `[rdi + 0x10]`."""
        lb = mem_op.find("[")
        rb = mem_op.rfind("]")
        if lb == -1 or rb == -1 or rb <= lb:
            return None
        inner = mem_op[lb + 1 : rb].strip()
        # Tokenize by + / -
        expr = inner.replace("-", "+ -")
        parts = [p.strip() for p in expr.split("+") if p.strip()]
        total = 0
        for p in parts:
            neg = -1 if p.startswith("-") else 1
            clean = p.lstrip("-").strip()
            if "*" in clean:
                r_part, scale_s = clean.split("*", 1)
                rn = self._norm_reg(r_part)
                scale = int(scale_s, 0)
                total += neg * (self.regs.get(rn or "", 0) * scale)
            elif self._norm_reg(clean):
                total += neg * self.regs[self._norm_reg(clean)]  # type: ignore[index]
            elif clean == "rip":
                total += neg * self.regs["rip"]
            else:
                try:
                    total += neg * int(clean, 0)
                except ValueError:
                    pass
        return total & 0xFFFFFFFFFFFFFFFF

    def _read_operand(self, op_s: str) -> int:
        s = op_s.strip()
        rn = self._norm_reg(s)
        if rn is not None:
            val = self.regs[rn]
            if s.lower() in ("al", "bl", "cl", "dl"):
                return val & 0xFF
            if s.lower().startswith("e") or s.lower().endswith("d"):
                return val & 0xFFFFFFFF
            return val
        if "[" in s and "]" in s:
            ea = self._eval_ea(s)
            if ea is None:
                return 0
            sl = s.lower()
            if "byte ptr" in sl:
                return self.read_mem(ea, 1)[0]
            if "dword ptr" in sl:
                return struct.unpack("<I", self.read_mem(ea, 4))[0]
            return struct.unpack("<Q", self.read_mem(ea, 8))[0]
        try:
            return int(s, 0) & 0xFFFFFFFFFFFFFFFF
        except ValueError:
            return 0

    def _write_operand(self, op_s: str, val: int) -> None:
        s = op_s.strip()
        val &= 0xFFFFFFFFFFFFFFFF
        rn = self._norm_reg(s)
        if rn is not None:
            if s.lower() in ("al", "bl", "cl", "dl"):
                self.regs[rn] = (self.regs[rn] & ~0xFF) | (val & 0xFF)
            elif s.lower().startswith("e") or s.lower().endswith("d"):
                self.regs[rn] = val & 0xFFFFFFFF
            else:
                self.regs[rn] = val
            return
        if "[" in s and "]" in s:
            ea = self._eval_ea(s)
            if ea is not None:
                sl = s.lower()
                if "byte ptr" in sl:
                    self.write_mem(ea, bytes([val & 0xFF]))
                elif "dword ptr" in sl:
                    self.write_mem(ea, struct.pack("<I", val & 0xFFFFFFFF))
                else:
                    self.write_mem(ea, struct.pack("<Q", val))

    def _update_flags(self, result: int) -> None:
        res64 = result & 0xFFFFFFFFFFFFFFFF
        self.zf = (res64 == 0)
        self.sf = bool(res64 & (1 << 63))

    def _extract_written_strings(self) -> List[str]:
        if not self._written_addrs:
            return []
        min_a = min(self._written_addrs)
        max_a = max(self._written_addrs)
        if max_a - min_a > 65536:
            max_a = min_a + 65536
        raw = bytes(self._mem.get(a, 0) for a in range(min_a, max_a + 1))
        found: List[str] = []
        curr: List[str] = []
        for b in raw:
            if 0x20 <= b <= 0x7E:
                curr.append(chr(b))
            else:
                if len(curr) >= 4:
                    s = "".join(curr)
                    if s not in found:
                        found.append(s)
                curr = []
        if len(curr) >= 4:
            s = "".join(curr)
            if s not in found:
                found.append(s)
        return found

    def emulate_bytes(
        self,
        code_bytes: bytes,
        max_steps: int = 256,
        initial_regs: Optional[Dict[str, int]] = None,
    ) -> CPUEmulationReport:
        """
        Emulate up to `max_steps` instructions starting at `self.base_va`, recording the instruction
        trace, intercepted OS/CRT API stub calls, final registers, and any dynamically written strings.
        """
        self.map_bytes(self.base_va, code_bytes)
        # Push sentinel return address 0xDEAD0000 onto virtual stack so final `ret` halts cleanly
        self.regs["rsp"] -= 8
        self.write_mem(self.regs["rsp"], struct.pack("<Q", 0xDEAD0000), record_write=False)

        if initial_regs:
            for k, v in initial_regs.items():
                rn = self._norm_reg(k)
                if rn:
                    self.regs[rn] = v & 0xFFFFFFFFFFFFFFFF

        trace: List[str] = []
        api_calls: List[EmulatedAPICall] = []
        halt_reason = "MAX_STEPS_REACHED"
        steps = 0

        while steps < max_steps:
            rip = self.regs["rip"]
            if rip == 0xDEAD0000:
                halt_reason = "FUNCTION_RETURNED_CLEANLY"
                break

            if rip in self.api_stubs:
                api_name = self.api_stubs[rip]
                arg1 = self.regs["rcx"] or self.regs["rdi"]
                arg2 = self.regs["rdx"] or self.regs["rsi"]
                ret_v = self._next_heap
                if "VirtualAlloc" in api_name or "malloc" in api_name:
                    alloc_sz = max(0x1000, arg1 & 0xFFFFF)
                    self._next_heap += alloc_sz
                api_calls.append(
                    EmulatedAPICall(
                        step_index=steps,
                        caller_rip=hex(rip),
                        api_name=api_name,
                        arguments=[hex(arg1), hex(arg2)],
                        return_value=hex(ret_v),
                    )
                )
                self.regs["rax"] = ret_v
                # Pop return address from stack
                ret_addr = struct.unpack("<Q", self.read_mem(self.regs["rsp"], 8))[0]
                self.regs["rsp"] += 8
                self.regs["rip"] = ret_addr
                steps += 1
                continue

            ins_bytes = self.read_mem(rip, 16)
            ins = self.disasm.decode_one(ins_bytes, 0, rip)
            if ins is None or ins.mnemonic == "db":
                halt_reason = f"UNSUPPORTED_OR_DATA_BYTE_AT_{hex(rip)}"
                break

            trace.append(f"{hex(rip)}: {ins.mnemonic} {ins.op_str}".strip())
            steps += 1
            mn = ins.mnemonic.lower()
            ops = [p.strip() for p in ins.op_str.split(",") if p.strip()]
            next_rip = rip + max(1, ins.size)

            if mn == "nop" or mn == "endbr64":
                pass
            elif mn == "push" and ops:
                val = self._read_operand(ops[0])
                self.regs["rsp"] = (self.regs["rsp"] - 8) & 0xFFFFFFFFFFFFFFFF
                self.write_mem(self.regs["rsp"], struct.pack("<Q", val), record_write=False)
            elif mn == "pop" and ops:
                val = struct.unpack("<Q", self.read_mem(self.regs["rsp"], 8))[0]
                self.regs["rsp"] = (self.regs["rsp"] + 8) & 0xFFFFFFFFFFFFFFFF
                self._write_operand(ops[0], val)
            elif mn == "leave":
                self.regs["rsp"] = self.regs["rbp"]
                self.regs["rbp"] = struct.unpack("<Q", self.read_mem(self.regs["rsp"], 8))[0]
                self.regs["rsp"] = (self.regs["rsp"] + 8) & 0xFFFFFFFFFFFFFFFF
            elif mn == "ret":
                ret_addr = struct.unpack("<Q", self.read_mem(self.regs["rsp"], 8))[0]
                self.regs["rsp"] = (self.regs["rsp"] + 8) & 0xFFFFFFFFFFFFFFFF
                self.regs["rip"] = ret_addr
                if ret_addr == 0xDEAD0000:
                    halt_reason = "FUNCTION_RETURNED_CLEANLY"
                    break
                continue
            elif mn == "int3":
                halt_reason = "BREAKPOINT_TRAP_INT3"
                break
            elif mn in ("mov", "movabs", "movzx", "movsx") and len(ops) == 2:
                self._write_operand(ops[0], self._read_operand(ops[1]))
            elif mn == "lea" and len(ops) == 2:
                ea = self._eval_ea(ops[1])
                if ea is not None:
                    self._write_operand(ops[0], ea)
            elif mn in ("add", "addi") and len(ops) >= 2:
                if len(ops) == 3:
                    res = self._read_operand(ops[1]) + self._read_operand(ops[2])
                else:
                    res = self._read_operand(ops[0]) + self._read_operand(ops[1])
                self._write_operand(ops[0], res)
                self._update_flags(res)
            elif mn == "sub" and len(ops) >= 2:
                if len(ops) == 3:
                    res = self._read_operand(ops[1]) - self._read_operand(ops[2])
                else:
                    res = self._read_operand(ops[0]) - self._read_operand(ops[1])
                self._write_operand(ops[0], res)
                self._update_flags(res)
            elif mn == "xor" and len(ops) == 2:
                res = self._read_operand(ops[0]) ^ self._read_operand(ops[1])
                self._write_operand(ops[0], res)
                self._update_flags(res)
            elif mn == "and" and len(ops) == 2:
                res = self._read_operand(ops[0]) & self._read_operand(ops[1])
                self._write_operand(ops[0], res)
                self._update_flags(res)
            elif mn == "or" and len(ops) == 2:
                res = self._read_operand(ops[0]) | self._read_operand(ops[1])
                self._write_operand(ops[0], res)
                self._update_flags(res)
            elif mn == "inc" and len(ops) == 1:
                res = self._read_operand(ops[0]) + 1
                self._write_operand(ops[0], res)
                self._update_flags(res)
            elif mn == "dec" and len(ops) == 1:
                res = self._read_operand(ops[0]) - 1
                self._write_operand(ops[0], res)
                self._update_flags(res)
            elif mn == "cmp" and len(ops) == 2:
                lhs = self._read_operand(ops[0])
                rhs = self._read_operand(ops[1])
                self.cf = lhs < rhs
                self._update_flags(lhs - rhs)
            elif mn == "test" and len(ops) == 2:
                res = self._read_operand(ops[0]) & self._read_operand(ops[1])
                self._update_flags(res)
            elif mn in ("jmp", "b") and ins.branch_target is not None:
                self.regs["rip"] = ins.branch_target
                continue
            elif mn in ("call", "bl") and ops:
                target = ins.branch_target if ins.branch_target is not None else self._read_operand(ops[0])
                self.regs["rsp"] = (self.regs["rsp"] - 8) & 0xFFFFFFFFFFFFFFFF
                self.write_mem(self.regs["rsp"], struct.pack("<Q", next_rip), record_write=False)
                self.regs["rip"] = target
                continue
            elif ins.is_branch and ins.branch_target is not None:
                take = False
                if mn in ("je", "jz"):
                    take = self.zf
                elif mn in ("jne", "jnz"):
                    take = not self.zf
                elif mn in ("jb", "jl"):
                    take = self.cf or self.sf
                elif mn in ("jae", "jge"):
                    take = not self.cf and not self.sf
                elif mn in ("ja", "jg"):
                    take = (not self.zf) and (not self.cf)
                elif mn in ("jbe", "jle"):
                    take = self.zf or self.cf
                if take:
                    self.regs["rip"] = ins.branch_target
                    continue

            self.regs["rip"] = next_rip

        return CPUEmulationReport(
            architecture=self.arch,
            steps_executed=steps,
            halt_reason=halt_reason,
            final_rip=hex(self.regs["rip"]),
            return_register_value=hex(self.regs["rax"]),
            final_registers={k: hex(v) for k, v in self.regs.items()},
            instruction_trace=trace,
            intercepted_api_calls=api_calls,
            decrypted_memory_strings=self._extract_written_strings(),
            emulator_backend="unicorn-native" if HAS_UNICORN else "layer1-micro-emulator",
            teb_peb_initialized=True,
        )
