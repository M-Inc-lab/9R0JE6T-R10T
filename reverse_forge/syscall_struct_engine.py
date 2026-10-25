"""
R3V3R53//F0RG3 — Phase 48: Direct Syscall ABI Resolver & Kaitai/ImHex C-Struct Template Parser
Modeled on:
  - Searchable Linux Syscall Tables (https://filippo.io/linux-syscall-table/) & Windows Native API Syscalls
  - Kaitai Struct (https://kaitai.io/) & ImHex Pattern Language (https://github.com/werwolv/imhex)
Provides:
  1. `resolve_direct_syscalls()`: Detects inline `syscall` (`0F 05`), `int 0x80` (`CD 80`), and ARM64
     `svc #0` (`01 00 00 D4`) instructions, tracks preceding immediate register assignments (`mov eax, N`),
     and maps syscall numbers to kernel syscall names, signatures, and security categories.
  2. `apply_c_struct_template()`: Parses a C `struct` declaration (`uint8_t`, `uint16_t`, `uint32_t`,
     `uint64_t`, `int32_t`, `float`, `double`, `char name[N]`) against any binary offset and returns
     decoded field-by-field values with exact byte offsets and sizes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
import struct
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ResolvedSyscallSite:
    file_offset: str
    virtual_address: str
    instruction_mnemonic: str       # syscall, int 0x80, svc #0
    abi_platform: str               # linux_x64, linux_x86, linux_arm64, windows_nt_x64
    syscall_number: Optional[int]
    syscall_name: str
    signature: str
    security_category: str


@dataclass
class ParsedStructField:
    field_name: str
    field_type: str
    relative_offset: int
    size_bytes: int
    value: Any
    hex_value: str


@dataclass
class ParsedCStructResult:
    struct_name: str
    base_offset: int
    total_size_bytes: int
    fields: List[ParsedStructField] = field(default_factory=list)


class SyscallAndStructEngine:
    """
    Resolves direct kernel syscalls in static/evasive binaries and overlays declarative
    C-struct templates over raw binary offsets.
    """

    LINUX_X64_SYSCALLS: Dict[int, Tuple[str, str, str]] = {
        0: ("sys_read", "ssize_t read(int fd, void *buf, size_t count)", "FILESYSTEM_IO"),
        1: ("sys_write", "ssize_t write(int fd, const void *buf, size_t count)", "FILESYSTEM_IO"),
        2: ("sys_open", "int open(const char *filename, int flags, mode_t mode)", "FILESYSTEM_IO"),
        3: ("sys_close", "int close(int fd)", "FILESYSTEM_IO"),
        9: ("sys_mmap", "void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)", "MEMORY_MANAGEMENT"),
        10: ("sys_mprotect", "int mprotect(void *addr, size_t len, int prot)", "MEMORY_MANAGEMENT_RWX"),
        39: ("sys_getpid", "pid_t getpid(void)", "PROCESS_INFO"),
        41: ("sys_socket", "int socket(int domain, int type, int protocol)", "NETWORK_SOCKET"),
        42: ("sys_connect", "int connect(int sockfd, const struct sockaddr *addr, socklen_t len)", "NETWORK_SOCKET"),
        49: ("sys_bind", "int bind(int sockfd, const struct sockaddr *addr, socklen_t len)", "NETWORK_SOCKET"),
        50: ("sys_listen", "int listen(int sockfd, int backlog)", "NETWORK_SOCKET"),
        56: ("sys_clone", "long clone(unsigned long flags, void *stack, ...)", "PROCESS_CREATION"),
        57: ("sys_fork", "pid_t fork(void)", "PROCESS_CREATION"),
        59: ("sys_execve", "int execve(const char *filename, char *const argv[], char *const envp[])", "COMMAND_EXECUTION"),
        60: ("sys_exit", "void exit(int status)", "PROCESS_CONTROL"),
        62: ("sys_kill", "int kill(pid_t pid, int sig)", "PROCESS_CONTROL"),
        101: ("sys_ptrace", "long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data)", "ANTI_DEBUG_OR_INJECTION"),
        257: ("sys_openat", "int openat(int dfd, const char *filename, int flags, mode_t mode)", "FILESYSTEM_IO"),
        319: ("sys_memfd_create", "int memfd_create(const char *uname, unsigned int flags)", "FILELESS_EXECUTION"),
        322: ("sys_execveat", "int execveat(int fd, const char *path, char *const argv[], char *const envp[], int flags)", "COMMAND_EXECUTION"),
    }

    WINDOWS_NT_X64_SYSCALLS: Dict[int, Tuple[str, str, str]] = {
        0x18: ("NtAllocateVirtualMemory", "NTSTATUS NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)", "MEMORY_MANAGEMENT_RWX"),
        0x26: ("NtOpenProcess", "NTSTATUS NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)", "PROCESS_INJECTION"),
        0x3A: ("NtWriteVirtualMemory", "NTSTATUS NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)", "PROCESS_INJECTION"),
        0x50: ("NtProtectVirtualMemory", "NTSTATUS NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)", "MEMORY_MANAGEMENT_RWX"),
        0xC1: ("NtCreateThreadEx", "NTSTATUS NtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, ...)", "PROCESS_INJECTION"),
    }

    C_TYPE_FORMATS: Dict[str, Tuple[str, int]] = {
        "uint8_t": ("<B", 1), "u8": ("<B", 1), "unsigned char": ("<B", 1), "byte": ("<B", 1),
        "int8_t": ("<b", 1), "i8": ("<b", 1), "char": ("<b", 1),
        "uint16_t": ("<H", 2), "u16": ("<H", 2), "unsigned short": ("<H", 2), "word": ("<H", 2),
        "int16_t": ("<h", 2), "i16": ("<h", 2), "short": ("<h", 2),
        "uint32_t": ("<I", 4), "u32": ("<I", 4), "unsigned int": ("<I", 4), "dword": ("<I", 4),
        "int32_t": ("<i", 4), "i32": ("<i", 4), "int": ("<i", 4),
        "uint64_t": ("<Q", 8), "u64": ("<Q", 8), "unsigned long long": ("<Q", 8), "qword": ("<Q", 8), "size_t": ("<Q", 8),
        "int64_t": ("<q", 8), "i64": ("<q", 8), "long long": ("<q", 8),
        "float": ("<f", 4),
        "double": ("<d", 8),
    }

    FIELD_RE = re.compile(
        r"^\s*([a-zA-Z0-9_]+(?:\s+[a-zA-Z0-9_]+)?)\s+([a-zA-Z_][a-zA-Z0-9_]*)(?:\[(\d+)\])?\s*;\s*$"
    )

    def resolve_direct_syscalls(
        self,
        code_bytes: bytes,
        base_va: int = 0x401000,
        platform_hint: str = "linux_x64",
    ) -> List[ResolvedSyscallSite]:
        """
        Scan machine code bytes for direct `syscall` (`0F 05`), `int 0x80` (`CD 80`),
        and ARM64 `svc #0` (`01 00 00 D4`), resolving preceding `eax`/`rax`/`w8` immediates.
        """
        sites: List[ResolvedSyscallSite] = []
        n = len(code_bytes)
        last_eax_imm: Optional[int] = None

        i = 0
        while i < n:
            b0 = code_bytes[i]

            # Track `xor eax, eax` (31 C0) -> eax = 0
            if i + 2 <= n and code_bytes[i : i + 2] == b"\x31\xc0":
                last_eax_imm = 0
                i += 2
                continue

            # Track `mov eax, imm32` (B8 imm32)
            if b0 == 0xB8 and i + 5 <= n:
                last_eax_imm = struct.unpack_from("<I", code_bytes, i + 1)[0]
                i += 5
                continue

            # Track `mov rax, imm32` (48 C7 C0 imm32)
            if i + 7 <= n and code_bytes[i : i + 3] == b"\x48\xc7\xc0":
                last_eax_imm = struct.unpack_from("<I", code_bytes, i + 3)[0]
                i += 7
                continue

            # Detect x86-64 `syscall` (0F 05)
            if i + 2 <= n and code_bytes[i : i + 2] == b"\x0f\x05":
                table = self.WINDOWS_NT_X64_SYSCALLS if "win" in platform_hint.lower() else self.LINUX_X64_SYSCALLS
                if last_eax_imm is not None and last_eax_imm in table:
                    name, sig, cat = table[last_eax_imm]
                else:
                    name = f"syscall_{last_eax_imm}" if last_eax_imm is not None else "syscall_dynamic_rax"
                    sig = f"long {name}(...)"
                    cat = "DIRECT_KERNEL_SYSCALL"
                sites.append(
                    ResolvedSyscallSite(
                        file_offset=hex(i),
                        virtual_address=hex(base_va + i),
                        instruction_mnemonic="syscall",
                        abi_platform=platform_hint,
                        syscall_number=last_eax_imm,
                        syscall_name=name,
                        signature=sig,
                        security_category=cat,
                    )
                )
                i += 2
                continue

            # Detect x86 `int 0x80` (CD 80)
            if i + 2 <= n and code_bytes[i : i + 2] == b"\xcd\x80":
                sites.append(
                    ResolvedSyscallSite(
                        file_offset=hex(i),
                        virtual_address=hex(base_va + i),
                        instruction_mnemonic="int 0x80",
                        abi_platform="linux_x86",
                        syscall_number=last_eax_imm,
                        syscall_name=f"sys_x86_{last_eax_imm}" if last_eax_imm is not None else "sys_x86_dynamic",
                        signature="int syscall_int80(...)",
                        security_category="LEGACY_X86_SYSCALL",
                    )
                )
                i += 2
                continue

            # Detect ARM64 `svc #0` (01 00 00 D4)
            if i + 4 <= n and code_bytes[i : i + 4] == b"\x01\x00\x00\xd4":
                sites.append(
                    ResolvedSyscallSite(
                        file_offset=hex(i),
                        virtual_address=hex(base_va + i),
                        instruction_mnemonic="svc #0",
                        abi_platform="linux_arm64",
                        syscall_number=last_eax_imm,
                        syscall_name=f"arm64_svc_{last_eax_imm}" if last_eax_imm is not None else "arm64_svc",
                        signature="long arm64_svc(...)",
                        security_category="ARM64_SUPERVISOR_CALL",
                    )
                )
                i += 4
                continue

            i += 1

        return sites

    def apply_c_struct_template(
        self,
        binary_bytes: bytes,
        c_struct_source: str,
        base_offset: int = 0,
    ) -> ParsedCStructResult:
        """
        Overlay a Kaitai/ImHex/010-Editor style C struct definition onto `binary_bytes[base_offset:]`
        and unpack each typed field or fixed-length array.
        Example:
            struct PacketHeader {
                uint32_t magic;
                uint16_t version;
                uint16_t length;
                char tag[8];
            };
        """
        m_name = re.search(r"struct\s+([a-zA-Z_][a-zA-Z0-9_]*)", c_struct_source)
        struct_name = m_name.group(1) if m_name else "AnonymousStruct"

        body_match = re.search(r"\{([^}]*)\}", c_struct_source, re.DOTALL)
        body_text = body_match.group(1) if body_match else c_struct_source

        curr_rel = 0
        fields: List[ParsedStructField] = []

        for raw_stmt in body_text.split(";"):
            stmt = raw_stmt.strip()
            if not stmt:
                continue
            m_f = self.FIELD_RE.match(stmt + ";")
            if not m_f:
                continue
            f_type = " ".join(m_f.group(1).strip().lower().split())
            f_name = m_f.group(2).strip()
            arr_count = int(m_f.group(3)) if m_f.group(3) else 1

            abs_off = base_offset + curr_rel
            if f_type in ("char", "u8", "uint8_t", "byte") and arr_count > 1:
                raw_slice = binary_bytes[abs_off : abs_off + arr_count].ljust(arr_count, b"\x00")
                if f_type == "char":
                    val: Any = raw_slice.split(b"\x00", 1)[0].decode("ascii", errors="replace")
                else:
                    val = list(raw_slice)
                fields.append(
                    ParsedStructField(
                        field_name=f_name,
                        field_type=f"{f_type}[{arr_count}]",
                        relative_offset=curr_rel,
                        size_bytes=arr_count,
                        value=val,
                        hex_value=raw_slice.hex(),
                    )
                )
                curr_rel += arr_count
            elif f_type in self.C_TYPE_FORMATS:
                fmt, elem_sz = self.C_TYPE_FORMATS[f_type]
                total_sz = elem_sz * arr_count
                raw_slice = binary_bytes[abs_off : abs_off + total_sz].ljust(total_sz, b"\x00")
                if arr_count == 1:
                    val = struct.unpack_from(fmt, raw_slice, 0)[0]
                    if isinstance(val, float):
                        val = round(val, 6)
                    hex_v = hex(val) if isinstance(val, int) else raw_slice.hex()
                else:
                    val = [struct.unpack_from(fmt, raw_slice, k * elem_sz)[0] for k in range(arr_count)]
                    hex_v = raw_slice.hex()
                fields.append(
                    ParsedStructField(
                        field_name=f_name,
                        field_type=f"{f_type}[{arr_count}]" if arr_count > 1 else f_type,
                        relative_offset=curr_rel,
                        size_bytes=total_sz,
                        value=val,
                        hex_value=hex_v,
                    )
                )
                curr_rel += total_sz

        return ParsedCStructResult(
            struct_name=struct_name,
            base_offset=base_offset,
            total_size_bytes=curr_rel,
            fields=fields,
        )
