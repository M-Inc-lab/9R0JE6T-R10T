"""
R3V3R53//F0RG3 — Linux/POSIX Isolated Runner & strace/gdb Telemetry Parser (§07, §08, §15.2)
Generates namespace-isolated Linux runner profiles (bubblewrap / network-disabled container)
and parses strace syscall logs and gdb batch crash traces into BehavioralTelemetryEngine events.
"""

import json
import os
import re
import shlex
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from reverse_forge.behavioral_engine import (
    BehavioralTelemetryEngine,
    CrashEvent,
    FileEvent,
    NetworkEvent,
    ProcessEvent,
)


class POSIXSandboxEngine:
    """Generates isolated Linux dynamic analysis runners and parses strace/gdb telemetry."""

    EXECVE_RE = re.compile(
        r'^(?:(\d+)\s+)?([\d.:]+)?\s*execve\("([^"]+)",\s*\[([^\]]*)\]',
        re.MULTILINE,
    )
    OPENAT_RE = re.compile(
        r'^(?:(\d+)\s+)?([\d.:]+)?\s*(?:openat|open|creat|unlink|unlinkat)\([^"]*"([^"]+)",\s*([A-Z_|0-9x]+)',
        re.MULTILINE,
    )
    CONNECT_RE = re.compile(
        r'^(?:(\d+)\s+)?([\d.:]+)?\s*connect\(\d+,\s*\{[^}]*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)',
        re.MULTILINE,
    )
    GDB_SIG_RE = re.compile(
        r"Program received signal\s+(SIG[A-Z0-9]+)",
        re.IGNORECASE,
    )
    GDB_ADDR_RE = re.compile(
        r"0x([0-9a-fA-F]{4,16})\s+in\s+([^\s(]+)",
    )

    def __init__(self, target_filepath: str):
        self.target_filepath = os.path.abspath(target_filepath)
        self.filename = os.path.basename(self.target_filepath)

    def generate_isolated_runner_script(self, output_sh_path: str, timeout_sec: int = 30) -> str:
        """
        Generate a shell-safe bubblewrap / container isolated strace runner script.
        Never executes the target on the host OS directly (§15.2).
        """
        safe_filename = shlex.quote(f"/sandbox/{self.filename}")
        safe_host_path = shlex.quote(self.target_filepath)
        timeout_int = max(1, min(int(timeout_sec), 300))

        script = f"""#!/usr/bin/env bash
# R3V3R53//F0RG3 Isolated Linux/POSIX Dynamic Analysis Runner (§07.1, §15.2)
# Enforces network isolation (--unshare-net), PID/IPC/UTS namespace isolation, and read-only mounts.
set -euo pipefail

HOST_BINARY={safe_host_path}
SANDBOX_BIN={safe_filename}
TRACE_OUT="${{1:-strace_telemetry.log}}"
TIMEOUT_SEC={timeout_int}

if ! command -v bwrap >/dev/null 2>&1; then
    echo "[-] Error: bubblewrap (bwrap) is required for safe namespace isolation." >&2
    exit 1
fi

echo "[*] Launching isolated namespace trace for ${{HOST_BINARY}} (timeout: ${{TIMEOUT_SEC}}s)..."
timeout --kill-after=5s "${{TIMEOUT_SEC}}s" bwrap \\
    --unshare-all \\
    --die-with-parent \\
    --ro-bind /usr /usr \\
    --ro-bind /lib /lib \\
    --ro-bind-try /lib64 /lib64 \\
    --ro-bind /bin /bin \\
    --proc /proc \\
    --dev /dev \\
    --tmpfs /tmp \\
    --tmpfs /sandbox \\
    --ro-bind "${{HOST_BINARY}}" "${{SANDBOX_BIN}}" \\
    -- strace -f -ttt -s 128 -e trace=process,file,network -o "/tmp/trace.log" "${{SANDBOX_BIN}}" || true

echo "[+] Trace session completed."
"""
        with open(output_sh_path, "w", encoding="utf-8") as f:
            f.write(script)
        if os.name == "posix":
            os.chmod(output_sh_path, 0o755)
        return os.path.abspath(output_sh_path)

    @classmethod
    def parse_strace_output(
        cls,
        strace_text: str,
        engine: Optional[BehavioralTelemetryEngine] = None,
        default_process: str = "target.elf",
    ) -> BehavioralTelemetryEngine:
        """Parse strace log lines into BehavioralTelemetryEngine events."""
        b_engine = engine or BehavioralTelemetryEngine()

        for m in cls.EXECVE_RE.finditer(strace_text):
            pid = int(m.group(1) or 1000)
            ts = m.group(2) or "0.0"
            img = m.group(3)
            argv = m.group(4).replace('"', "")
            b_engine.record_process_event(ProcessEvent(
                timestamp=ts,
                pid=pid,
                parent_pid=max(1, pid - 1),
                image_path=img,
                command_line=argv,
                action="SPAWNED",
            ))

        for m in cls.OPENAT_RE.finditer(strace_text):
            ts = m.group(2) or "0.0"
            fpath = m.group(3)
            flags = m.group(4)
            op = "WRITE" if any(w in flags for w in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC")) else "READ"
            b_engine.record_file_event(FileEvent(
                timestamp=ts,
                path=fpath,
                operation=op,
                process_name=default_process,
            ))

        for m in cls.CONNECT_RE.finditer(strace_text):
            ts = m.group(2) or "0.0"
            port = int(m.group(3))
            dip = m.group(4)
            b_engine.record_network_event(NetworkEvent(
                timestamp=ts,
                source_ip="127.0.0.1",
                source_port=0,
                destination_ip=dip,
                destination_port=port,
                protocol="TCP",
                data_summary=f"strace connect() to {dip}:{port}",
            ))

        return b_engine

    @classmethod
    def parse_gdb_crash_output(
        cls,
        gdb_text: str,
        engine: Optional[BehavioralTelemetryEngine] = None,
        default_process: str = "target.elf",
    ) -> BehavioralTelemetryEngine:
        """Parse batch GDB crash output into CrashEvent records."""
        b_engine = engine or BehavioralTelemetryEngine()
        sig_match = cls.GDB_SIG_RE.search(gdb_text)
        if not sig_match:
            return b_engine

        sig_name = sig_match.group(1).upper()
        addr_match = cls.GDB_ADDR_RE.search(gdb_text)
        fault_addr = f"0x{addr_match.group(1)}" if addr_match else "0x0"
        fn_name = addr_match.group(2) if addr_match else "unknown"

        b_engine.record_crash_event(CrashEvent(
            timestamp="0.0",
            process_name=default_process,
            fault_address=fault_addr,
            exception_code=sig_name,
            register_state={"function": fn_name},
            stack_trace=[f"{fault_addr} in {fn_name}"],
        ))
        return b_engine

    @classmethod
    def export_telemetry_json(
        cls,
        b_engine: BehavioralTelemetryEngine,
        output_json_path: str,
    ) -> str:
        payload = {
            "processes": [asdict(p) for p in b_engine.process_events],
            "files": [asdict(f) for f in b_engine.file_events],
            "registry": [asdict(r) for r in b_engine.registry_events],
            "network": [asdict(n) for n in b_engine.network_events],
            "crashes": [asdict(c) for c in b_engine.crash_events],
        }
        with open(output_json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return os.path.abspath(output_json_path)
