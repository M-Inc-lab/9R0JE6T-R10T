"""
R3V3R53//F0RG3  Interactive REPL — Stateful Cross-Platform TUI Workbench (v7.0)
===============================================================================
A polished, stateful interactive reverse-engineering shell wrapping all 54
subcommands of the reverse_forge CLI plus instant target-aware workspace commands:
  - `load <file>` / `use <file>` — Load a binary once into the session context
  - `info` / `dossier`           — Display unified executive & technical binary dossier
  - `ask <query>`                — Query the binary naturally ("network", "crypto", "urls", "0x401000")
  - `caps` / `capabilities`      — Display CAPA-style behavioral capabilities & MITRE ATT&CK matrix
  - `xrefs`                      — Display CALL, JMP, and RIP-relative string cross-references
  - `inspect <offset_or_va>`     — Run ImHex-style 14-format Data Inspector at any address
  - `find <pattern>`             — Search ASCII, UTF-16LE, or wildcard hex byte patterns
  - Automatic `-i <loaded_file>` injection when running any CLI subcommand without `-i`!

Zero extra dependencies — pure stdlib (readline + shlex + textwrap + os).
"""

from __future__ import annotations

from dataclasses import asdict
import os
import sys
import shlex
import shutil
import time
import json
import threading
from typing import Any, Dict, List, Optional, Tuple

_FORCE_COLOR = os.environ.get("FORCE_COLOR", "")
_NO_COLOR = os.environ.get("NO_COLOR", "")


def _supports_ansi() -> bool:
    if _NO_COLOR:
        return False
    if _FORCE_COLOR:
        return True
    if sys.platform == "win32":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = k32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            k32.GetConsoleMode(handle, ctypes.byref(mode))
            k32.SetConsoleMode(handle, mode.value | 0x0004)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_ANSI = _supports_ansi()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _ANSI else text


def _bold(t: str) -> str: return _c("1", t)
def _dim(t: str) -> str: return _c("2", t)
def _red(t: str) -> str: return _c("91", t)
def _green(t: str) -> str: return _c("92", t)
def _yellow(t: str) -> str: return _c("93", t)
def _blue(t: str) -> str: return _c("94", t)
def _magenta(t: str) -> str: return _c("95", t)
def _cyan(t: str) -> str: return _c("96", t)


def _term_width() -> int:
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


def _init_readline(completer_fn) -> None:
    rl = None
    try:
        import readline as rl  # type: ignore[no-redef]
    except ImportError:
        try:
            import pyreadline3 as rl  # type: ignore[no-redef]
        except ImportError:
            try:
                import pyreadline as rl  # type: ignore[no-redef]
            except ImportError:
                pass
    if rl is not None:
        rl.set_completer(completer_fn)
        rl.parse_and_bind("tab: complete")
        hist_path = os.path.join(os.path.expanduser("~"), ".rf_repl_history")
        try:
            rl.read_history_file(hist_path)
        except Exception:
            pass
        import atexit
        atexit.register(lambda: rl.write_history_file(hist_path))


COMMAND_GROUPS: Dict[str, List[Tuple[str, str]]] = {
    "🧠  Smart Binary Intelligence (New in v7.0)": [
        ("dossier",         "Complete one-stop executive & technical binary dossier"),
        ("ask",             "Ask any question or keyword ('network', 'crypto', '0x401000')"),
        ("capabilities",    "CAPA-style behavioral capabilities & MITRE ATT&CK matrix"),
        ("xrefs",           "Bidirectional CALL, JMP & RIP-relative string cross-references"),
        ("inspect",         "ImHex-style 14-format Data Inspector at any offset or VA"),
        ("desktop-app",     "Launch Cross-Platform Native Desktop Studio (Tkinter/App Window)"),
    ],
    "🔍  Triage & Discovery": [
        ("triage",          "Cross-platform format triage (PE/ELF/Mach-O/JVM)"),
        ("streaming-triage","Zero-copy memory-mapped streaming PE triage"),
        ("strings",         "Extract & categorize embedded strings"),
        ("detect-tools",    "Discover local reverse-engineering toolchain"),
        ("bootstrap",       "Auto-download and install analysis tools"),
        ("doctor",          "Full system & engine readiness check"),
    ],
    "🛡️  Security Audit": [
        ("win-checksec",    "Windows PE security mitigations (ASLR/DEP/CFG)"),
        ("win-iat",         "Windows Import Address Table analysis"),
        ("win-audit",       "Full Windows PE vulnerability audit"),
        ("elf-audit",       "Linux ELF mitigation & symbol audit"),
        ("macho-audit",     "Apple Mach-O dylib/signing audit"),
        ("crypto-audit",    "Cryptographic primitives & hardcoded secrets"),
    ],
    "⚙️  Deep Analysis": [
        ("correlate",       "Multi-engine correlation analysis"),
        ("dataflow",        "Source-to-sink taint reachability analysis"),
        ("decompile",       "Pure-Python SSA-to-C micro-decompiler"),
        ("alias-trace",     "Heap lifecycle analysis (UAF/double-free)"),
        ("uil-lift",        "Cross-arch Unified IL lifter"),
        ("taint-trace",     "Register & memory instruction taint tracker"),
        ("sig-scan",        "FLIRT/YARA-style byte signature scanner"),
        ("unpack",          "Container / .NET / JAR layer extractor"),
    ],
    "🧬  Advanced Engines": [
        ("ssa-optimize",    "Cytron SSA lifter + algebraic optimizer"),
        ("structure-cfg",   "Region-based goto-free C recovery"),
        ("vsa-analyze",     "Datalog fixed-point & Value-Set Analysis"),
        ("deobfuscate-mba", "MBA expression simplifier"),
        ("cpp-rtti",        "C++ RTTI / VTable class hierarchy recovery"),
        ("firmware-base",   "Bare-metal firmware base-address scanner"),
        ("eh-frame",        "DWARF .eh_frame unwind & function recovery"),
        ("trace-diff",      "Differential execution trace aligner"),
    ],
    "🎯  Vulnerability Research": [
        ("zeroday-scan",    "Heuristic zero-day anomaly clustering"),
        ("symbolic-verify", "SSA symbolic interval bounds verification"),
        ("smt-solve",       "SMT constraint & guard completeness check"),
        ("semantic-recover","Stripped function name & struct field recovery"),
        ("remediate",       "Defensive patch & regression test synthesiser"),
        ("patch-verify",    "Patch resilience & C/Python harness verifier"),
    ],
    "🔬  Dynamic & Sandbox": [
        ("behavioral-correlate", "Runtime telemetry ↔ static correlation"),
        ("win-sandbox",     "Windows Sandbox .wsb detonation profile"),
        ("posix-trace",     "strace/gdb log converter & bwrap runner"),
        ("frida-gen",       "Frida DBI telemetry script generator"),
    ],
    "📊  Reporting, GUI & Corpus": [
        ("gui",             "Launch live Web GUI Workbench"),
        ("pipeline",        "Full 12-stage autonomous pipeline"),
        ("ab-bench",        "Empirical A/B statistical hypothesis testing"),
        ("dashboard",       "Interactive HTML5/SVG workbench generator"),
        ("sbom",            "CycloneDX v1.5 SBOM + SARIF v2.1.0 export"),
        ("batch-scan",      "Recursive directory corpus scanner + SQLite"),
        ("db-query",        "Query indexed findings from SQLite KB"),
        ("corpus-cluster",  "Multi-threaded binary family clustering"),
    ],
    "🔗  External Tool Integration": [
        ("ghidra-audit",    "Headless Ghidra decompilation & xref export"),
        ("ida-audit",       "Headless IDA Pro + Hex-Rays batch analysis"),
        ("bindiff",         "Structural binary & patch diffing"),
    ],
}

ALL_COMMANDS: Dict[str, str] = {}
for _cmds in COMMAND_GROUPS.values():
    for name, desc in _cmds:
        ALL_COMMANDS[name] = desc

# Commands that accept `-i / --input` and benefit from automatic session target injection
TARGET_INPUT_COMMANDS = {
    "triage", "streaming-triage", "strings", "win-checksec", "win-iat", "win-audit",
    "elf-audit", "macho-audit", "crypto-audit", "correlate", "dataflow", "decompile",
    "alias-trace", "sig-scan", "unpack", "structure-cfg", "cpp-rtti", "firmware-base",
    "eh-frame", "zeroday-scan", "semantic-recover", "pipeline", "ab-bench", "dashboard",
    "sbom", "ghidra-audit", "ida-audit", "dossier", "capabilities", "xrefs", "inspect",
    "ask", "gui", "desktop-app",
}

META_COMMANDS: Dict[str, str] = {
    "load":     "Load a binary into active session context (e.g. 'load sample.exe')",
    "use":      "Alias for 'load <binary>'",
    "info":     "Show executive summary card of currently loaded binary",
    "caps":     "Show behavioral capabilities of loaded binary",
    "find":     "Search strings or wildcard hex bytes in loaded binary",
    "help":     "Show this command reference",
    "commands": "List all commands (compact)",
    "groups":   "Show grouped command panels",
    "clear":    "Clear the terminal",
    "history":  "Show command history this session",
    "status":   "Show session state & active binary",
    "version":  "Show engine version",
    "exit":     "Exit the REPL",
    "quit":     "Exit the REPL",
    "q":        "Exit the REPL",
}

ALL_WORDS = sorted(set(list(ALL_COMMANDS.keys()) + list(META_COMMANDS.keys())))


class Spinner:
    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, label: str = "Processing"):
        self._label = label
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self, ok: bool = True) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        icon = _green("✔") if ok else _red("✖")
        sys.stdout.write(f"\r{icon} {self._label}  \n")
        sys.stdout.flush()

    def _spin(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = _cyan(self._FRAMES[i % len(self._FRAMES)])
            sys.stdout.write(f"\r{frame} {_dim(self._label)}  ")
            sys.stdout.flush()
            i += 1
            time.sleep(0.08)


BANNER = r"""
 ╔══════════════════════════════════════════════════════════════════════╗
 ║   ██████╗ ██████╗ ██╗   ██╗██████╗ ██████╗ ██████╗ ██████╗           ║
 ║   ██╔══██╗╚════██╗██║   ██║╚════██╗██╔══██╗╚════██╗╚════██╗          ║
 ║   ██████╔╝ █████╔╝██║   ██║ █████╔╝██████╔╝ █████╔╝ █████╔╝          ║
 ║   ██╔══██╗ ╚═══██╗╚██╗ ██╔╝██╔══╝ ██╔══██╗╚═══██╗ ╚═══██╗            ║
 ║   ██║  ██║██████╔╝ ╚████╔╝ ███████╗██║  ██║██████╔╝██████╔╝          ║
 ║   ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═════╝           ║
 ║            ╔═╗╔═╗╦═╗╔═╗╔═╗  //  F0RG3  v7.0.0-singularity            ║
 ║            ╠╣ ║ ║╠╦╝║ ╦║╣                                            ║
 ║            ╚  ╚═╝╩╚═╚═╝╚═╝  47 Engines · 54 Commands · Stateful TUI  ║
 ╚══════════════════════════════════════════════════════════════════════╝
"""


def _print_banner() -> None:
    for line in BANNER.strip().splitlines():
        if "v7.0.0" in line:
            line = line.replace("v7.0.0-singularity", _yellow("v7.0.0-singularity"))
        if "╔" in line or "╚" in line or "║" in line:
            line = _magenta(line) if ("██" in line or "═╗" in line or "═╝" in line) else _blue(line)
        print(line)
    print()
    print(f"  {_dim('Quickstart:')} {_green('load <file>')} {_dim('→')} {_cyan('info')} {_dim('·')} {_cyan('caps')} {_dim('·')} {_cyan('xrefs')} {_dim('·')} {_cyan('ask network')} {_dim('·')} {_cyan('inspect 0x0')}")
    print(f"  {_dim('Type')} {_cyan('groups')} {_dim('for all 54 categorized commands ·')} {_cyan('exit')} {_dim('to quit')}")
    print()


def _print_groups() -> None:
    tw = _term_width()
    for group_name, cmds in COMMAND_GROUPS.items():
        print(f"  {_bold(group_name)}")
        print(f"  {_dim('─' * min(64, tw - 4))}")
        for name, desc in cmds:
            pad = 24 - len(name)
            print(f"    {_cyan(name)}{' ' * max(pad, 2)}{_dim(desc)}")
        print()


def _print_compact_commands() -> None:
    tw = _term_width()
    col_w = 22
    cols = max(1, (tw - 4) // col_w)
    names = list(ALL_COMMANDS.keys())
    rows = (len(names) + cols - 1) // cols
    print(f"\n  {_bold('All Engine Commands')} ({len(names)} total):\n")
    for r in range(rows):
        line_parts = []
        for c in range(cols):
            idx = r + c * rows
            if idx < len(names):
                line_parts.append(f"  {_cyan(names[idx].ljust(20))}")
        print("".join(line_parts))
    print()


def _print_help() -> None:
    print(f"\n  {_bold(_yellow('R3V3R53//F0RG3 Stateful Interactive Workbench'))}\n")
    print(f"  {_bold('1. Stateful Target Workflow (Recommended):')}")
    print(f"    {_green('load /bin/ls')}                 {_dim('# Load binary once into session')}")
    print(f"    {_green('info')}                         {_dim('# Instant executive dossier & checksec')}")
    print(f"    {_green('caps')}                         {_dim('# CAPA behavioral capabilities & MITRE ATT&CK')}")
    print(f"    {_green('ask network')}                  {_dim('# Query capabilities, URLs, imports, or addresses')}")
    print(f"    {_green('inspect 0x401000')}             {_dim('# ImHex 14-format Data Inspector at offset/VA')}")
    print(f"    {_green('find http')}                    {_dim('# Search ASCII/UTF-16LE/hex wildcard patterns')}")
    print(f"    {_green('decompile')}                    {_dim('# Auto-uses loaded binary when -i is omitted!')}\n")
    print(f"  {_bold('2. Shell Meta-Commands:')}")
    for name, desc in META_COMMANDS.items():
        if name in ("quit", "q", "use"):
            continue
        pad = 14 - len(name)
        print(f"    {_yellow(name)}{' ' * max(pad, 2)}{_dim(desc)}")
    print()


def _run_engine_command(raw_args: List[str]) -> bool:
    from reverse_forge.cli import main as cli_main

    old_argv = sys.argv
    sys.argv = ["reverse-forge"] + raw_args

    spinner = Spinner(label=f"Running: {raw_args[0]}")
    spinner.start()
    ok = True
    try:
        cli_main()
    except SystemExit as e:
        if e.code and e.code != 0:
            ok = False
    except Exception as exc:
        ok = False
        print(f"\n  {_red('Error:')} {exc}")
    finally:
        spinner.stop(ok)
        sys.argv = old_argv
    return ok


def _completer(text: str, state: int) -> Optional[str]:
    matches = [w for w in ALL_WORDS if w.startswith(text)]
    if os.sep in text or text.startswith(".") or text.startswith("~"):
        dir_part = os.path.dirname(text) or "."
        base_part = os.path.basename(text)
        try:
            entries = os.listdir(os.path.expanduser(dir_part))
            for e in entries:
                if e.lower().startswith(base_part.lower()):
                    full = os.path.join(dir_part, e)
                    if os.path.isdir(full):
                        full += os.sep
                    matches.append(full)
        except OSError:
            pass
    matches = sorted(set(matches))
    return matches[state] if state < len(matches) else None


class Session:
    """Tracks REPL session state and currently loaded binary artifact."""

    def __init__(self, initial_binary: Optional[str] = None):
        self.start_time = time.time()
        self.command_count = 0
        self.history: List[str] = []
        self.last_command: Optional[str] = None
        self.last_ok: Optional[bool] = None
        self.cwd = os.getcwd()
        self.target_path: Optional[str] = None
        self.target_intel: Any = None
        if initial_binary and os.path.exists(initial_binary):
            self.load_binary(initial_binary)

    def load_binary(self, path: str) -> bool:
        expanded = os.path.abspath(os.path.expanduser(path))
        if not os.path.exists(expanded) or not os.path.isfile(expanded):
            print(f"  {_red('Error:')} File not found: {expanded}")
            return False
        from reverse_forge.binary_intel_engine import BinaryIntelEngine
        with open(expanded, "rb") as f:
            data = f.read()
        self.target_path = expanded
        self.target_intel = BinaryIntelEngine(data, filepath=expanded)
        caps = self.target_intel.detect_capabilities()
        print(f"\n  {_green('✔ Loaded active target:')} {_bold(os.path.basename(expanded))}")
        print(f"    {_dim('Path:')}         {expanded}")
        print(f"    {_dim('Format/Arch:')}  {_cyan(self.target_intel.format_name)} ({self.target_intel.metadata.get('architecture', 'unknown')})")
        print(f"    {_dim('Size:')}         {len(data):,} bytes  ·  Entropy: {self.target_intel.metadata.get('entropy', 0.0)}")
        print(f"    {_dim('Entry Point:')}  {_yellow(str(self.target_intel.metadata.get('entry_point', '0x0')))}")
        print(f"    {_dim('Capabilities:')} {len(caps)} behavioral capability match(es) detected\n")
        return True

    def elapsed(self) -> str:
        s = int(time.time() - self.start_time)
        m, s = divmod(s, 60)
        h, m = divmod(m, 60)
        if h:
            return f"{h}h {m}m {s}s"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"

    def status_line(self) -> str:
        last = "—"
        if self.last_command:
            icon = _green("✔") if self.last_ok else _red("✖")
            last = f"{icon} {self.last_command}"
        t_label = f"{self.target_path} ({self.target_intel.format_name})" if self.target_path and self.target_intel else "None (run 'load <file>')"
        return (
            f"  {_bold('Session Status')}\n"
            f"  {_dim('Active Target:')} {_cyan(t_label)}\n"
            f"  {_dim('Uptime:')}        {self.elapsed()}\n"
            f"  {_dim('Commands run:')}  {self.command_count}\n"
            f"  {_dim('Last result:')}   {last}\n"
            f"  {_dim('Working dir:')}   {self.cwd}\n"
        )


def _prompt(session: Session) -> str:
    if session.target_path and session.target_intel:
        bname = os.path.basename(session.target_path)
        fmt = session.target_intel.format_name
        return f"{_magenta('r3v3rs3')} [{_cyan(bname)} {_dim('·')} {_green(fmt)}] {_yellow('❯')} "
    cwd_short = os.path.basename(session.cwd) or session.cwd
    return f"{_magenta('r3v3rs3')} {_dim('·')} {_blue(cwd_short)} {_yellow('❯')} "


def repl_main(initial_binary: Optional[str] = None) -> None:
    _init_readline(_completer)
    _print_banner()
    session = Session(initial_binary=initial_binary)

    while True:
        try:
            raw = input(_prompt(session)).strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{_dim('Goodbye.')}")
            break

        if not raw:
            continue

        session.history.append(raw)
        try:
            tokens = shlex.split(raw)
        except ValueError as e:
            print(f"  {_red('Parse error:')} {e}")
            continue

        cmd = tokens[0].lower()
        rest = tokens[1:]

        if cmd in ("exit", "quit", "q"):
            print(f"\n  {_dim('Session ended after')} {_bold(session.elapsed())} · {session.command_count} {_dim('commands')}")
            print(f"  {_magenta('// F0RG3 out.')}\n")
            break

        elif cmd in ("load", "use"):
            if not rest:
                print(f"  {_yellow('Usage:')} load <path_to_binary>")
            else:
                session.load_binary(rest[0])
            continue

        elif cmd == "info":
            if not session.target_intel:
                print(f"  {_yellow('No binary loaded.')} Run {_green('load <file>')} first.")
            else:
                d = session.target_intel.get_full_dossier()
                print(json.dumps({
                    "artifact": d["artifact"],
                    "format": d["format"],
                    "architecture": d["architecture"],
                    "size_bytes": d["size_bytes"],
                    "sha256": d["sha256"],
                    "entry_point": d["entry_point"],
                    "mitigations": d["mitigations"],
                    "sections_count": len(d["sections"]),
                    "imported_symbols_count": d["imported_symbols_count"],
                    "capabilities_count": d["capabilities_count"],
                }, indent=2))
            continue

        elif cmd == "caps":
            if not session.target_intel:
                print(f"  {_yellow('No binary loaded.')} Run {_green('load <file>')} first.")
            else:
                caps = [asdict(c) for c in session.target_intel.detect_capabilities()]
                print(json.dumps(caps, indent=2))
            continue

        elif cmd == "find":
            if not session.target_intel or not rest:
                print(f"  {_yellow('Usage:')} find <string_or_hex_pattern> (requires loaded binary)")
            else:
                hits = [asdict(h) for h in session.target_intel.find_patterns(" ".join(rest))]
                print(json.dumps(hits, indent=2))
            continue

        elif cmd == "help":
            _print_help()
            continue

        elif cmd == "commands":
            _print_compact_commands()
            continue

        elif cmd == "groups":
            _print_groups()
            continue

        elif cmd == "clear":
            os.system("cls" if sys.platform == "win32" else "clear")
            _print_banner()
            continue

        elif cmd == "history":
            print(f"\n  {_bold('Session History')} ({len(session.history)} entries):\n")
            for i, h in enumerate(session.history, 1):
                print(f"  {_dim(f'{i:3d}')}  {h}")
            print()
            continue

        elif cmd == "status":
            print(f"\n{session.status_line()}")
            continue

        elif cmd == "version":
            print(f"\n  {_bold('R3V3R53//F0RG3')} {_yellow('v7.0.0-singularity')}")
            print(f"  {_dim('47 internal engines · 54 subcommands · pure Python core')}\n")
            continue

        # --- Engine commands (with automatic `-i <target>` injection!) ---
        if cmd in ALL_COMMANDS:
            session.command_count += 1
            session.last_command = raw
            invoke_tokens = list(tokens)
            if (
                session.target_path
                and cmd in TARGET_INPUT_COMMANDS
                and "-i" not in invoke_tokens
                and "--input" not in invoke_tokens
                and "--help" not in invoke_tokens
                and "-h" not in invoke_tokens
            ):
                # Support shorthand `ask <query>` or `inspect <offset>` without flags
                if cmd == "ask" and rest and not rest[0].startswith("-"):
                    invoke_tokens = ["ask", "-i", session.target_path, "--query", " ".join(rest)]
                elif cmd == "inspect" and rest and not rest[0].startswith("-"):
                    invoke_tokens = ["inspect", "-i", session.target_path, "--offset", rest[0]]
                else:
                    invoke_tokens.extend(["-i", session.target_path])

            ok = _run_engine_command(invoke_tokens)
            session.last_ok = ok
        elif cmd in ("--help", "-h"):
            _print_help()
        else:
            close = [c for c in ALL_COMMANDS if c.startswith(cmd[:3])]
            msg = f"  {_red('Unknown command:')} {_bold(cmd)}"
            if close:
                msg += f"  {_dim('Did you mean:')} {_cyan(', '.join(close[:3]))}?"
            print(msg)


def main() -> None:
    init_bin = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None
    repl_main(initial_binary=init_bin)


if __name__ == "__main__":
    main()
