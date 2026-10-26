"""
R3V3R53//F0RG3 — Rich Terminal UI (TUI) Table, Syntax-Colored C & ASCII CFG Renderer (`tui_renderer.py`)
========================================================================================================
Replaces raw `json.dumps()` terminal walls with human-first, ANSI-colored tables, multi-line
syntax-highlighted C / Assembly / YARA code blocks, and box-drawn ASCII Control-Flow Graphs
whenever a user interacts with `reverse-forge` in an interactive terminal or REPL.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from typing import Any, Dict, List, Optional


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("RF_PRETTY_TUI"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _use_color() else str(text)


def bold(t: Any) -> str: return _c("1", str(t))
def dim(t: Any) -> str: return _c("2", str(t))
def cyan(t: Any) -> str: return _c("96", str(t))
def green(t: Any) -> str: return _c("92", str(t))
def yellow(t: Any) -> str: return _c("93", str(t))
def red(t: Any) -> str: return _c("91", str(t))
def magenta(t: Any) -> str: return _c("95", str(t))
def blue(t: Any) -> str: return _c("94", str(t))


def highlight_c_code(c_text: str) -> str:
    """Render multi-line C / IR code with line numbers and ANSI syntax highlighting."""
    out: List[str] = []
    kw_re = re.compile(r"\b(if|else|while|for|do|switch|case|default|break|continue|goto|return|sizeof)\b")
    ty_re = re.compile(r"\b(int64_t|uint64_t|int32_t|uint32_t|int16_t|uint16_t|int8_t|uint8_t|int|long|char|void|bool|size_t|struct|typedef)\b")
    num_re = re.compile(r"\b(0x[0-9a-fA-F]+|\d+)\b")

    for idx, raw_line in enumerate(c_text.splitlines(), 1):
        num_col = dim(f"{idx:4d} │ ")
        if raw_line.strip().startswith("//") or raw_line.strip().startswith("/*"):
            out.append(num_col + dim(raw_line))
            continue

        # Split trailing comment `// @ 0x...`
        if "//" in raw_line:
            code_part, cmt_part = raw_line.split("//", 1)
            cmt_s = dim("//" + cmt_part)
        else:
            code_part, cmt_s = raw_line, ""

        # Highlight string literals first
        parts = re.split(r'(".*?")', code_part)
        colored_chunks: List[str] = []
        for p in parts:
            if p.startswith('"') and p.endswith('"'):
                colored_chunks.append(green(p))
            else:
                s = ty_re.sub(lambda m: cyan(m.group(0)), p)
                s = kw_re.sub(lambda m: magenta(bold(m.group(0))), s)
                s = num_re.sub(lambda m: yellow(m.group(0)), s)
                colored_chunks.append(s)

        out.append(num_col + "".join(colored_chunks) + cmt_s)
    return "\n".join(out)


def render_ascii_cfg(cfg_blocks: List[Dict[str, Any]], max_blocks: int = 12) -> str:
    """Render basic blocks and branch edges as box-drawn ASCII Control-Flow Graph."""
    if not cfg_blocks:
        return dim("  (No CFG basic blocks available)")
    lines: List[str] = []
    for blk in cfg_blocks[:max_blocks]:
        lbl = blk.get("label") or blk.get("addr") or "block"
        succs = blk.get("successors") or []
        insns = blk.get("insns") or []
        w = 68
        hdr = f"┌─[ {lbl} ]─" + ("─" * max(2, w - len(lbl) - 6)) + "┐"
        lines.append("  " + cyan(bold(hdr)))
        for ins in insns[:10]:
            va = str(ins.get("va", "")).ljust(8)
            mn = str(ins.get("mnem", "")).ljust(8)
            ops = str(ins.get("ops", ""))[:46]
            row = f"  │ {dim(va)} {magenta(bold(mn))} {ops}"
            lines.append(row)
        lines.append("  " + cyan("└" + ("─" * (w - 1)) + "┘"))
        if len(succs) == 1:
            lines.append(f"        │\n        ▼  {green('fallthrough/jump → ' + str(succs[0]))}")
        elif len(succs) >= 2:
            lines.append(f"        ├──► {green('TRUE  → ' + str(succs[0]))}")
            lines.append(f"        └──► {red('FALSE → ' + str(succs[1]))}")
    if len(cfg_blocks) > max_blocks:
        lines.append(dim(f"  ... ({len(cfg_blocks) - max_blocks} additional CFG blocks omitted; use 'gui' for full pan/zoom graph)"))
    return "\n".join(lines)


def render_functions_table(funcs: List[Dict[str, Any]], limit: int = 35) -> str:
    """Render discovered functions in a clean aligned terminal table."""
    lines = [
        f"\n  {bold(cyan('DISCOVERED FUNCTIONS'))} ({len(funcs)} total)",
        "  " + dim("─" * 76),
        f"  {bold('ADDRESS'.ljust(12))} {bold('KIND'.ljust(10))} {bold('SIZE'.ljust(8))} {bold('CALLS'.ljust(7))} {bold('FUNCTION NAME')}",
        "  " + dim("─" * 76),
    ]
    for f in funcs[:limit]:
        addr = str(f.get("addr", "0x0")).ljust(12)
        kind = str(f.get("kind", "sub")).upper().ljust(10)
        sz = f"{f.get('size', 0)} B".ljust(8)
        calls = f"{f.get('call_count', 0)}x".ljust(7)
        name = str(f.get("name", "sub"))
        k_col = green(kind) if "MAIN" in kind else (cyan(kind) if "ENTRY" in kind else (magenta(kind) if "PLT" in kind else dim(kind)))
        n_col = bold(green(name)) if name == "main" else (cyan(name) if "@plt" not in name else magenta(name))
        lines.append(f"  {yellow(addr)} {k_col} {dim(sz)} {calls} {n_col}")
    if len(funcs) > limit:
        lines.append(dim(f"  ... and {len(funcs) - limit} more functions (run 'funcs <filter>' or 'dec <name_or_addr>')"))
    lines.append("")
    return "\n".join(lines)


def render_pretty_cli_output(res: Dict[str, Any], label: str) -> str:
    """Render any CLI / REPL dictionary result into a clean human-readable TUI report."""
    lines: List[str] = []
    lines.append(f"\n  {bold(magenta('╔══'))} {bold(cyan(label.upper()))} {bold(magenta('══╗'))}")

    # 1. Executive Header if dossier/triage keys exist
    if "format" in res or "artifact" in res:
        art = res.get("artifact", "")
        fmt = res.get("format", res.get("detected_format", ""))
        arch = res.get("architecture", res.get("metadata", {}).get("architecture", ""))
        ep = res.get("entry_point", res.get("metadata", {}).get("entry_point", ""))
        sz = res.get("size_bytes", 0)
        act_fn = res.get("active_function_name", "")
        act_va = res.get("active_function_va", "")
        lines.append(f"  {dim('Artifact:')}      {bold(art)}")
        lines.append(f"  {dim('Format / Arch:')} {cyan(fmt)} · {yellow(arch)}  ({sz:,} bytes)")
        if ep:
            ep_line = f"  {dim('Entry Point:')}   {yellow(ep)}"
            if act_fn and act_va:
                ep_line += f"  ·  {dim('Resolved Primary Function:')} {green(bold(f'{act_fn} @ {act_va}'))}"
            lines.append(ep_line)

    # 2. Mitigations Table
    mits = res.get("mitigations") or res.get("metadata", {}).get("mitigations")
    if isinstance(mits, dict) and mits:
        lines.append(f"\n  {bold(cyan('🛡  SECURITY MITIGATIONS'))}")
        lines.append("  " + dim("─" * 68))
        for k, v in mits.items():
            if isinstance(v, dict):
                passed = v.get("pass", False)
                desc = v.get("val", "")
            else:
                passed = bool(v)
                desc = str(v)
            badge = green("✔ ENABLED ") if passed else red("✖ ABSENT  ")
            lines.append(f"  {badge} {bold(str(k).ljust(36))} {dim(desc)}")

    # 3. Discovered Functions Table
    if "discovered_functions" in res and isinstance(res["discovered_functions"], list):
        lines.append(render_functions_table(res["discovered_functions"], limit=18))

    # 4. Capabilities / Vulnerabilities Summary
    if "capabilities" in res and isinstance(res["capabilities"], list) and res["capabilities"]:
        caps = res["capabilities"]
        lines.append(f"\n  {bold(cyan(f'🧠  BEHAVIORAL CAPABILITIES ({len(caps)})'))}")
        lines.append("  " + dim("─" * 68))
        for c in caps[:12]:
            cid = str(c.get("capability_id", "CAP")).ljust(14)
            cname = str(c.get("name", "")).ljust(38)
            att = str(c.get("mitre_attack", ""))
            lines.append(f"  {yellow(cid)} {bold(cname)} {magenta(att)}")

    if "vulnerabilities" in res and isinstance(res["vulnerabilities"], list) and res["vulnerabilities"]:
        vulns = res["vulnerabilities"]
        risk_str = res.get("risk_rating", res.get("vulnerability_risk_rating", "HIGH"))
        lines.append(f"\n  {bold(red(f'⚠  VULNERABILITY FINDINGS ({len(vulns)}) — Risk: {risk_str}'))}")
        lines.append("  " + dim("─" * 68))
        for v in vulns[:12]:
            cwe = str(v.get("cwe_id", "CWE")).ljust(10)
            sev = str(v.get("severity", "HIGH")).ljust(9)
            title = str(v.get("title", v.get("sink_symbol", "")))
            loc = str(v.get("address", v.get("location", "")))
            lines.append(f"  {red(bold(cwe))} {yellow(sev)} {bold(title)} @ {cyan(loc)}")

    # 5. Syntax-Highlighted Decompiled C Code (Never dump C code as a single-line escaped JSON string!)
    c_code = (
        res.get("unified_decompiled_c")
        or res.get("final_c_code")
        or res.get("decompiled_c")
        or res.get("c_source")
        or res.get("structured_c")
        or res.get("pcode_decompiled_c")
        or (res.get("detection_bundle", {}) if isinstance(res.get("detection_bundle"), dict) else {}).get("yara_rule_source")
    )
    if isinstance(c_code, str) and c_code.strip():
        lines.append(f"\n  {bold(cyan('⚙  DECOMPILED C / GENERATED CODE'))}")
        lines.append("  " + dim("─" * 76))
        lines.append(highlight_c_code(c_code))
        lines.append("  " + dim("─" * 76))

    # 6. If it wasn't a dossier/decompile dict, format top-level scalar/table fields cleanly
    if not c_code and "format" not in res and "capabilities" not in res and "vulnerabilities" not in res:
        lines.append("  " + dim("─" * 68))
        for k, v in res.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                lines.append(f"  {cyan(str(k).ljust(28))}: {bold(str(v))}")
            elif isinstance(v, list) and len(v) <= 15:
                lines.append(f"  {cyan(str(k))} ({len(v)} items):")
                for item in v[:10]:
                    lines.append(f"    • {item}")
            elif isinstance(v, dict):
                lines.append(f"  {cyan(str(k))}:")
                for sk, sv in list(v.items())[:12]:
                    lines.append(f"    {dim(str(sk).ljust(24))}: {sv}")

    lines.append("")
    return "\n".join(lines)
