"""
R3V3R53//F0RG3 — Dynamic Binary Instrumentation (DBI) & Frida Telemetry Engine (§07.3, §08)
Synthesizes read-only Frida Interceptor.attach scripts to log function arguments and return values
as structured JSON telemetry compatible with BehavioralTelemetryEngine.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional


class FridaDBIEngine:
    """Generates safe, non-destructive Frida JavaScript instrumentation hooks for target symbols."""

    SAFE_SYMBOL_RE = re.compile(r"^[A-Za-z0-9_@.?$]+$")

    @classmethod
    def sanitize_symbol(cls, symbol: str) -> str:
        cleaned = symbol.strip()
        if not cleaned or not cls.SAFE_SYMBOL_RE.match(cleaned):
            raise ValueError(f"Invalid symbol identifier for Frida hook: {symbol!r}")
        return cleaned

    @classmethod
    def generate_frida_trace_script(
        cls,
        symbols: List[str],
        module_name: Optional[str] = None,
        max_args: int = 4,
    ) -> str:
        """Produce a Frida Interceptor script emitting JSON telemetry events on function entry/exit."""
        valid_symbols = [cls.sanitize_symbol(s) for s in symbols if s.strip()]
        mod_json = json.dumps(module_name) if module_name else "null"
        syms_json = json.dumps(valid_symbols)
        arg_count = max(1, min(int(max_args), 8))

        script = f"""// R3V3R53//F0RG3 Read-Only Frida DBI Telemetry Script
// Emits JSON-formatted function entry/exit traces for static-to-dynamic correlation.
(function () {{
    const targetModule = {mod_json};
    const targetSymbols = {syms_json};
    const maxArgs = {arg_count};

    function resolveTarget(sym) {{
        if (sym.startsWith("0x") || sym.startsWith("0X")) {{
            return ptr(sym);
        }}
        if (targetModule) {{
            const mod = Process.findModuleByName(targetModule);
            return mod ? mod.findExportByName(sym) : null;
        }}
        return Module.findExportByName(null, sym);
    }}

    targetSymbols.forEach(function (sym) {{
        const addr = resolveTarget(sym);
        if (!addr) {{
            send({{ type: "hook_skipped", symbol: sym, reason: "Symbol not resolved" }});
            return;
        }}
        Interceptor.attach(addr, {{
            onEnter: function (args) {{
                this.fnName = sym;
                this.callTime = new Date().toISOString();
                this.argSnapshot = [];
                for (let i = 0; i < maxArgs; i++) {{
                    try {{
                        this.argSnapshot.push(args[i].toString());
                    }} catch (e) {{
                        this.argSnapshot.push("unreadable");
                    }}
                }}
            }},
            onLeave: function (retval) {{
                send({{
                    type: "function_trace",
                    timestamp: this.callTime,
                    thread_id: this.threadId,
                    symbol: this.fnName,
                    address: addr.toString(),
                    arguments: this.argSnapshot,
                    return_value: retval ? retval.toString() : "0x0"
                }});
            }}
        }});
    }});
}})();
"""
        return script

    @classmethod
    def write_frida_script(
        cls,
        output_js_path: str,
        symbols: List[str],
        module_name: Optional[str] = None,
    ) -> str:
        js_code = cls.generate_frida_trace_script(symbols, module_name=module_name)
        with open(output_js_path, "w", encoding="utf-8") as f:
            f.write(js_code)
        return os.path.abspath(output_js_path)
