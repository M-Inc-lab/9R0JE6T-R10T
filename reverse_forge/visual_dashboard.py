"""
R3V3R53//F0RG3 — Interactive HTML5 & SVG Reverse-Engineering Workbench Generator (§19)
Generates an offline, zero-dependency, XSS-hardened interactive HTML dashboard containing:
- Interactive SVG Call-Graph & Taint Flow visualization
- Section Memory Map & Shannon Entropy bars
- Security Mitigations & Hardware Protection grid (PIE/ASLR, NX/DEP, RELRO, Canary, CET, PAC)
- 12-Stage Pipeline Telemetry & CWE/CVSS Finding Cards with Unified Diff Patches
"""

import html
import os
from typing import Any, Dict, List, Tuple


class DashboardGenerator:
    """Renders static, dynamic, and pipeline analysis state into a self-contained HTML5/SVG workbench."""

    @staticmethod
    def _esc(val: Any) -> str:
        return html.escape(str(val if val is not None else ""), quote=True)

    @classmethod
    def render_svg_call_graph(
        cls,
        edges: List[Tuple[str, str]],
        sources: set[str] | None = None,
        sinks: set[str] | None = None,
    ) -> str:
        """Render a layered SVG directed graph from (caller, callee) edges."""
        sources = sources or {"recv", "read", "fgets", "fread", "getenv", "scanf"}
        sinks = sinks or {"strcpy", "strcat", "sprintf", "gets", "system", "popen", "memcpy", "free"}

        if not edges:
            edges = [("entry", "main")]

        nodes: List[str] = []
        for u, v in edges:
            if u not in nodes:
                nodes.append(u)
            if v not in nodes:
                nodes.append(v)
        nodes = nodes[:24]

        width = 820
        row_height = 68
        cols = 3
        rows = max(1, (len(nodes) + cols - 1) // cols)
        height = max(220, rows * row_height + 60)

        coords: Dict[str, Tuple[int, int]] = {}
        for idx, n in enumerate(nodes):
            r = idx // cols
            c = idx % cols
            x = 130 + c * 260
            y = 50 + r * row_height
            coords[n] = (x, y)

        svg_lines = [
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'xmlns="http://www.w3.org/2000/svg" style="background:#0f172a;border-radius:8px;border:1px solid #334155;">',
            '<defs>',
            '  <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
            '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b"/>',
            '  </marker>',
            '</defs>',
        ]

        for u, v in edges:
            if u in coords and v in coords:
                x1, y1 = coords[u]
                x2, y2 = coords[v]
                stroke = "#f97316" if v.lstrip("_") in sinks else "#475569"
                svg_lines.append(
                    f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                    f'stroke="{stroke}" stroke-width="2" marker-end="url(#arrow)" stroke-opacity="0.85"/>'
                )

        for n in nodes:
            x, y = coords[n]
            clean = n.lstrip("_")
            if clean in sinks:
                fill, border = "#7f1d1d", "#ef4444"
            elif clean in sources:
                fill, border = "#1e3a8a", "#3b82f6"
            else:
                fill, border = "#1e293b", "#64748b"

            label = cls._esc(n[:20])
            svg_lines.extend([
                f'<g transform="translate({x - 85},{y - 18})">',
                f'  <rect width="170" height="36" rx="6" fill="{fill}" stroke="{border}" stroke-width="1.5"/>',
                f'  <text x="85" y="22" fill="#f8fafc" font-family="monospace" font-size="12" text-anchor="middle">{label}</text>',
                '</g>',
            ])

        svg_lines.append("</svg>")
        return "\n".join(svg_lines)

    @classmethod
    def generate_html_dashboard(
        cls,
        pipeline_state: Dict[str, Any],
        static_metadata: Dict[str, Any] | None = None,
    ) -> str:
        static_metadata = static_metadata or {}
        report_json = pipeline_state.get("report_json", {})
        exec_sum = report_json.get("executive_summary", {})
        findings = report_json.get("findings", [])
        stages = pipeline_state.get("stages", [])

        target_name = cls._esc(pipeline_state.get("artifact", "unknown"))
        sha256 = cls._esc(pipeline_state.get("sha256", ""))
        posture = cls._esc(exec_sum.get("overall_posture", "UNKNOWN"))

        # Build call-graph edges from imported symbols & findings
        edges: List[Tuple[str, str]] = []
        for sym in static_metadata.get("imported_symbols", [])[:18]:
            edges.append(("entry", str(sym)))
        for f in findings:
            loc = str(f.get("function_symbol", ""))
            if "->" in loc:
                parts = [p.strip() for p in loc.split("->") if p.strip()]
                for i in range(len(parts) - 1):
                    edges.append((parts[i], parts[i + 1]))

        svg_graph = cls.render_svg_call_graph(edges)

        # Build Sections table rows
        section_rows = []
        for sec in static_metadata.get("sections", [])[:35]:
            sname = cls._esc(sec.get("name", ""))
            vaddr = cls._esc(sec.get("virtual_address") or sec.get("address") or "0x0")
            roff = cls._esc(sec.get("raw_offset") or sec.get("offset") or "0x0")
            sz = int(sec.get("raw_size") or sec.get("size") or 0)
            ent = float(sec.get("entropy", 0.0))
            ent_pct = min(100, max(2, int((ent / 8.0) * 100)))
            perms = (
                ("R" if sec.get("readable", True) else "-")
                + ("W" if sec.get("writable", False) else "-")
                + ("X" if sec.get("executable", False) else "-")
            )
            bar_color = "#ef4444" if ent > 7.1 else ("#eab308" if ent > 6.2 else "#22c55e")
            section_rows.append(
                f"<tr>"
                f"<td><code>{sname}</code></td>"
                f"<td><code>{vaddr}</code></td>"
                f"<td><code>{roff}</code></td>"
                f"<td style='text-align:right'>{sz:,} B</td>"
                f"<td><code>{perms}</code></td>"
                f"<td><div style='display:flex;align-items:center;gap:8px;'>"
                f"<div style='width:90px;background:#334155;height:8px;border-radius:4px;'>"
                f"<div style='width:{ent_pct}%;background:{bar_color};height:8px;border-radius:4px;'></div></div>"
                f"<span>{ent:.2f}</span></div></td>"
                f"</tr>"
            )
        sections_html = "\n".join(section_rows) or "<tr><td colspan='6'>No section table parsed.</td></tr>"

        # Build Mitigations badges
        mitigations = static_metadata.get("mitigations", {})
        sig_rec = static_metadata.get("signature_scan", {}).get("stripped_function_recovery", {})
        if "has_cet_ibt" in sig_rec:
            mitigations["cet_ibt"] = sig_rec["has_cet_ibt"]
        if "has_arm64_pac" in sig_rec:
            mitigations["arm64_pac"] = sig_rec["has_arm64_pac"]

        mit_cards = []
        for k, v in mitigations.items():
            if v is None:
                continue
            is_good = bool(v) and str(v) not in ("False", "No RELRO")
            badge_bg = "#14532d" if is_good else "#7f1d1d"
            badge_fg = "#86efac" if is_good else "#fca5a5"
            mit_cards.append(
                f"<div style='background:#1e293b;border:1px solid #334155;border-radius:8px;padding:10px 14px;'>"
                f"<div style='font-size:11px;color:#94a3b8;text-transform:uppercase;'>{cls._esc(k)}</div>"
                f"<div style='margin-top:4px;display:inline-block;padding:2px 8px;border-radius:4px;"
                f"background:{badge_bg};color:{badge_fg};font-weight:600;font-size:13px;'>{cls._esc(v)}</div>"
                f"</div>"
            )
        mitigations_html = "\n".join(mit_cards) or "<p>No platform mitigation flags recorded.</p>"

        # Build Stage Timeline rows
        stage_rows = []
        for st in stages:
            st_status = cls._esc(st.get("status", ""))
            color = "#22c55e" if st_status == "COMPLETED" else ("#eab308" if st_status == "SKIPPED" else "#ef4444")
            stage_rows.append(
                f"<tr>"
                f"<td><strong>Stage {int(st.get('stage', 0))}</strong></td>"
                f"<td>{cls._esc(st.get('name', ''))}</td>"
                f"<td><span style='color:{color};font-weight:600;'>{st_status}</span></td>"
                f"<td>{cls._esc(st.get('summary') or st.get('error') or '')}</td>"
                f"</tr>"
            )
        stages_html = "\n".join(stage_rows)

        # Build Findings cards
        finding_cards = []
        for f in findings:
            fid = cls._esc(f.get("finding_id", ""))
            ftitle = cls._esc(f.get("title", ""))
            fclass = cls._esc(f.get("vulnerability_class", ""))
            fconf = cls._esc(f.get("confidence", ""))
            fcvss = float(f.get("cvss_score", 0.0))
            fcwe = cls._esc(f.get("cwe_id", ""))
            floc = cls._esc(f.get("function_symbol", ""))
            faddr = cls._esc(f.get("address_or_offset", ""))
            fwhat = cls._esc(f.get("what", ""))
            fwhy = cls._esc(f.get("why", ""))
            frem = cls._esc(f.get("remediation", ""))
            sev_color = "#ef4444" if fcvss >= 7.0 else ("#eab308" if fcvss >= 4.0 else "#3b82f6")

            finding_cards.append(
                f"<div style='background:#1e293b;border-left:4px solid {sev_color};border-radius:6px;padding:16px;margin-bottom:14px;'>"
                f"<div style='display:flex;justify-content:space-between;align-items:center;'>"
                f"<h3 style='margin:0;font-size:16px;color:#f8fafc;'>[{fid}] {ftitle}</h3>"
                f"<span style='background:{sev_color};color:#0f172a;font-weight:700;padding:2px 8px;border-radius:4px;font-size:12px;'>"
                f"CVSS {fcvss:.1f} | {fcwe}</span></div>"
                f"<p style='margin:6px 0;font-size:13px;color:#94a3b8;'>"
                f"<strong>Class:</strong> {fclass} &bull; <strong>Confidence:</strong> {fconf} &bull; "
                f"<strong>Location:</strong> <code>{floc} @ {faddr}</code></p>"
                f"<p style='margin:6px 0;font-size:13px;color:#e2e8f0;'><strong>Root Cause:</strong> {fwhat} ({fwhy})</p>"
                f"<pre style='background:#0f172a;padding:10px;border-radius:6px;overflow-x:auto;font-size:12px;color:#cbd5e1;margin:8px 0 0 0;'>{frem}</pre>"
                f"</div>"
            )
        findings_html = "\n".join(finding_cards) or "<p style='color:#94a3b8;'>No vulnerability findings identified.</p>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>R3V3R53//F0RG3 Workbench — {target_name}</title>
<style>
  body {{ background:#0b0f19; color:#e2e8f0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; margin:0; padding:24px; }}
  .container {{ max-width:1180px; margin:0 auto; }}
  .header {{ background:#1e293b; border:1px solid #334155; border-radius:10px; padding:20px; margin-bottom:20px; }}
  .grid-4 {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:20px; }}
  .panel {{ background:#111827; border:1px solid #1f2937; border-radius:10px; padding:18px; margin-bottom:20px; }}
  h2 {{ margin-top:0; font-size:18px; color:#f8fafc; border-bottom:1px solid #1f2937; padding-bottom:8px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #1f2937; }}
  th {{ color:#94a3b8; font-weight:600; }}
  code {{ font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; color:#38bdf8; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1 style="margin:0 0 8px 0;font-size:22px;color:#f8fafc;">R3V3R53//F0RG3 Interactive Workbench</h1>
    <div style="font-size:13px;color:#94a3b8;">
      <strong>Artifact:</strong> <code>{target_name}</code> &nbsp;|&nbsp;
      <strong>SHA-256:</strong> <code>{sha256}</code> &nbsp;|&nbsp;
      <strong>Posture:</strong> <strong style="color:#f8fafc;">{posture}</strong>
    </div>
  </div>

  <div class="panel">
    <h2>Security Mitigations &amp; Hardware Protections</h2>
    <div class="grid-4">{mitigations_html}</div>
  </div>

  <div class="panel">
    <h2>Interactive Call-Graph &amp; Source-to-Sink Topology</h2>
    {svg_graph}
  </div>

  <div class="panel">
    <h2>Prioritized Vulnerability Findings &amp; Defensive Patches ({len(findings)})</h2>
    {findings_html}
  </div>

  <div class="panel">
    <h2>Binary Section Memory Map &amp; Shannon Entropy</h2>
    <table>
      <thead><tr><th>Section</th><th>Virtual Address</th><th>File Offset</th><th style="text-align:right">Size</th><th>Perms</th><th>Entropy (0–8)</th></tr></thead>
      <tbody>{sections_html}</tbody>
    </table>
  </div>

  <div class="panel">
    <h2>12-Stage Autonomous Pipeline Execution Trace</h2>
    <table>
      <thead><tr><th>Stage</th><th>Component</th><th>Status</th><th>Summary / Telemetry</th></tr></thead>
      <tbody>{stages_html}</tbody>
    </table>
  </div>
</div>
</body>
</html>
"""

    @classmethod
    def write_dashboard_from_pipeline(cls, sm: Any, output_html_path: str) -> str:
        state = sm.get_pipeline_state()
        html_doc = cls.generate_html_dashboard(state, static_metadata=sm.static_metadata)
        with open(output_html_path, "w", encoding="utf-8") as f:
            f.write(html_doc)
        return os.path.abspath(output_html_path)
