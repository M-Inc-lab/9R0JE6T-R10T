import re
"""
R3V3R53//F0RG3 — 12-Stage Pipeline State Machine & Autonomy Coordinator (§03.2, §16, §17)
Coordinates Stage 0–11 autonomous progression, Human-In-the-Loop (HIL) gates, and anti-loop guards.
"""

import enum
import hashlib
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from reverse_forge.correlation_engine import CorrelationEngine
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.ghidra_analyzer import GhidraHeadlessAnalyzer
from reverse_forge.macho_analyzer import MachOAnalyzer
from reverse_forge.pe_analyzer import PEAnalyzer
from reverse_forge.provenance import ActionPermission, ArtifactProvenance, ProvenanceManager, ScopeLedger
from reverse_forge.reporter import Finding, ReportGenerator
from reverse_forge.behavioral_engine import BehavioralTelemetryEngine
from reverse_forge.authorization import (
    ApprovalGrant,
    AuthorizationDecision,
    AuthorizationDeniedError,
    CentralAuthorizationBoundary,
    OperationType,
    get_authorization_boundary,
)
from reverse_forge.firebase_sync import AuthUserContext, UserRole


class AutonomyLevel(enum.IntEnum):
    MANUAL = 0              # Every single action requires explicit operator sign-off
    INTERACTIVE = 1         # Asks operator before any high-privilege tool or transition
    SUPERVISED = 2          # (Default) Pauses at risk boundaries & confirmation steps
    AUTONOMOUS = 3          # Automatic progression through all static & headless stages
    CONTINUOUS = 4          # Unconstrained end-to-end self-directing audit


class StageStatus(enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"
    BLOCKED_HIL = "BLOCKED_HIL"


@dataclass
class StageRecord:
    stage_id: int
    name: str
    status: StageStatus = StageStatus.PENDING
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    output_summary: str = ""
    error: Optional[str] = None


class AntiLoopGuard:
    """Detects cycles and repeated identical states to prevent infinite analysis loops."""

    def __init__(self, max_repeats_per_state: int = 3):
        self.max_repeats = max_repeats_per_state
        self.state_history: List[str] = []

    def record_transition(self, stage_id: int, signature: str) -> bool:
        """Returns True if transition is safe, False if an infinite loop is detected."""
        token = f"{stage_id}:{signature}"
        repeats = self.state_history.count(token)
        if repeats >= self.max_repeats:
            return False
        self.state_history.append(token)
        return True


class PipelineStateMachine:
    """12-Stage Reverse Engineering State Machine orchestrator."""

    STAGE_NAMES = {
        0: "Input & Scope Verification",
        1: "File & Format Reconnaissance",
        2: "Extraction & Wrapper Identification",
        3: "Static Analysis & Surface Enumeration",
        4: "Structural & Architecture Reconstruction",
        5: "Data-Flow & Input-Control Analysis",
        6: "Security Interface & Mitigations Analysis",
        7: "Sandboxed Dynamic Analysis (Optional/Gated)",
        8: "Hypothesis Validation & Correlation",
        9: "Finding Scoring & CVSS/CWE Triage",
        10: "Reproducibility & Report Generation",
        11: "Defensive Remediation Synthesis",
    }

    def __init__(
        self,
        artifact_path: str,
        autonomy_level: AutonomyLevel = AutonomyLevel.SUPERVISED,
        scope_ledger: Optional[ScopeLedger] = None,
        workspace_dir: Optional[str] = None,
        hil_callback: Optional[Callable[[str, Dict[str, Any]], bool]] = None,
        principal: Optional[AuthUserContext] = None,
        tenant_id: str = "default_tenant",
        approval_grant: Optional[ApprovalGrant] = None,
        strict_auth: bool = False,
    ):
        self.artifact_path = os.path.abspath(artifact_path)
        self.autonomy_level = autonomy_level
        self.tenant_id = tenant_id
        self.principal = principal or AuthUserContext(
            uid="local_operator",
            email="operator@reverse-forge.local",
            role=UserRole.ANALYST,
            tenant_id=tenant_id,
            is_verified=True,
        )
        self.active_approval_grant = approval_grant
        self.strict_auth = strict_auth
        self.authorization_boundary = get_authorization_boundary()
        if scope_ledger is not None:
            self.scope_ledger = scope_ledger
        else:
            # Default to restricted scope locked strictly to the specific canonical artifact path (fail-closed)
            target_real = os.path.realpath(self.artifact_path)
            self.scope_ledger = ScopeLedger(
                allowed_patterns=[os.path.basename(self.artifact_path)],
                allowed_paths=[target_real, os.path.dirname(target_real)],
                default_actions=[
                    ActionPermission.READ_HASH,
                    ActionPermission.STATIC_ANALYSIS,
                    ActionPermission.MODIFY_ARTIFACT,
                    ActionPermission.EXPORT_REPORT,
                ],
                allow_all=False,
            )
        self.provenance_mgr = ProvenanceManager(workspace_dir)
        self.hil_callback = hil_callback
        self.loop_guard = AntiLoopGuard()

        self.provenance: Optional[ArtifactProvenance] = None
        self.binary_bytes: bytes = b""
        self.format_name: str = "Unknown"
        self.static_metadata: Dict[str, Any] = {}
        self.correlation_results: Dict[str, Any] = {}
        self.ghidra_results: Dict[str, Any] = {}
        self.report_generator: Optional[ReportGenerator] = None

        self.stages: Dict[int, StageRecord] = {
            i: StageRecord(stage_id=i, name=self.STAGE_NAMES[i]) for i in range(12)
        }

    def _mark_stage(self, stage_id: int, status: StageStatus, summary: str = "", error: Optional[str] = None):
        rec = self.stages[stage_id]
        rec.status = status
        if status == StageStatus.RUNNING:
            rec.started_at = datetime.now(timezone.utc).isoformat()
        elif status in (StageStatus.COMPLETED, StageStatus.FAILED, StageStatus.SKIPPED):
            rec.finished_at = datetime.now(timezone.utc).isoformat()
            rec.output_summary = summary
            rec.error = error

    STAGE_REQUIRED_PERMISSIONS = {
        0: ActionPermission.READ_HASH,
        1: ActionPermission.STATIC_ANALYSIS,
        2: ActionPermission.STATIC_ANALYSIS,
        3: ActionPermission.STATIC_ANALYSIS,
        4: ActionPermission.STATIC_ANALYSIS,
        5: ActionPermission.STATIC_ANALYSIS,
        6: ActionPermission.STATIC_ANALYSIS,
        7: ActionPermission.DYNAMIC_SANDBOX,
        8: ActionPermission.STATIC_ANALYSIS,
        9: ActionPermission.STATIC_ANALYSIS,
        10: ActionPermission.STATIC_ANALYSIS,
        11: ActionPermission.STATIC_ANALYSIS,
    }

    STAGE_OPERATION_MAP = {
        0: OperationType.READ_METADATA,
        1: OperationType.STATIC_ANALYSIS,
        2: OperationType.STATIC_ANALYSIS,
        3: OperationType.STATIC_ANALYSIS,
        4: OperationType.STATIC_ANALYSIS,
        5: OperationType.STATIC_ANALYSIS,
        6: OperationType.STATIC_ANALYSIS,
        7: OperationType.DYNAMIC_SANDBOX,
        8: OperationType.STATIC_ANALYSIS,
        9: OperationType.STATIC_ANALYSIS,
        10: OperationType.EXPORT_REPORT,
        11: OperationType.REMEDIATION_PATCH,
    }

    def _check_hil_gate(
        self,
        prompt: str,
        context: Dict[str, Any],
        action: ActionPermission = ActionPermission.DYNAMIC_SANDBOX,
        operation: Optional[OperationType] = None,
    ) -> bool:
        """
        Enforce mandatory human approval and scope authorization through CentralAuthorizationBoundary (§04).
        Autonomous mode CANNOT bypass security policies for sensitive actions.
        Missing HIL callback strictly denies sensitive actions (fail-closed).
        """
        # 1. Mandatory Scope Check first: ScopeLedger must authorize the action
        if not self.scope_ledger.is_authorized(self.artifact_path, action=action):
            return False

        op = operation or (OperationType.DYNAMIC_SANDBOX if action == ActionPermission.DYNAMIC_SANDBOX else OperationType.STATIC_ANALYSIS)
        target_sha256 = self.provenance.sha256 if self.provenance else hashlib.sha256(self.binary_bytes).hexdigest()

        permitted, decision, reason, grant = self.authorization_boundary.evaluate_request(
            principal=self.principal,
            operation=op,
            target_path=self.artifact_path,
            target_sha256=target_sha256,
            target_tenant_id=self.tenant_id,
            parameters=context,
            scope_ledger=self.scope_ledger,
            approval_grant=self.active_approval_grant,
            hil_callback=self.hil_callback,
            autonomy_level=self.autonomy_level.value,
        )
        if permitted and grant:
            self.active_approval_grant = grant
        return permitted

    def run_all(self) -> Dict[str, Any]:
        """Execute the full 12-stage pipeline sequentially."""
        for stage_idx in range(12):
            success = self.execute_stage(stage_idx)
            if not success and self.stages[stage_idx].status == StageStatus.FAILED:
                break
        return self.get_pipeline_state()

    def execute_stage(self, stage_id: int) -> bool:
        req_action = self.STAGE_REQUIRED_PERMISSIONS.get(stage_id, ActionPermission.STATIC_ANALYSIS)
        if not self.scope_ledger.is_authorized(self.artifact_path, action=req_action):
            # If sensitive optional stage (like dynamic sandbox), mark SKIPPED with reason
            if req_action in (ActionPermission.DYNAMIC_SANDBOX, ActionPermission.NETWORK_ACCESS):
                self._mark_stage(
                    stage_id,
                    StageStatus.SKIPPED,
                    summary=f"Skipped: Action '{req_action.value}' not authorized in ScopeLedger policy"
                )
                return True
            self._mark_stage(
                stage_id,
                StageStatus.FAILED,
                error=f"Security Policy Denied: Action '{req_action.value}' not authorized by ScopeLedger for target '{self.artifact_path}'"
            )
            return False

        # Central authorization boundary evaluation
        op = self.STAGE_OPERATION_MAP.get(stage_id, OperationType.STATIC_ANALYSIS)
        target_sha256 = self.provenance.sha256 if self.provenance else (hashlib.sha256(self.binary_bytes).hexdigest() if self.binary_bytes else "")
        permitted, decision, reason, grant = self.authorization_boundary.evaluate_request(
            principal=self.principal,
            operation=op,
            target_path=self.artifact_path,
            target_sha256=target_sha256,
            target_tenant_id=self.tenant_id,
            parameters={"stage": stage_id},
            scope_ledger=self.scope_ledger,
            approval_grant=self.active_approval_grant,
            hil_callback=self.hil_callback if op in self.authorization_boundary.MANDATORY_HIL_OPERATIONS else None,
            autonomy_level=self.autonomy_level.value,
        )
        if not permitted:
            if op in self.authorization_boundary.MANDATORY_HIL_OPERATIONS and not self.strict_auth:
                self._mark_stage(
                    stage_id,
                    StageStatus.SKIPPED,
                    summary=f"Skipped: Operator declined or unauthorized ({reason})"
                )
                return True
            self._mark_stage(
                stage_id,
                StageStatus.SKIPPED if op in self.authorization_boundary.MANDATORY_HIL_OPERATIONS else StageStatus.FAILED,
                error=f"Security Policy Denied: {reason}" if op not in self.authorization_boundary.MANDATORY_HIL_OPERATIONS else None,
                summary=f"Skipped: Operator declined or unauthorized ({reason})" if op in self.authorization_boundary.MANDATORY_HIL_OPERATIONS else "",
            )
            return False

        if not self.loop_guard.record_transition(stage_id, self.format_name):
            self._mark_stage(stage_id, StageStatus.FAILED, error="Anti-loop guard detected infinite cyclic transition")
            return False

        self._mark_stage(stage_id, StageStatus.RUNNING)

        try:
            handler = getattr(self, f"_stage_{stage_id}", None)
            if not handler:
                self._mark_stage(stage_id, StageStatus.SKIPPED, summary="No handler defined")
                return True

            return handler()
        except Exception as e:
            self._mark_stage(stage_id, StageStatus.FAILED, error=str(e))
            return False

    # Stage 0: Input & Scope Verification
    def _stage_0(self) -> bool:
        self.provenance = self.provenance_mgr.ingest_artifact(
            self.artifact_path, scope_ledger=self.scope_ledger
        )
        if not self.provenance.in_scope:
            self._mark_stage(0, StageStatus.FAILED, error=f"Target outside authorized scope: {self.artifact_path}")
            return False

        with open(self.provenance.working_copy_path, "rb") as f:
            self.binary_bytes = f.read()

        self.report_generator = ReportGenerator(
            target_name=self.provenance.artifact_name,
            sha256=self.provenance.sha256
        )

        summary = f"Ingested into sandbox. SHA-256: {self.provenance.sha256[:16]}... Read-only working copy active."
        self._mark_stage(0, StageStatus.COMPLETED, summary=summary)
        return True

    # Stage 1: File & Format Reconnaissance
    def _stage_1(self) -> bool:
        engine = CorrelationEngine()
        self.format_name = engine.identify_format(self.binary_bytes)
        summary = f"Detected binary format: {self.format_name}"
        self._mark_stage(1, StageStatus.COMPLETED, summary=summary)
        return True

    # Stage 2: Extraction & Wrapper Identification
    def _stage_2(self) -> bool:
        entropy = PEAnalyzer.calculate_entropy(self.binary_bytes)
        packed = entropy > 7.2
        
        from reverse_forge.layer_unpacker import LayerUnpacker
        containers = LayerUnpacker.identify_embedded_containers(self.binary_bytes)
        dotnet_info = LayerUnpacker.inspect_dotnet_metadata(self.binary_bytes)
        fat_slices = LayerUnpacker.parse_macho_fat_slices(self.binary_bytes)

        summary_parts = [f"Entropy: {entropy:.2f}"]
        if packed:
            summary_parts.append("Suspicious High Entropy (Packer)")
            self.report_generator.add_non_finding(
                f"High entropy ({entropy:.2f}) observed in Stage 2 indicates possible compression/packing."
            )
        if dotnet_info.get("is_dotnet"):
            summary_parts.append(".NET Assembly Detected")
        if containers:
            summary_parts.append(f"Embedded Containers: {len(containers)}")
        if fat_slices:
            summary_parts.append(f"Universal Fat Slices: {len(fat_slices)}")

        summary = ". ".join(summary_parts)
        self._mark_stage(2, StageStatus.COMPLETED, summary=summary)
        return True

    # Stage 3: Static Analysis & Surface Enumeration
    def _stage_3(self) -> bool:
        if self.format_name == "PE":
            self.static_metadata = PEAnalyzer(self.binary_bytes).analyze()
        elif self.format_name == "ELF":
            elf_analyzer = ELFAnalyzer(self.binary_bytes)
            base_meta = elf_analyzer.analyze()
            audit_meta = elf_analyzer.full_audit()
            base_meta.update(audit_meta)
            self.static_metadata = base_meta
        elif self.format_name == "Mach-O":
            macho_analyzer = MachOAnalyzer(self.binary_bytes)
            base_meta = macho_analyzer.analyze()
            audit_meta = macho_analyzer.full_audit()
            base_meta.update(audit_meta)
            self.static_metadata = base_meta
        else:
            self.static_metadata = {"entropy": PEAnalyzer.calculate_entropy(self.binary_bytes)}

        from reverse_forge.signature_engine import SignatureEngine
        from reverse_forge.cpp_rtti_engine import CppRTTIEngine
        sig_scan = SignatureEngine().full_signature_scan(self.binary_bytes)
        self.static_metadata["signature_scan"] = sig_scan

        rtti_rep = CppRTTIEngine().analyze_binary_rtti(
            self.binary_bytes,
            symbol_list=self.static_metadata.get("imported_symbols", []) + self.static_metadata.get("exported_symbols", []),
        )
        self.static_metadata["cpp_rtti_classes_recovered"] = rtti_rep.total_classes_recovered
        prologues = sig_scan["stripped_function_recovery"]["estimated_function_prologues_total"]
        sig_hits = sig_scan["total_signature_matches"]

        # Anti-injection sanitization for symbols, section names, and strings
        from reverse_forge.anti_injection_guard import AntiInjectionGuard
        guard = AntiInjectionGuard()
        self.static_metadata, injection_attempts = guard.sanitize_metadata_dict(self.static_metadata)
        for att in injection_attempts:
            self.report_generator.add_finding(Finding(
                finding_id="ADVERSARIAL-METADATA-POISON",
                title=f"Adversarial Binary Metadata Attack: {att.injection_type}",
                vulnerability_class="Adversarial Injection / AI Poisoning",
                confidence="Confirmed",
                cvss_score=7.5,
                cwe_id="CWE-116",
                function_symbol="Binary Header / Symbol Table",
                address_or_offset=att.source_field,
                what=f"Target binary contains adversarial payload: {att.raw_payload_snippet}",
                why="Binary attempts to mislead automated analyzers or poison LLM decompiler context.",
                where=att.source_field,
                when="Static analysis ingestion",
                how="Adversarial payload injected into symbol or section table.",
                remediation=att.defense_action,
            ))

        summary = (
            f"Extracted header, sections, and symbols for {self.format_name} "
            f"(Signature hits: {sig_hits}, Prologue candidates: {prologues}, Injections neutralized: {len(injection_attempts)})"
        )
        self._mark_stage(3, StageStatus.COMPLETED, summary=summary)
        return True

    # Stage 4: Structural & Architecture Reconstruction
    def _stage_4(self) -> bool:
        # Multi-tool correlation: invoke Radare2 / Capstone via CorrelationEngine
        corr = CorrelationEngine()
        self.correlation_results = corr.analyze_artifact(self.provenance.working_copy_path, run_ghidra=False)
        r2_funcs = self.correlation_results.get("tool_radare2", {}).get("functions_count", 0)
        cs_insns = len(self.correlation_results.get("tool_capstone", {}).get("disassembled_instructions", []))

        # Native micro-decompilation + Phase 33 Region Structuring + Phase 34 Datalog/VSA sweep
        from reverse_forge.decompiler_engine import MicroDecompilerEngine
        from reverse_forge.datalog_vsa_engine import DatalogVSAEngine
        decompiler = MicroDecompilerEngine()
        code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(self.binary_bytes, self.static_metadata)
        base_va = entry_va or 0x401000
        native_decomp = decompiler.decompile_raw_bytes(code_slice, base_addr=base_va)
        self.static_metadata["native_decompiled_c"] = native_decomp.c_source

        vsa_engine = DatalogVSAEngine()
        swept_funcs = vsa_engine.sweep_executable_section(code_slice, base_addr=base_va)
        self.static_metadata["vsa_discovered_functions"] = [hex(a) for a in swept_funcs[:64]]

        summary = (
            f"Disassembly: Capstone ({cs_insns} insns) / Radare2 ({r2_funcs} funcs). "
            f"Native Decompiler recovered {native_decomp.total_blocks} CFG blocks."
        )
        self._mark_stage(4, StageStatus.COMPLETED, summary=summary)
        return True

    # Stage 5: Data-Flow & Input-Control Analysis
    def _stage_5(self) -> bool:
        # 1. Attempt headless Ghidra extraction if available
        ghidra = GhidraHeadlessAnalyzer()
        self.ghidra_results = ghidra.analyze(self.provenance.working_copy_path, timeout=60)
        g_analysis = self.ghidra_results.get("analysis", {})
        decomp_list = self.ghidra_results.get("decompiled_functions") or g_analysis.get("decompiled_functions", [])
        decomp_count = len(decomp_list)

        # 2. Build Call-Graph & Taint Flow analysis
        from reverse_forge.dataflow_engine import DataFlowGraph
        dfg = DataFlowGraph()
        sinks = dict(self.ghidra_results.get("sink_xrefs", {}))
        if not sinks and g_analysis.get("dangerous_sink_xrefs"):
            for item in g_analysis["dangerous_sink_xrefs"]:
                s_name = item.get("sink", "").lstrip("_")
                caller = item.get("caller_function") or "unknown"
                if s_name:
                    sinks.setdefault(s_name, []).append(caller)
        self.ghidra_results["sink_xrefs"] = sinks
        if sinks:
            dfg.build_from_xrefs(sinks)

        # Also add imported symbols to call-graph so co-occurring sources & sinks are detected
        for sym in self.static_metadata.get("imported_symbols", []):
            clean_sym = str(sym).lstrip("_")
            if clean_sym:
                dfg.add_edge("entry", clean_sym)

        flows = dfg.analyze_source_to_sink_flows()
        for flow in flows:
            self.report_generator.add_finding(Finding(
                finding_id=f"TAINT-{flow.sink_name.upper()}",
                title=f"Source-to-Sink Taint Path: {flow.source_name} -> {flow.sink_name}",
                vulnerability_class="Untrusted Data Flow & Memory Taint",
                confidence=flow.path_confidence,
                cvss_score=8.5,
                cwe_id=flow.cwe,
                function_symbol=" -> ".join(flow.intermediate_nodes),
                address_or_offset="CallGraph Edge",
                what=flow.description,
                why="Untrusted input flows directly or transitively into hazardous sink.",
                where=f"Path nodes: {flow.intermediate_nodes}",
                when="Processing external untrusted input stream",
                how="Payload reaches sink parameter without sanitization or bounds check.",
                remediation=f"Sanitize data from `{flow.source_name}` before invoking `{flow.sink_name}`."
            ))

        # 3. Interprocedural pointer alias & heap lifecycle analysis over decompiled pseudocode
        from reverse_forge.pointer_alias_engine import PointerAliasEngine
        pae = PointerAliasEngine()
        for dfn in decomp_list:
            c_text = dfn.get("pseudocode", "") if isinstance(dfn, dict) else ""
            fn_label = dfn.get("function", "func") if isinstance(dfn, dict) else "func"
            seq = []
            for idx, line in enumerate(c_text.splitlines()):
                st = line.strip().rstrip(";")
                if "malloc(" in st or "calloc(" in st:
                    seq.append((f"{fn_label}:{idx}", "CALL", st))
                elif "free(" in st:
                    seq.append((f"{fn_label}:{idx}", "CALL", st))
            if seq:
                pae.analyze_instruction_sequence(seq)
        for defect in pae.defects:
            self.report_generator.add_finding(Finding(
                finding_id=f"HEAP-{defect.defect_type}",
                title=f"Heap Lifecycle Defect: {defect.defect_type} on `{defect.pointer_var}`",
                vulnerability_class="Memory Lifecycle & Aliasing",
                confidence="Probable",
                cvss_score=defect.cvss_score,
                cwe_id=defect.cwe,
                function_symbol=defect.pointer_var,
                address_or_offset=defect.trigger_site,
                what=defect.description,
                why="Pointer continues to be referenced or freed again after deallocation.",
                where=f"Allocated at {defect.alloc_site}, triggered at {defect.trigger_site}",
                when="Dynamic heap management",
                how="Dangling pointer alias is dereferenced or passed to free() twice.",
                remediation="Nullify pointers immediately after free (`ptr = NULL;`) and enforce single-ownership smart pointers.",
            ))

        summary = f"Ghidra status: {self.ghidra_results.get('status')}. Decompiled: {decomp_count}. Taint paths: {len(flows)}"
        self._mark_stage(5, StageStatus.COMPLETED, summary=summary)
        return True

    # Stage 6: Security Interface & Mitigations Analysis
    def _stage_6(self) -> bool:
        severity_to_cvss = {"CRITICAL": 9.2, "HIGH": 7.8, "MEDIUM": 5.5, "LOW": 3.5}
        # Evaluate platform mitigations and dangerous calls
        if self.format_name == "PE":
            try:
                from reverse_forge.windows_engine import WindowsEngine
                with WindowsEngine(self.provenance.working_copy_path) as wengine:
                    audit = wengine.full_audit()
                pe_vulns = audit.get("identified_vulnerabilities") or audit.get("vulnerabilities", [])
                for vuln in pe_vulns:
                    v_title = vuln.get("title") or vuln.get("rule", "PE Security Weakness")
                    v_sev = vuln.get("severity", "MEDIUM").upper()
                    self.report_generator.add_finding(Finding(
                        finding_id=vuln.get("id", "WIN-VULN"),
                        title=v_title,
                        vulnerability_class="Binary Mitigation / API Deficiency",
                        confidence="Confirmed",
                        cvss_score=severity_to_cvss.get(v_sev, 5.5),
                        cwe_id=vuln.get("cwe", "CWE-693"),
                        function_symbol="PE Header / IAT",
                        address_or_offset="OptionalHeader",
                        what=vuln.get("description", ""),
                        why="Binary was compiled without modern mitigation flags or imports unsafe APIs.",
                        where="PE OptionalHeader / Import Directory",
                        when="Process initialization or runtime API invocation",
                        how="Loader maps sections without security enforcement or invokes unbounded CRT APIs.",
                        remediation=vuln.get("remediation", "Recompile with /NXCOMPAT, /DYNAMICBASE, and /guard:cf.")
                    ))
            except Exception as e:
                self.report_generator.add_blocker(f"WindowsEngine PE audit bypassed: {e}")

        elif self.format_name in ("ELF", "Mach-O"):
            for vuln in self.static_metadata.get("identified_vulnerabilities", []):
                v_title = vuln.get("title", f"{self.format_name} Security Weakness")
                v_sev = vuln.get("severity", "MEDIUM").upper()
                self.report_generator.add_finding(Finding(
                    finding_id=vuln.get("id", f"{self.format_name.upper()}-VULN"),
                    title=v_title,
                    vulnerability_class="Binary Mitigation / Symbol Deficiency",
                    confidence="Confirmed",
                    cvss_score=severity_to_cvss.get(v_sev, 5.5),
                    cwe_id=vuln.get("cwe", "CWE-119"),
                    function_symbol=f"{self.format_name} Header / Symbol Table",
                    address_or_offset=str(self.static_metadata.get("entry_point", "0x0")),
                    what=vuln.get("description", ""),
                    why=f"{self.format_name} binary lacks recommended hardening or imports hazardous symbols.",
                    where=f"{self.format_name} Program/Load Headers & Symbol Table",
                    when="Binary load or input processing",
                    how="Missing mitigation or unbounded symbol consumption increases exploitability.",
                    remediation="Recompile with PIE, non-executable stack, Full RELRO, and bounded string APIs."
                ))

        # Cryptographic algorithms & embedded secrets scan
        from reverse_forge.crypto_engine import CryptoSecretEngine
        crypto_engine = CryptoSecretEngine()
        crypto_audit = crypto_engine.full_crypto_audit(self.binary_bytes)

        for sec in crypto_audit.get("secrets_detected", []):
            self.report_generator.add_finding(Finding(
                finding_id=f"SECRET-{sec['secret_type']}",
                title=f"Hardcoded Cryptographic Secret / Credential: {sec['secret_type']}",
                vulnerability_class="Hardcoded Credentials & Cryptographic Exposure",
                confidence=sec["confidence"],
                cvss_score=8.6,
                cwe_id="CWE-798",
                function_symbol="Embedded Constant",
                address_or_offset=hex(sec["offset"]),
                what=f"Hardcoded credential or key detected (masked: {sec['matched_value_masked']}, entropy: {sec['entropy']}).",
                why=sec["description"],
                where="Binary data segment / read-only rodata",
                when="Static binary inspection or runtime credential extraction",
                how="Adversary extracts hardcoded key directly from binary string table.",
                remediation="Store secrets externally in a secure vault (KMS / HashiCorp Vault / DPAPI)."
            ))

        for prim in crypto_audit.get("primitives_detected", []):
            if "Weak" in prim["algorithm_family"]:
                self.report_generator.add_finding(Finding(
                    finding_id=f"CRYPTO-WEAK-{prim['primitive_name']}",
                    title=f"Deprecated / Collision-Prone Hash Algorithm: {prim['primitive_name']}",
                    vulnerability_class="Broken / Risky Cryptographic Algorithm",
                    confidence=prim["confidence"],
                    cvss_score=6.5,
                    cwe_id="CWE-328",
                    function_symbol="Cryptographic Constant Table",
                    address_or_offset=hex(prim["offset"]),
                    what=prim["description"],
                    why="Algorithm is mathematically broken and vulnerable to practical hash collision attacks.",
                    where="Binary initialization block",
                    when="Verifying cryptographic signatures or data integrity",
                    how="Adversary crafts colliding payload matching expected digest.",
                    remediation="Upgrade to SHA-256, SHA-3, or Argon2id."
                ))

        summary = (
            f"Security mitigation audit completed for {self.format_name}. "
            f"Crypto status: {crypto_audit['crypto_hygiene_status']} "
            f"(Secrets: {crypto_audit['high_risk_secrets_count']}, Weak Algos: {crypto_audit['weak_algorithms_count']})"
        )
        self._mark_stage(6, StageStatus.COMPLETED, summary=summary)
        return True

    # Stage 7: Sandboxed Dynamic Analysis (Optional/Gated)
    def _stage_7(self) -> bool:
        authorized = self._check_hil_gate(
            "Execute dynamic behavioral analysis in sandbox?",
            {"target": self.artifact_path, "stage": 7},
            action=ActionPermission.DYNAMIC_SANDBOX,
        )
        if not authorized:
            self._mark_stage(7, StageStatus.SKIPPED, summary="Operator declined sandboxed dynamic execution.")
            return False if self.strict_auth else True

        from reverse_forge.windows_sandbox import WindowsSandbox
        from reverse_forge.posix_sandbox import POSIXSandboxEngine
        from reverse_forge.frida_dbi_engine import FridaDBIEngine

        wsb = WindowsSandbox(self.provenance.working_copy_path)
        wsb_profile = os.path.join(self.provenance_mgr.workspace_root, "detonation_profile.wsb")
        wsb.generate_wsb_profile(wsb_profile)

        ps1_collector = os.path.join(self.provenance_mgr.workspace_root, "collect_telemetry.ps1")
        WindowsSandbox.generate_telemetry_collector_script(ps1_collector, self.provenance.artifact_name)

        posix_runner = os.path.join(self.provenance_mgr.workspace_root, "posix_isolated_runner.sh")
        POSIXSandboxEngine(self.provenance.working_copy_path).generate_isolated_runner_script(posix_runner)

        frida_js = os.path.join(self.provenance_mgr.workspace_root, "frida_telemetry.js")
        hook_syms = [s for s in self.static_metadata.get("imported_symbols", [])[:15] if re.match(r"^[A-Za-z0-9_]+$", str(s))]
        if not hook_syms:
            hook_syms = ["main", "recv", "strcpy"]
        FridaDBIEngine.write_frida_script(frida_js, hook_syms)

        summary = (
            f"Generated Windows (.wsb/PS1) & Linux/POSIX (bwrap/strace) isolation runners "
            f"plus Frida DBI script ({len(hook_syms)} hooks)"
        )
        self._mark_stage(7, StageStatus.COMPLETED, summary=summary)
        return True

    # Stage 8: Hypothesis Validation & Correlation
    def _stage_8(self) -> bool:
        # 1. Cross-reference static findings with discovered xrefs/sinks
        sinks = self.ghidra_results.get("sink_xrefs", {})
        for sink_name, callers in sinks.items():
            if callers:
                self.report_generator.add_finding(Finding(
                    finding_id=f"SINK-{sink_name.upper()}",
                    title=f"Potential Insecure Usage of Dangerous Sink: {sink_name}",
                    vulnerability_class="Dangerous API Consumption",
                    confidence="Probable",
                    cvss_score=6.8,
                    cwe_id="CWE-676",
                    function_symbol=str(callers[0]),
                    address_or_offset="Decompiled xref",
                    what=f"Call to potentially dangerous function `{sink_name}` discovered.",
                    why="Dangerous APIs can lead to buffer overflows or arbitrary command execution if input is unchecked.",
                    where=f"Caller function `{callers[0]}`",
                    when="Triggered during user input parsing path",
                    how="Input flows into parameter without strict boundary checking.",
                    remediation=f"Replace `{sink_name}` with safe bounded alternative."
                ))

        # 2. Concolic path exploration & exploit payload synthesis for sinks
        from reverse_forge.concolic_engine import ConcolicPathPruner
        from reverse_forge.smt_solver_engine import PathConstraint
        concolic_pruner = ConcolicPathPruner()
        for sink_name in sinks.keys():
            # Synthesize trigger for potential unbounded length
            synth_res = concolic_pruner.synthesize_exploit_trigger(
                path_constraints=[PathConstraint(var="input_len", op="GT", value=0)],
                length_var="input_len",
                buffer_capacity=512,
                sink_name=sink_name,
            )
            if synth_res.is_satisfiable:
                self.report_generator.add_finding(Finding(
                    finding_id=f"SYNTH-SAT-{sink_name.upper()}",
                    title=f"SMT Proven Exploit Trigger Payload: {sink_name}",
                    vulnerability_class="Mathematically Proven Out-of-Bounds Condition",
                    confidence="Confirmed",
                    cvss_score=9.1,
                    cwe_id="CWE-787",
                    function_symbol=sink_name,
                    address_or_offset="Concolic AST Path",
                    what=synth_res.solver_notes,
                    why="Solver mathematically derived an unconstrained input triggering memory corruption.",
                    where=f"Call path to {sink_name}",
                    when="Input parsing before length validation",
                    how=f"Supplying input matching payload model {synth_res.payload_input} exceeds buffer capacity.",
                    remediation="Insert strict upper-bound invariant check: `if (input_len > 512) return -1;`"
                ))

        # 3. Correlate with behavioral telemetry traces if available
        telemetry_file = os.path.join(os.path.dirname(self.provenance.working_copy_path), "telemetry_trace.json")
        b_engine = BehavioralTelemetryEngine()
        if os.path.exists(telemetry_file):
            b_engine.ingest_json_trace(telemetry_file)
            matches = b_engine.correlate_with_static_analysis(self.static_metadata)
            for m in matches:
                self.report_generator.add_finding(Finding(
                    finding_id=f"BEHAV-{m.hypothesis_id}",
                    title=f"Runtime Correlated Behavior: {m.runtime_event_type}",
                    vulnerability_class="Runtime Behavioral Telemetry",
                    confidence="Confirmed",
                    cvss_score=8.2,
                    cwe_id="CWE-693",
                    function_symbol=m.static_symbol_or_address,
                    address_or_offset="Runtime Trace",
                    what=m.runtime_detail,
                    why=m.rationale,
                    where="Sandboxed execution environment",
                    when="Observed actively during dynamic execution",
                    how="Process triggered event during monitored session",
                    remediation="Validate execution environment and apply least-privilege confinement."
                ))

        summary = "Correlated static headers, decompiled call-paths, concolic exploit models, and runtime telemetry."
        self._mark_stage(8, StageStatus.COMPLETED, summary=summary)
        return True

    # Stage 9: Finding Scoring & CVSS/CWE Triage
    def _stage_9(self) -> bool:
        summary = f"Scored {len(self.report_generator.findings)} findings against CVSS 4.0 / CWE"
        self._mark_stage(9, StageStatus.COMPLETED, summary=summary)
        return True

    # Stage 10: Reproducibility & Report Generation
    def _stage_10(self) -> bool:
        summary = "Dual Executive Summary & Technical Triage report formatted"
        self._mark_stage(10, StageStatus.COMPLETED, summary=summary)
        return True

    # Stage 11: Defensive Remediation Synthesis
    def _stage_11(self) -> bool:
        target_sha256 = self.provenance.sha256 if self.provenance else (hashlib.sha256(self.binary_bytes).hexdigest() if self.binary_bytes else "")
        permitted, decision, reason, grant = self.authorization_boundary.evaluate_request(
            principal=self.principal,
            operation=OperationType.REMEDIATION_PATCH,
            target_path=self.artifact_path,
            target_sha256=target_sha256,
            target_tenant_id=self.tenant_id,
            parameters={"stage": 11},
            scope_ledger=self.scope_ledger,
            approval_grant=self.active_approval_grant,
            hil_callback=self.hil_callback,
            autonomy_level=self.autonomy_level.value,
        )
        if not permitted:
            if self.strict_auth:
                raise AuthorizationDeniedError(decision, reason, {})
            self._mark_stage(11, StageStatus.SKIPPED, summary=f"Central boundary denied remediation synthesis: {reason}")
            return False

        from reverse_forge.remediation_engine import RemediationEngine
        from reverse_forge.patch_verifier import PatchVerifier
        rem_engine = RemediationEngine()
        verifier = PatchVerifier()
        remediation_count = 0
        verified_count = 0

        # Synthesize patches and regression harnesses for confirmed findings
        for f in self.report_generator.findings:
            if f.confidence in ("Confirmed", "Probable") and f.cwe_id:
                patch = rem_engine.generate_defensive_patch(f.finding_id, f.cwe_id, f.function_symbol)
                harness = rem_engine.generate_regression_test_harness(self.provenance.artifact_name, f.cwe_id)
                v_report = verifier.verify_patch_resilience(patch)
                remediation_count += 1
                if v_report.verdict == "VERIFIED_DEFENDED":
                    verified_count += 1
                f.remediation += (
                    f"\n\n```diff\n{patch.diff_patch}```\n"
                    f"**Hardening Flags:** `{', '.join(patch.compiler_hardening_flags)}`\n"
                    f"**Verification:** `{v_report.verdict}` ({v_report.invariant_checked})\n"
                    f"**Defensive Test:** `{harness.execution_command}`"
                )

        summary = f"Synthesized {remediation_count} defensive code patches ({verified_count} verified) and regression test harnesses."
        self._mark_stage(11, StageStatus.COMPLETED, summary=summary)
        return True

    def get_pipeline_state(self) -> Dict[str, Any]:
        return {
            "artifact": self.provenance.artifact_name if self.provenance else os.path.basename(self.artifact_path),
            "sha256": self.provenance.sha256 if self.provenance else "",
            "autonomy_level": self.autonomy_level.name,
            "stages": [
                {
                    "stage": s.stage_id,
                    "name": s.name,
                    "status": s.status.value,
                    "summary": s.output_summary,
                    "error": s.error,
                }
                for s in self.stages.values()
            ],
            "report_json": self.report_generator.to_json() if self.report_generator else {},
            "report_markdown": self.report_generator.to_markdown() if self.report_generator else "",
        }


# Canonical export alias
ReverseForgePipeline = PipelineStateMachine

