"""
R3V3R53//F0RG3 — Part III: Natural Language Intent Understanding & Objective Compiler
(`intent_engine.py`)

Translates freeform natural language investigation objectives into structured,
executable, hypothesis-generating `InvestigationSpecification` plans.
"""

from __future__ import annotations

import enum
import hashlib
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from reverse_forge.capability_registry import CapabilityRegistry, ToolCategory, capability_registry

logger = logging.getLogger("reverse_forge.intent_engine")


class InvestigationObjectiveType(enum.Enum):
    CONFIG_EXTRACTION = "CONFIG_EXTRACTION"
    CRASH_ROOT_CAUSE = "CRASH_ROOT_CAUSE"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    DATA_FLOW_TRACING = "DATA_FLOW_TRACING"
    SUSPICIOUS_BEHAVIOR = "SUSPICIOUS_BEHAVIOR"
    BINARY_DIFFING = "BINARY_DIFFING"
    VULNERABILITY_RESEARCH = "VULNERABILITY_RESEARCH"
    ARCHITECTURE_MAPPING = "ARCHITECTURE_MAPPING"
    GENERAL_RECON = "GENERAL_RECON"


@dataclass
class InvestigationSpecification:
    """Rigorous compiled specification of an intent-driven reverse engineering mission."""
    spec_id: str
    raw_intent: str
    objective_type: InvestigationObjectiveType
    primary_objective: str
    target_artifact_path: str
    candidate_tools: List[str]                  # List of tool_ids from CapabilityRegistry
    candidate_techniques: List[str]            # e.g., ["SSA Decompilation", "Backward Slicing"]
    questions_to_answer: List[str]
    required_evidence_types: List[str]         # e.g., ["CFG", "Decompiled C", "Call Trace", "Taint Path"]
    expected_deliverables: List[str]           # e.g., ["SARIF", "Annotated C", "Executive Report"]
    requires_dynamic_execution: bool
    requires_hil_approval: bool
    safety_constraints: List[str]
    budget_seconds: float = 60.0
    max_iterations: int = 25
    remaining_uncertainties: List[str] = field(default_factory=list)
    inferred_assumptions: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["objective_type"] = self.objective_type.value
        return d


class IntentCompiler:
    """
    Compiles human investigative intent into a machine-actionable
    investigation plan with tool selection and safety boundaries.
    """

    INTENT_KEYWORDS: Dict[InvestigationObjectiveType, List[str]] = {
        InvestigationObjectiveType.CONFIG_EXTRACTION: [
            "config", "configuration", "settings", "embedded", "c2", "endpoint", "url", "domain", "key", "secret"
        ],
        InvestigationObjectiveType.CRASH_ROOT_CAUSE: [
            "crash", "fault", "core dump", "segfault", "sigsegv", "null pointer", "exception", "panic", "root cause"
        ],
        InvestigationObjectiveType.INPUT_VALIDATION: [
            "validate", "validation", "sanitize", "boundary", "bounds check", "length check", "filter", "parameter"
        ],
        InvestigationObjectiveType.DATA_FLOW_TRACING: [
            "trace", "data flow", "dataflow", "taint", "source to sink", "user input", "network packet", "payload path"
        ],
        InvestigationObjectiveType.SUSPICIOUS_BEHAVIOR: [
            "suspicious", "malware", "trojan", "stealth", "evasion", "anti-debug", "persistence", "hollowing", "packer"
        ],
        InvestigationObjectiveType.BINARY_DIFFING: [
            "diff", "compare", "patch", "version", "changes", "modified", "bindiff"
        ],
        InvestigationObjectiveType.VULNERABILITY_RESEARCH: [
            "vulnerability", "exploit", "cwe", "cve", "overflow", "buffer overflow", "uaf", "use after free",
            "format string", "memory corruption", "heap", "rop", "gadget"
        ],
        InvestigationObjectiveType.ARCHITECTURE_MAPPING: [
            "map", "architecture", "overview", "functions", "callgraph", "call graph", "modules", "components"
        ],
    }

    def __init__(self, registry: Optional[CapabilityRegistry] = None) -> None:
        self.registry = registry or capability_registry

    def compile(
        self,
        intent_text: str,
        target_artifact: str,
        format_hint: Optional[str] = None,
        arch_hint: Optional[str] = None,
    ) -> InvestigationSpecification:
        """Parse natural language intent into a structured InvestigationSpecification."""
        cleaned = intent_text.strip().lower()
        spec_id = f"spec_{uuid.uuid4().hex[:12]}"

        # 1. Classify Primary Objective Type
        obj_type = self._classify_objective(cleaned)

        # 2. Derive Questions to Answer and Required Evidence
        questions, evidence, deliverables = self._derive_questions_and_evidence(obj_type, cleaned)

        # 3. Dynamic execution & HIL constraints
        dynamic_req = (obj_type in (InvestigationObjectiveType.CRASH_ROOT_CAUSE, InvestigationObjectiveType.SUSPICIOUS_BEHAVIOR)) or any(
            w in cleaned for w in ["run", "execute", "dynamic", "sandbox", "trace", "hook", "dbi", "live", "fault"]
        )
        hil_req = dynamic_req or any(w in cleaned for w in ["exploit", "fuzz", "patch", "modify", "network"])

        # 4. Map candidate tools from CapabilityRegistry
        candidate_tools, techniques = self._select_candidate_tools(obj_type, format_hint or "*", arch_hint or "*", dynamic_req)

        # 5. Safety constraints
        safety = [
            "Host execution prohibited without verified sandbox",
            "Read-only inspection of target binary",
            "Path canonicalization and traversal blocklist enforced",
            "Resource budget bounded to 60.0s",
        ]
        if hil_req:
            safety.append("HIL authorization required prior to any dynamic execution or mutation")

        assumptions = [
            f"Assumed target format is {format_hint or 'standard PE/ELF executable'}",
            f"Prioritizing {obj_type.value} analysis modules",
        ]

        uncertainties = []
        if obj_type == InvestigationObjectiveType.GENERAL_RECON:
            uncertainties.append("Broad objective; will start with full 12-stage reconnaissance")

        return InvestigationSpecification(
            spec_id=spec_id,
            raw_intent=intent_text,
            objective_type=obj_type,
            primary_objective=intent_text.strip(),
            target_artifact_path=target_artifact,
            candidate_tools=candidate_tools,
            candidate_techniques=techniques,
            questions_to_answer=questions,
            required_evidence_types=evidence,
            expected_deliverables=deliverables,
            requires_dynamic_execution=dynamic_req,
            requires_hil_approval=hil_req,
            safety_constraints=safety,
            budget_seconds=60.0,
            max_iterations=25,
            remaining_uncertainties=uncertainties,
            inferred_assumptions=assumptions,
        )

    def _classify_objective(self, text: str) -> InvestigationObjectiveType:
        scores: Dict[InvestigationObjectiveType, int] = {k: 0 for k in self.INTENT_KEYWORDS}
        for obj, keywords in self.INTENT_KEYWORDS.items():
            for kw in keywords:
                if kw in text:
                    scores[obj] += (3 if " " in kw else 1)

        best_type, best_score = max(scores.items(), key=lambda kv: kv[1])
        if best_score > 0:
            return best_type
        return InvestigationObjectiveType.GENERAL_RECON

    def _derive_questions_and_evidence(
        self,
        obj_type: InvestigationObjectiveType,
        text: str,
    ) -> Tuple[List[str], List[str], List[str]]:
        if obj_type == InvestigationObjectiveType.CONFIG_EXTRACTION:
            questions = [
                "Where are embedded configuration assets or strings stored?",
                "Are configuration parameters encrypted, base64-encoded, or obfuscated?",
                "Which functions parse or decode configuration files?",
            ]
            evidence = ["Decoded Strings", "Resource Offsets", "Decompiled Decryptor Loop"]
            deliverables = ["Config JSON Extraction", "Cryptographic Key Manifest", "Annotated C Pseudocode"]

        elif obj_type == InvestigationObjectiveType.CRASH_ROOT_CAUSE:
            questions = [
                "Which instruction address and basic block triggered the fault?",
                "What were the CPU register states and memory operands at the crash site?",
                "Is the crash caused by a NULL pointer dereference, buffer overflow, or stack exhaustion?",
            ]
            evidence = ["Faulting Virtual Address", "CFG Basic Block", "Disassembly Slice", "Register State Snapshot"]
            deliverables = ["Root Cause Assessment", "Crash Triage Report", "Remediation Patch"]

        elif obj_type == InvestigationObjectiveType.INPUT_VALIDATION:
            questions = [
                "What bounds checks or size validations are performed on user input?",
                "Can input parameters trigger an off-by-one or integer truncation?",
                "Are input validation failures safely handled with graceful termination?",
            ]
            evidence = ["Branch Conditions", "Decompiled C Bounds Guard", "SMT Path Feasibility Constraint"]
            deliverables = ["Validation Matrix", "Safe Input Specifications", "CWE Analysis"]

        elif obj_type == InvestigationObjectiveType.DATA_FLOW_TRACING:
            questions = [
                "Where does untrusted data enter the executable (socket, file, env)?",
                "Through which intermediate buffers and transformations does the data flow?",
                "Does untrusted data reach sensitive sinks (execve, system, format string, memcpy)?",
            ]
            evidence = ["Source-to-Sink Taint Path", "Function Call Graph", "Intermediate Variable Assignments"]
            deliverables = ["Data Flow Graph", "Taint Propagation Report", "Sink Reachability Proof"]

        elif obj_type == InvestigationObjectiveType.VULNERABILITY_RESEARCH:
            questions = [
                "Are compiler mitigations present (ASLR/PIE, Stack Canaries, DEP/NX, CET)?",
                "Are there unbounded memory copies or unsafe format string invocations?",
                "Can a heap use-after-free or double-free condition be reached?",
            ]
            evidence = ["CWE Violation Finding", "Checksec Mitigations Matrix", "Disassembled Sinks", "Memory Map"]
            deliverables = ["SARIF 2.1 Report", "CycloneDX SBOM", "Remediation Recommendation"]

        elif obj_type == InvestigationObjectiveType.SUSPICIOUS_BEHAVIOR:
            questions = [
                "Does the binary employ anti-analysis, anti-debugging, or VM detection?",
                "Does it establish persistence or communicate with external C2 servers?",
                "Are suspicious API calls (VirtualAllocEx, CreateRemoteThread, WriteProcessMemory) present?",
            ]
            evidence = ["MITRE ATT&CK Matrix", "Detected Suspicious APIs", "Entropy Spike Regions", "YARA Rule Matches"]
            deliverables = ["Threat Intel Dossier", "YARA Rule", "SIGMA Rule", "STIX 2.1 Bundle"]

        elif obj_type == InvestigationObjectiveType.BINARY_DIFFING:
            questions = [
                "Which functions were added, deleted, or modified between versions?",
                "Did code modifications fix known security vulnerabilities?",
                "Were any new attack surfaces or dependencies introduced?",
            ]
            evidence = ["Small-Prime-Product Graph Hash", "Basic Block Diff", "Modified Opcode Sequences"]
            deliverables = ["BinDiff Visual Graph", "Patch Verification Report"]

        else: # GENERAL_RECON / ARCHITECTURE_MAPPING
            questions = [
                "What is the binary format, architecture, and toolchain provenance?",
                "What are the major exported/imported functions and entry points?",
                "What security posture and hardening score does the binary exhibit?",
            ]
            evidence = ["Format Header", "Section Entropy Map", "Whole-Binary Function Index"]
            deliverables = ["Executive Summary", "Architecture Map", "Decompiled Prototypes"]

        return questions, evidence, deliverables

    def _select_candidate_tools(
        self,
        obj_type: InvestigationObjectiveType,
        fmt: str,
        arch: str,
        dynamic_req: bool,
    ) -> Tuple[List[str], List[str]]:
        tools: List[str] = ["rust_zero_copy_parser", "whole_binary_indexer"]
        techniques: List[str] = ["Zero-Copy Format Parsing", "Whole-Binary Function Indexing", "CFG Recovery"]

        # Objective-specific selections
        if obj_type in (InvestigationObjectiveType.CONFIG_EXTRACTION, InvestigationObjectiveType.SUSPICIOUS_BEHAVIOR):
            tools.extend(["yara_sigma_synthesizer", "ida_universal_loader"])
            techniques.extend(["Wildcard Opcode Pattern Synthesis", "Resource Decryption Loop Detection"])

        if obj_type in (InvestigationObjectiveType.INPUT_VALIDATION, InvestigationObjectiveType.DATA_FLOW_TRACING):
            tools.extend(["ghidra_pcode_ssa", "datalog_vsa_taint", "smt_solver_engine"])
            techniques.extend(["Heritage SSA Lifting", "Forward Datalog Taint Analysis", "SMT Path Feasibility"])

        if obj_type in (InvestigationObjectiveType.VULNERABILITY_RESEARCH, InvestigationObjectiveType.CRASH_ROOT_CAUSE):
            tools.extend(["ghidra_pcode_ssa", "underconstrained_visor", "datalog_vsa_taint", "firebase_cloud_sync"])
            techniques.extend(["CWE Memory Safety Scanner", "Under-Constrained Force-Execution", "Cloud Findings Sync"])

        if dynamic_req:
            tools.append("frida_dbi_tracer")
            techniques.append("Sandboxed Dynamic Instruction Hooking")

        # Deduplicate while preserving order
        seen_t: Set[str] = set()
        dedup_tools = [t for t in tools if not (t in seen_t or seen_t.add(t))]
        seen_tech: Set[str] = set()
        dedup_tech = [t for t in techniques if not (t in seen_tech or seen_tech.add(t))]

        return dedup_tools, dedup_tech


# Global singleton instance
intent_compiler = IntentCompiler()
