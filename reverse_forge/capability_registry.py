"""
R3V3R53//F0RG3 — Part I: Open-Source Capability Registry & Tool Discovery Engine
(`capability_registry.py`)

Maintains a machine-readable, provenance-aware registry of all available analysis
engines, native Rust components, and external open-source tools across all 14 reverse
engineering categories.
"""

from __future__ import annotations

import enum
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("reverse_forge.capability_registry")


class ToolCategory(enum.Enum):
    DISASSEMBLY = "DISASSEMBLY"
    DECOMPILATION = "DECOMPILATION"
    BINARY_PARSING = "BINARY_PARSING"
    DEBUG_SYMBOLS = "DEBUG_SYMBOLS"
    CFG_CALLGRAPH = "CFG_CALLGRAPH"
    DATAFLOW_TAINT = "DATAFLOW_TAINT"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    DYNAMIC_TRACING = "DYNAMIC_TRACING"
    EMULATION_SANDBOX = "EMULATION_SANDBOX"
    MALWARE_BEHAVIOR = "MALWARE_BEHAVIOR"
    SYMBOLIC_EXECUTION = "SYMBOLIC_EXECUTION"
    FUZZING_TRIAGE = "FUZZING_TRIAGE"
    MEMORY_ANALYSIS = "MEMORY_ANALYSIS"
    RULE_SYNTHESIS = "RULE_SYNTHESIS"


class IntegrationStrategy(enum.Enum):
    RUST_NATIVE = "RUST_NATIVE"              # Compiled directly into zero-copy Rust core
    RUST_BINDING = "RUST_BINDING"            # C-FFI / native shared library bridge
    INTERNAL_ENGINE = "INTERNAL_ENGINE"      # Native Python analysis engine in reverse_forge
    SUBPROCESS_ADAPTER = "SUBPROCESS_ADAPTER"# Isolated, sandboxed external CLI tool


class LicenseType(enum.Enum):
    APACHE_2 = "Apache-2.0"
    MIT = "MIT"
    BSD_3 = "BSD-3-Clause"
    GPL_3 = "GPL-3.0"
    LGPL_2_1 = "LGPL-2.1"


@dataclass
class ToolCapability:
    """Rigorous metadata record for an analysis tool or subsystem."""
    tool_id: str
    name: str
    category: ToolCategory
    version: str
    repository_url: str
    pinned_commit: str
    license: LicenseType
    strategy: IntegrationStrategy
    supported_formats: List[str]            # e.g. ["PE", "ELF", "Mach-O", "WASM", "*"]
    supported_architectures: List[str]      # e.g. ["x86_64", "ARM64", "MIPS", "*"]
    is_sandboxed: bool
    requires_hil: bool                      # Requires Human-In-The-Loop approval before execution
    performance_rating: str                 # "HIGH" (<10ms), "MEDIUM" (<500ms), "LOW" (>1s)
    description: str
    security_review_status: str             # "VERIFIED_SECURE", "SANDBOX_REQUIRED", "SAFE_IN_PROCESS"
    input_contract: str = "binary_bytes_or_filepath"
    output_contract: str = "structured_json_dossier"
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def matches_target(self, format_name: str, arch: str) -> bool:
        """Check if capability applies to given binary format and architecture."""
        fmt_ok = ("*" in self.supported_formats) or (format_name.upper() in [f.upper() for f in self.supported_formats])
        arch_ok = ("*" in self.supported_architectures) or (arch.upper() in [a.upper() for a in self.supported_architectures])
        return fmt_ok and arch_ok

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["strategy"] = self.strategy.value
        d["license"] = self.license.value
        return d


class CapabilityRegistry:
    """
    Centralized, provenance-aware capability registry and dynamic tool selector
    for the intent-driven reverse engineering platform.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, ToolCapability] = {}
        self._seed_standard_capabilities()

    def register_tool(self, cap: ToolCapability) -> None:
        self._tools[cap.tool_id] = cap
        logger.debug(f"Registered tool capability: {cap.tool_id} ({cap.name})")

    def get_tool(self, tool_id: str) -> Optional[ToolCapability]:
        return self._tools.get(tool_id)

    def find_tools(
        self,
        category: Optional[ToolCategory] = None,
        format_name: Optional[str] = None,
        architecture: Optional[str] = None,
        require_sandboxed_only: bool = False,
    ) -> List[ToolCapability]:
        """Query capabilities matching investigative criteria."""
        results: List[ToolCapability] = []
        for t in self._tools.values():
            if category and t.category != category:
                continue
            if format_name or architecture:
                if not t.matches_target(format_name or "*", architecture or "*"):
                    continue
            if require_sandboxed_only and not t.is_sandboxed:
                continue
            results.append(t)
        return results

    def list_all(self) -> List[ToolCapability]:
        return list(self._tools.values())

    def get_all_capabilities(self) -> List[ToolCapability]:
        return list(self._tools.values())

    def get_by_category(self, category: ToolCategory) -> List[ToolCapability]:
        return [t for t in self._tools.values() if t.category == category]

    def find_matching_tools(self, format_name: str, architecture: str) -> List[ToolCapability]:
        return self.find_tools(format_name=format_name, architecture=architecture)

    def export_catalog(self) -> Dict[str, Any]:
        return {
            "version": "33.0.0-rust-singularity",
            "total_capabilities": len(self._tools),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tools": [t.to_dict() for t in self._tools.values()],
        }

    def _seed_standard_capabilities(self) -> None:
        """Seed the registry with all built-in Rust, Ghidra, and Python capabilities."""
        seeds = [
            ToolCapability(
                tool_id="rust_zero_copy_parser",
                name="Native Rust Zero-Copy Format Parser",
                category=ToolCategory.BINARY_PARSING,
                version="32.0.0",
                repository_url="https://github.com/M-Inc-lab/9R0JE6T-R10T/tree/main/rust_core",
                pinned_commit="bb22b92",
                license=LicenseType.GPL_3,
                strategy=IntegrationStrategy.RUST_NATIVE,
                supported_formats=["PE", "ELF", "Mach-O", "WASM", "DEX"],
                supported_architectures=["*"],
                is_sandboxed=True,
                requires_hil=False,
                performance_rating="HIGH",
                description="Zero-copy SIMD header parser and 256-bin Shannon entropy calculator in <1.5MB RSS.",
                security_review_status="VERIFIED_SECURE",
            ),
            ToolCapability(
                tool_id="ghidra_pcode_ssa",
                name="Ghidra SLEIGH P-Code & SSA Decompiler",
                category=ToolCategory.DECOMPILATION,
                version="11.1.2",
                repository_url="https://github.com/NationalSecurityAgency/ghidra",
                pinned_commit="ghidra-11.1.2-rel",
                license=LicenseType.APACHE_2,
                strategy=IntegrationStrategy.RUST_NATIVE,
                supported_formats=["PE", "ELF", "Mach-O", "*"],
                supported_architectures=["x86", "x86_64", "ARM", "ARM64", "MIPS"],
                is_sandboxed=True,
                requires_hil=False,
                performance_rating="HIGH",
                description="Direct Rust port of Ghidra CPUI P-Code lifter, Heritage SSA, and structured C emission.",
                security_review_status="VERIFIED_SECURE",
            ),
            ToolCapability(
                tool_id="whole_binary_indexer",
                name="Whole-Binary Function Indexer & Sugiyama CFG",
                category=ToolCategory.CFG_CALLGRAPH,
                version="30.0.0",
                repository_url="https://github.com/M-Inc-lab/9R0JE6T-R10T",
                pinned_commit="bb22b92",
                license=LicenseType.GPL_3,
                strategy=IntegrationStrategy.INTERNAL_ENGINE,
                supported_formats=["*"],
                supported_architectures=["*"],
                is_sandboxed=True,
                requires_hil=False,
                performance_rating="MEDIUM",
                description="1-to-1 function indexer recovering basic blocks, true/false edges, and Sugiyama DAG layouts.",
                security_review_status="VERIFIED_SECURE",
            ),
            ToolCapability(
                tool_id="underconstrained_visor",
                name="Under-Constrained Force-Execution Micro-Visor",
                category=ToolCategory.EMULATION_SANDBOX,
                version="26.0.0",
                repository_url="https://github.com/M-Inc-lab/9R0JE6T-R10T/blob/main/rust_core/src/visor.rs",
                pinned_commit="bb22b92",
                license=LicenseType.GPL_3,
                strategy=IntegrationStrategy.RUST_NATIVE,
                supported_formats=["*"],
                supported_architectures=["x86_64"],
                is_sandboxed=True,
                requires_hil=False,
                performance_rating="HIGH",
                description="Fault-tolerant register/memory micro-visor that force-executes opcodes without environment setup.",
                security_review_status="VERIFIED_SECURE",
            ),
            ToolCapability(
                tool_id="datalog_vsa_taint",
                name="Datalog Value-Set Analysis & Forward Taint Engine",
                category=ToolCategory.DATAFLOW_TAINT,
                version="24.0.0",
                repository_url="https://github.com/M-Inc-lab/9R0JE6T-R10T",
                pinned_commit="bb22b92",
                license=LicenseType.GPL_3,
                strategy=IntegrationStrategy.INTERNAL_ENGINE,
                supported_formats=["*"],
                supported_architectures=["*"],
                is_sandboxed=True,
                requires_hil=False,
                performance_rating="MEDIUM",
                description="Fine-grained interprocedural taint propagation tracing untrusted sources to dangerous memory sinks.",
                security_review_status="VERIFIED_SECURE",
            ),
            ToolCapability(
                tool_id="smt_solver_engine",
                name="angr Claripy SMT Bit-Vector Constraint Solver",
                category=ToolCategory.SYMBOLIC_EXECUTION,
                version="9.2.102",
                repository_url="https://github.com/angr/claripy",
                pinned_commit="claripy-v9.2",
                license=LicenseType.BSD_3,
                strategy=IntegrationStrategy.INTERNAL_ENGINE,
                supported_formats=["*"],
                supported_architectures=["x86", "x86_64", "ARM64"],
                is_sandboxed=True,
                requires_hil=False,
                performance_rating="MEDIUM",
                description="Evaluates branch condition reachability, integer overflows (CWE-190), and symbolic inputs.",
                security_review_status="VERIFIED_SECURE",
            ),
            ToolCapability(
                tool_id="frida_dbi_tracer",
                name="Frida Dynamic Binary Instrumentation Coordinator",
                category=ToolCategory.DYNAMIC_TRACING,
                version="16.2.1",
                repository_url="https://github.com/frida/frida",
                pinned_commit="frida-16.2",
                license=LicenseType.LGPL_2_1,
                strategy=IntegrationStrategy.SUBPROCESS_ADAPTER,
                supported_formats=["PE", "ELF", "Mach-O"],
                supported_architectures=["x86_64", "ARM64"],
                is_sandboxed=False,
                requires_hil=True, # STRICT HUMAN-IN-THE-LOOP APPROVAL REQUIRED
                performance_rating="LOW",
                description="Live stalker and instruction-level hooking engine. Strictly requires operator approval.",
                security_review_status="SANDBOX_REQUIRED",
            ),
            ToolCapability(
                tool_id="yara_sigma_synthesizer",
                name="YARA & SIGMA Rule Synthesis with Quality Gate",
                category=ToolCategory.RULE_SYNTHESIS,
                version="32.0.0",
                repository_url="https://github.com/M-Inc-lab/9R0JE6T-R10T",
                pinned_commit="bb22b92",
                license=LicenseType.APACHE_2,
                strategy=IntegrationStrategy.INTERNAL_ENGINE,
                supported_formats=["*"],
                supported_architectures=["*"],
                is_sandboxed=True,
                requires_hil=False,
                performance_rating="HIGH",
                description="Generates syntactically validated YARA opcode signatures, SIGMA YAML, and STIX 2.1 bundles.",
                security_review_status="VERIFIED_SECURE",
            ),
            ToolCapability(
                tool_id="ida_universal_loader",
                name="Universal IDA Pro Loader (36+ Specialized Formats)",
                category=ToolCategory.BINARY_PARSING,
                version="30.0.0",
                repository_url="https://github.com/M-Inc-lab/9R0JE6T-R10T",
                pinned_commit="bb22b92",
                license=LicenseType.APACHE_2,
                strategy=IntegrationStrategy.INTERNAL_ENGINE,
                supported_formats=[
                    "DOS_MZ", "WIN16_NE", "OS2_LE", "ELF", "PE", "MACH_O", "COFF", "AOUT",
                    "INTEL_HEX", "MOTOROLA_SREC", "AMIGA_HUNK", "ATARI_TOS", "UBOOT_UIMAGE",
                    "FIRMWARE_DTB", "UEFI_TE", "XBOX_XEX", "SWITCH_NSO", "MINIDUMP_MDMP",
                    "MS_PDB", "WASM", "DEX", "CLASS_JVM", "NET_CLR"
                ],
                supported_architectures=["*"],
                is_sandboxed=True,
                requires_hil=False,
                performance_rating="HIGH",
                description="Universal binary loader supporting 36+ historical, modern, console, and firmware file formats.",
                security_review_status="VERIFIED_SECURE",
            ),
            ToolCapability(
                tool_id="firebase_cloud_sync",
                name="Firebase Firestore & Cloud Storage Synchronizer",
                category=ToolCategory.STATIC_ANALYSIS,
                version="32.0.0",
                repository_url="https://github.com/M-Inc-lab/9R0JE6T-R10T",
                pinned_commit="bb22b92",
                license=LicenseType.APACHE_2,
                strategy=IntegrationStrategy.INTERNAL_ENGINE,
                supported_formats=["*"],
                supported_architectures=["*"],
                is_sandboxed=True,
                requires_hil=False,
                performance_rating="HIGH",
                description="Enterprise Cloud Firestore findings persistence and Cloud Storage artifact archiving with RBAC.",
                security_review_status="VERIFIED_SECURE",
            ),
        ]
        for cap in seeds:
            self.register_tool(cap)


# Global singleton instance
capability_registry = CapabilityRegistry()
