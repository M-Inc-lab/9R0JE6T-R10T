"""
R3V3R53//F0RG3 — Behavioral Telemetry & Dynamic-to-Static Correlation Engine (§07, §08)
Captures, parses, and correlates runtime behavioral artifacts (processes, network, file, registry, crashes)
against static binary disassembly and vulnerability hypotheses.
"""

import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class ProcessEvent:
    timestamp: str
    pid: int
    parent_pid: int
    image_path: str
    command_line: str
    action: str  # SPAWNED, TERMINATED, INJECTED


@dataclass
class FileEvent:
    timestamp: str
    path: str
    operation: str  # CREATE, WRITE, READ, DELETE
    process_name: str


@dataclass
class RegistryEvent:
    timestamp: str
    key_path: str
    value_name: str
    operation: str  # SET_VALUE, CREATE_KEY, DELETE_KEY
    process_name: str


@dataclass
class NetworkEvent:
    timestamp: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str  # TCP, UDP, DNS, HTTP
    data_summary: str


@dataclass
class CrashEvent:
    timestamp: str
    process_name: str
    fault_address: str
    exception_code: str
    register_state: Dict[str, str] = field(default_factory=dict)
    stack_trace: List[str] = field(default_factory=list)


@dataclass
class CorrelationMatch:
    hypothesis_id: str
    runtime_event_type: str
    runtime_detail: str
    static_symbol_or_address: str
    status: str  # CONFIRMED, REFUTED, INCONCLUSIVE
    rationale: str


class BehavioralTelemetryEngine:
    """Parses dynamic execution logs and maps observed behaviors back to static code."""

    def __init__(self):
        self.process_events: List[ProcessEvent] = []
        self.file_events: List[FileEvent] = []
        self.registry_events: List[RegistryEvent] = []
        self.network_events: List[NetworkEvent] = []
        self.crash_events: List[CrashEvent] = []
        self.correlation_matches: List[CorrelationMatch] = []

    def record_process_event(self, event: ProcessEvent) -> None:
        self.process_events.append(event)

    def record_file_event(self, event: FileEvent) -> None:
        self.file_events.append(event)

    def record_registry_event(self, event: RegistryEvent) -> None:
        self.registry_events.append(event)

    def record_network_event(self, event: NetworkEvent) -> None:
        self.network_events.append(event)

    def record_crash_event(self, event: CrashEvent) -> None:
        self.crash_events.append(event)

    def ingest_json_trace(self, trace_json_path: str) -> Dict[str, int]:
        """Ingest serialized telemetry trace output produced inside sandbox runner."""
        if not os.path.exists(trace_json_path):
            raise FileNotFoundError(f"Telemetry log not found: {trace_json_path}")

        with open(trace_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for p in data.get("processes", []):
            self.record_process_event(ProcessEvent(**p))
        for f in data.get("files", []):
            self.record_file_event(FileEvent(**f))
        for r in data.get("registry", []):
            self.record_registry_event(RegistryEvent(**r))
        for n in data.get("network", []):
            self.record_network_event(NetworkEvent(**n))
        for c in data.get("crashes", []):
            self.record_crash_event(CrashEvent(**c))

        return {
            "processes": len(self.process_events),
            "files": len(self.file_events),
            "registry": len(self.registry_events),
            "network": len(self.network_events),
            "crashes": len(self.crash_events),
        }

    def correlate_with_static_analysis(
        self,
        static_analysis: Dict[str, Any],
        hypotheses: Optional[List[Dict[str, Any]]] = None,
    ) -> List[CorrelationMatch]:
        """
        Cross-correlate dynamic runtime observations with static symbols,
        imported APIs, strings, and vulnerability hypotheses.
        """
        matches: List[CorrelationMatch] = []

        # 1. Correlate Network Activity with Static Strings/Imports
        extracted_strings = static_analysis.get("strings", {})
        known_ips_urls = set(extracted_strings.get("ips", []) + extracted_strings.get("urls", []))
        for net in self.network_events:
            target_ip = net.destination_ip
            matched = any(target_ip in s for s in known_ips_urls)
            if matched:
                matches.append(CorrelationMatch(
                    hypothesis_id="HYP-NET-C2",
                    runtime_event_type="NETWORK_CONNECTION",
                    runtime_detail=f"Outbound {net.protocol} to {target_ip}:{net.destination_port}",
                    static_symbol_or_address=f"String reference `{target_ip}`",
                    status="CONFIRMED",
                    rationale="Static IOC confirmed via observed active runtime network telemetry."
                ))

        # 2. Correlate File/Persistence Operations with Suspicious Imports
        for reg in self.registry_events:
            if "Run" in reg.key_path or "Services" in reg.key_path:
                matches.append(CorrelationMatch(
                    hypothesis_id="HYP-PERSISTENCE-RUNKEY",
                    runtime_event_type="REGISTRY_PERSISTENCE",
                    runtime_detail=f"Registry modified: {reg.key_path}\\{reg.value_name}",
                    static_symbol_or_address="RegSetValue / RegCreateKey",
                    status="CONFIRMED",
                    rationale="Process actively attempted persistence through autostart run keys."
                ))

        # 3. Correlate Crashes with Buffer Overflow or Memory Flaw Hypotheses
        for crash in self.crash_events:
            addr = crash.fault_address
            matches.append(CorrelationMatch(
                hypothesis_id="HYP-MEM-FAULT",
                runtime_event_type="PROCESS_CRASH",
                runtime_detail=f"Exception {crash.exception_code} at address {addr}",
                static_symbol_or_address=addr,
                status="CONFIRMED",
                rationale=f"Observed memory access violation at runtime confirms vulnerability hypothesis."
            ))

        self.correlation_matches.extend(matches)
        return matches

    def generate_behavioral_summary(self) -> Dict[str, Any]:
        """Synthesize overall behavioral footprint."""
        return {
            "summary_utc": datetime.now(timezone.utc).isoformat(),
            "total_process_events": len(self.process_events),
            "total_file_events": len(self.file_events),
            "total_registry_events": len(self.registry_events),
            "total_network_events": len(self.network_events),
            "total_crash_events": len(self.crash_events),
            "correlation_matches": [asdict(m) for m in self.correlation_matches],
            "suspicious_indicators": {
                "persistence_attempted": any("Run" in r.key_path for r in self.registry_events),
                "c2_network_traffic": len(self.network_events) > 0,
                "process_spawned_child": len(self.process_events) > 1,
                "access_violation_crashes": any(c.exception_code in ("0xC0000005", "SIGSEGV") for c in self.crash_events),
            }
        }
