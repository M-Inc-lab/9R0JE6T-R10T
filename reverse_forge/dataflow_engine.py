"""
R3V3R53//F0RG3 — Data-Flow, Call-Graph & Memory Taint Engine (§05, §09–§14)
Constructs call-graphs, performs intraprocedural data-flow analysis,
and tracks source-to-sink reachability for dangerous APIs and memory operations.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class CallEdge:
    caller: str
    callee: str
    call_site_offset: str
    is_indirect: bool = False


@dataclass
class TaintPath:
    source_name: str
    sink_name: str
    intermediate_nodes: List[str]
    is_reachable: bool
    path_confidence: str  # CONFIRMED, PROBABLE, HYPOTHESIZED
    cwe: str
    description: str


class DataFlowGraph:
    """Directed Call-Graph and Source-to-Sink Taint Propagation Network."""

    # Recognized untrusted input sources
    TAINT_SOURCES = {
        "recv", "read", "fgets", "fread", "ReadFile", "WSARecv",
        "getenv", "InternetReadFile", "getc", "getchar", "scanf"
    }

    # High-impact security sinks
    TAINT_SINKS = {
        "strcpy": ("CWE-120", "Classic unbounded buffer copy"),
        "sprintf": ("CWE-134", "Unbounded formatted string printing"),
        "system": ("CWE-78", "Arbitrary command execution via shell interpreter"),
        "popen": ("CWE-78", "Process pipe creation with shell interpreter"),
        "WinExec": ("CWE-78", "Direct process execution sink"),
        "CreateProcessA": ("CWE-88", "Process instantiation sink"),
        "CreateProcessW": ("CWE-88", "Process instantiation sink"),
        "memcpy": ("CWE-119", "Memory block copy without boundary validation"),
        "free": ("CWE-416", "Memory deallocation sink (UAF / Double Free vector)"),
    }

    def __init__(self):
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.call_edges: List[CallEdge] = []
        self.functions: Set[str] = set()

    def add_edge(self, caller: str, callee: str, offset: str = "0x0", is_indirect: bool = False) -> None:
        self.functions.add(caller)
        self.functions.add(callee)
        self.adjacency[caller].add(callee)
        self.call_edges.append(CallEdge(caller, callee, offset, is_indirect))

    def build_from_xrefs(self, xref_dict: Dict[str, List[str]]) -> None:
        """
        Build call-graph from decompilation/disassembly xrefs.
        Format: {callee_name: [caller_1, caller_2, ...]}
        """
        for callee, callers in xref_dict.items():
            for caller in callers:
                self.add_edge(caller=caller, callee=callee)

    def find_all_paths(self, start: str, target: str, max_depth: int = 8) -> List[List[str]]:
        """Find directed paths between start node and target node via BFS."""
        if start not in self.adjacency and start != target:
            return []

        paths: List[List[str]] = []
        queue = deque([(start, [start])])

        while queue:
            curr, path = queue.popleft()
            if len(path) > max_depth:
                continue
            if curr == target:
                paths.append(path)
                continue

            for neighbor in self.adjacency.get(curr, set()):
                if neighbor not in path:  # Prevent infinite cycle
                    queue.append((neighbor, path + [neighbor]))

        return paths

    def analyze_source_to_sink_flows(self) -> List[TaintPath]:
        """Discover reachability flows from known input sources to critical sinks."""
        discovered_paths: List[TaintPath] = []

        active_sources = self.TAINT_SOURCES.intersection(self.functions)
        active_sinks = set(self.TAINT_SINKS.keys()).intersection(self.functions)

        # Check reachability through caller functions
        for caller in self.functions:
            called = self.adjacency.get(caller, set())
            sources_called = called.intersection(self.TAINT_SOURCES)
            sinks_called = called.intersection(set(self.TAINT_SINKS.keys()))

            # Direct co-occurrence within the same function scope
            for src in sources_called:
                for snk in sinks_called:
                    cwe, desc = self.TAINT_SINKS[snk]
                    discovered_paths.append(TaintPath(
                        source_name=src,
                        sink_name=snk,
                        intermediate_nodes=[caller],
                        is_reachable=True,
                        path_confidence="PROBABLE",
                        cwe=cwe,
                        description=f"Function `{caller}` ingests input from `{src}` and invokes sink `{snk}`: {desc}."
                    ))

        # Check multi-hop reachability
        for src in active_sources:
            for snk in active_sinks:
                paths = self.find_all_paths(src, snk)
                for p in paths:
                    cwe, desc = self.TAINT_SINKS[snk]
                    discovered_paths.append(TaintPath(
                        source_name=src,
                        sink_name=snk,
                        intermediate_nodes=p,
                        is_reachable=True,
                        path_confidence="CONFIRMED",
                        cwe=cwe,
                        description=f"Multi-hop data flow from `{src}` -> `{snk}` across {len(p)} nodes."
                    ))

        return discovered_paths
