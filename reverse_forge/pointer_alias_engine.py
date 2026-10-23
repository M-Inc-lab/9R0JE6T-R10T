"""
R3V3R53//F0RG3 — Interprocedural Heap & Pointer Alias Engine (§05, §10)
Constructs points-to graphs for dynamic memory allocations and tracks pointer lifecycles
to identify Use-After-Free (UAF, CWE-416) and Double-Free (CWE-415) defects statically.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class MemoryState(Enum):
    UNALLOCATED = "UNALLOCATED"
    ALLOCATED = "ALLOCATED"
    INITIALIZED = "INITIALIZED"
    FREED = "FREED"
    DANGLING = "DANGLING"


@dataclass
class HeapObject:
    alloc_id: str
    alloc_site: str
    size_expr: str
    state: MemoryState = MemoryState.ALLOCATED
    free_site: Optional[str] = None
    aliases: Set[str] = field(default_factory=set)


@dataclass
class MemoryDefect:
    defect_type: str  # USE_AFTER_FREE, DOUBLE_FREE, UNINITIALIZED_READ
    cwe: str
    pointer_var: str
    alloc_site: str
    trigger_site: str
    description: str
    cvss_score: float = 8.8


class PointerAliasEngine:
    """Tracks pointer aliases and memory object states across operations."""

    ALLOC_FUNCTIONS = {"malloc", "calloc", "realloc", "HeapAlloc", "VirtualAlloc", "new", "operator new"}
    FREE_FUNCTIONS = {"free", "HeapFree", "VirtualFree", "delete", "operator delete"}

    def __init__(self):
        self.heap_objects: Dict[str, HeapObject] = {}
        self.points_to: Dict[str, Set[str]] = defaultdict(set)  # ptr_var -> set of alloc_ids
        self.defects: List[MemoryDefect] = []

    def record_allocation(self, ptr_var: str, alloc_site: str, size_expr: str = "unknown") -> str:
        """Register a new dynamic heap allocation."""
        alloc_id = f"heap_{alloc_site}_{ptr_var}"
        obj = HeapObject(alloc_id=alloc_id, alloc_site=alloc_site, size_expr=size_expr, state=MemoryState.ALLOCATED)
        obj.aliases.add(ptr_var)
        self.heap_objects[alloc_id] = obj
        self.points_to[ptr_var].add(alloc_id)
        return alloc_id

    def record_alias(self, dst_var: str, src_var: str) -> None:
        """Register pointer aliasing (dst_var = src_var)."""
        target_ids = self.points_to.get(src_var, set())
        for aid in target_ids:
            self.points_to[dst_var].add(aid)
            if aid in self.heap_objects:
                self.heap_objects[aid].aliases.add(dst_var)

    def record_free(self, ptr_var: str, free_site: str) -> None:
        """Record deallocation of memory object pointed to by ptr_var."""
        target_ids = self.points_to.get(ptr_var, set())
        if not target_ids:
            # Freeing unmapped pointer
            return

        for aid in target_ids:
            obj = self.heap_objects.get(aid)
            if obj:
                if obj.state == MemoryState.FREED:
                    # Double free!
                    self.defects.append(MemoryDefect(
                        defect_type="DOUBLE_FREE",
                        cwe="CWE-415",
                        pointer_var=ptr_var,
                        alloc_site=obj.alloc_site,
                        trigger_site=free_site,
                        description=f"Double-free detected for pointer `{ptr_var}` referencing object `{aid}` (previously freed at `{obj.free_site}`)."
                    ))
                else:
                    obj.state = MemoryState.FREED
                    obj.free_site = free_site

    def record_dereference(self, ptr_var: str, access_site: str, is_write: bool = False) -> None:
        """Check pointer state during read or write dereference (*ptr)."""
        target_ids = self.points_to.get(ptr_var, set())
        for aid in target_ids:
            obj = self.heap_objects.get(aid)
            if obj and obj.state == MemoryState.FREED:
                # Use-After-Free!
                self.defects.append(MemoryDefect(
                    defect_type="USE_AFTER_FREE",
                    cwe="CWE-416",
                    pointer_var=ptr_var,
                    alloc_site=obj.alloc_site,
                    trigger_site=access_site,
                    description=f"Use-After-Free: Pointer `{ptr_var}` dereferenced at `{access_site}` after object was freed at `{obj.free_site}`."
                ))

    def analyze_instruction_sequence(self, instructions: List[Tuple[str, str, str]]) -> List[MemoryDefect]:
        """
        Analyze tokenized linear code statements: (site_label, statement_type, args)
        Example: [('0x4010', 'CALL', 'malloc'), ('0x4018', 'ASSIGN', 'p2 = p1'), ('0x4020', 'CALL', 'free(p1)'), ...]
        """
        for site, op, arg in instructions:
            op_u = op.upper()
            if "MALLOC" in arg or "ALLOC" in arg:
                # Format: ptr = malloc(...)
                parts = arg.split("=", 1)
                ptr = parts[0].strip() if len(parts) == 2 else "ret_ptr"
                self.record_allocation(ptr, site)
            elif op_u == "ASSIGN" and "=" in arg:
                dst, src = [p.strip() for p in arg.split("=", 1)]
                self.record_alias(dst, src)
            elif "FREE" in arg:
                # Extract pointer inside free(ptr)
                import re
                m = re.search(r"free\s*\(\s*([a-zA-Z0-9_]+)\s*\)", arg, re.IGNORECASE)
                ptr = m.group(1) if m else "ptr"
                self.record_free(ptr, site)
            elif op_u in ("READ", "WRITE", "DEREF"):
                self.record_dereference(arg.strip(), site, is_write=(op_u == "WRITE"))

        return self.defects
