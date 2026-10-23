"""
R3V3R53//F0RG3 — Phase 37: C++ RTTI, VTable & Class Hierarchy Reconstructor
Recovers C++ object-oriented abstractions from stripped and symbol-bearing PE/ELF/Mach-O
binaries by parsing:
  1. Itanium C++ ABI RTTI symbols & mangled names (`_ZTV`, `_ZTI`, `_ZTS`, `_ZN...E`)
  2. Microsoft Visual C++ (MSVC) RTTI TypeDescriptors (`.?AVClassName@@`, `.?AUStructName@@`)
  3. Virtual Function Table (`vftable` / `vtable`) pointer arrays and C++ struct definitions
"""

from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class ReconstructedCppClass:
    class_name: str
    abi_type: str                 # "Itanium_ABI" or "MSVC_ABI"
    kind: str                     # "class" or "struct"
    namespace: str = ""
    base_classes: List[str] = field(default_factory=list)
    virtual_methods: List[str] = field(default_factory=list)
    vtable_symbol: Optional[str] = None
    c_struct_definition: str = ""


@dataclass
class CppRTTIReport:
    total_classes_recovered: int
    itanium_classes: int
    msvc_classes: int
    demangled_symbols: Dict[str, str]
    classes: List[ReconstructedCppClass]


class CppRTTIEngine:
    """
    Demangles Itanium C++ ABI and MSVC mangled symbols, extracts RTTI type descriptors
    from raw binary bytes, and reconstructs C++ class hierarchies and vtables.
    """

    # MSVC TypeDescriptor ASCII pattern inside .rdata / .data: `.?AVDerivedClass@Namespace@@`
    MSVC_RTTI_RE = re.compile(rb"\.\?A([VU])([A-Za-z0-9_@]+?)@@")
    # Itanium RTTI / VTable symbol pattern in symbol tables or strings
    ITANIUM_SYM_RE = re.compile(rb"(_Z(?:TV|TI|TS|N)[A-Za-z0-9_]+)")

    TYPE_CODE_MAP = {
        "v": "void",
        "b": "bool",
        "c": "char",
        "h": "unsigned char",
        "s": "short",
        "t": "unsigned short",
        "i": "int",
        "j": "unsigned int",
        "l": "long",
        "m": "unsigned long",
        "x": "long long",
        "y": "unsigned long long",
        "f": "float",
        "d": "double",
    }

    def demangle_itanium_symbol(self, sym: str) -> str:
        """
        Deterministic pure-Python demangler for Itanium C++ ABI symbols:
          - `_ZTV10PacketNode` -> `vtable for PacketNode`
          - `_ZTI10PacketNode` -> `typeinfo for PacketNode`
          - `_ZN3Net10PacketNode5parseEPci` -> `Net::PacketNode::parse(char*, int)`
        """
        s = sym.strip().lstrip("_")
        if s.startswith("Z"):
            s = "_" + s
        if not s.startswith("_Z"):
            return sym

        rest = s[2:]
        prefix = ""
        if rest.startswith("TV"):
            prefix = "vtable for "
            rest = rest[2:]
        elif rest.startswith("TI"):
            prefix = "typeinfo for "
            rest = rest[2:]
        elif rest.startswith("TS"):
            prefix = "typeinfo name for "
            rest = rest[2:]

        if rest.startswith("N"):
            rest = rest[1:]
            segments: List[str] = []
            while rest and not rest.startswith("E"):
                m_len = re.match(r"^(\d+)", rest)
                if not m_len:
                    break
                n_len = int(m_len.group(1))
                rest = rest[len(m_len.group(1)):]
                segments.append(rest[:n_len])
                rest = rest[n_len:]
            if rest.startswith("E"):
                rest = rest[1:]
            qualified = "::".join(segments)
            if prefix:
                return f"{prefix}{qualified}"
            params = self._parse_itanium_params(rest)
            return f"{qualified}({', '.join(params)})"

        m_single = re.match(r"^(\d+)(.+)$", rest)
        if m_single:
            n_len = int(m_single.group(1))
            tail = m_single.group(2)
            name = tail[:n_len]
            rem = tail[n_len:]
            if prefix:
                return f"{prefix}{name}"
            params = self._parse_itanium_params(rem)
            return f"{name}({', '.join(params)})" if params else name

        return sym

    def _parse_itanium_params(self, param_str: str) -> List[str]:
        if not param_str or param_str == "v":
            return ["void"]
        params: List[str] = []
        i = 0
        ptr_depth = 0
        is_const = False
        while i < len(param_str):
            ch = param_str[i]
            if ch == "P":
                ptr_depth += 1
                i += 1
            elif ch == "K":
                is_const = True
                i += 1
            elif ch in self.TYPE_CODE_MAP:
                base = self.TYPE_CODE_MAP[ch]
                if is_const:
                    base = f"const {base}"
                if ptr_depth:
                    base = f"{base} {'*' * ptr_depth}".strip()
                params.append(base)
                ptr_depth = 0
                is_const = False
                i += 1
            else:
                i += 1
        return params or ["void"]

    def demangle_msvc_rtti(self, raw_descriptor: str) -> Tuple[str, str, str]:
        """
        Demangle MSVC `.?AVClassName@SubNs@RootNs@@` into `(kind, namespace, class_name)`.
        """
        cleaned = raw_descriptor.strip()
        m = re.match(r"^\.\?A([VU])(.+?)@@$", cleaned)
        if not m:
            return ("class", "", cleaned)
        kind = "class" if m.group(1) == "V" else "struct"
        parts = [p for p in m.group(2).split("@") if p]
        if not parts:
            return (kind, "", cleaned)
        cls_name = parts[0]
        ns = "::".join(reversed(parts[1:])) if len(parts) > 1 else ""
        return (kind, ns, cls_name)

    def analyze_binary_rtti(
        self,
        binary_bytes: bytes,
        symbol_list: Optional[List[str]] = None,
        inheritance_hints: Optional[Dict[str, List[str]]] = None,
    ) -> CppRTTIReport:
        """
        Scan binary bytes and symbol tables for Itanium and MSVC C++ RTTI descriptors,
        demangle all discovered symbols, and emit C vtable struct reconstructions.
        """
        symbols: Set[str] = set(symbol_list or [])
        for m in self.ITANIUM_SYM_RE.finditer(binary_bytes):
            try:
                symbols.add(m.group(1).decode("ascii", errors="ignore"))
            except Exception:
                pass

        demangled_map: Dict[str, str] = {}
        classes_by_name: Dict[str, ReconstructedCppClass] = {}
        itanium_count = 0
        msvc_count = 0

        # 1. Process Itanium symbols
        for sym in sorted(symbols):
            if sym.startswith("_Z") or sym.startswith("Z"):
                dem = self.demangle_itanium_symbol(sym)
                demangled_map[sym] = dem
                if dem.startswith("vtable for ") or dem.startswith("typeinfo for "):
                    full_cls = dem.split(" for ", 1)[1].strip()
                    ns, _, cls_name = full_cls.rpartition("::")
                    if full_cls not in classes_by_name:
                        classes_by_name[full_cls] = ReconstructedCppClass(
                            class_name=cls_name or full_cls,
                            abi_type="Itanium_ABI",
                            kind="class",
                            namespace=ns,
                            vtable_symbol=sym if dem.startswith("vtable") else None,
                        )
                        itanium_count += 1
                    elif dem.startswith("vtable"):
                        classes_by_name[full_cls].vtable_symbol = sym

        # Attach Itanium member functions (`Ns::Class::method(...)`) to their class
        for sym, dem in demangled_map.items():
            if "(" in dem and "::" in dem.split("(", 1)[0]:
                fn_Part, sig_part = dem.split("(", 1)
                owner, _, method_name = fn_Part.rpartition("::")
                if owner not in classes_by_name:
                    ns, _, c_name = owner.rpartition("::")
                    classes_by_name[owner] = ReconstructedCppClass(
                        class_name=c_name or owner,
                        abi_type="Itanium_ABI",
                        kind="class",
                        namespace=ns,
                    )
                    itanium_count += 1
                classes_by_name[owner].virtual_methods.append(f"{method_name}({sig_part}")

        # 2. Process MSVC `.?AV...@@` RTTI descriptors from binary bytes
        for m_msvc in self.MSVC_RTTI_RE.finditer(binary_bytes):
            raw_desc = m_msvc.group(0).decode("ascii", errors="ignore")
            kind, ns, cls_name = self.demangle_msvc_rtti(raw_desc)
            full_key = f"{ns}::{cls_name}" if ns else cls_name
            demangled_map[raw_desc] = f"{kind} {full_key}"
            if full_key not in classes_by_name:
                classes_by_name[full_key] = ReconstructedCppClass(
                    class_name=cls_name,
                    abi_type="MSVC_ABI",
                    kind=kind,
                    namespace=ns,
                    vtable_symbol=f"??_7{cls_name}@@6B@",
                )
                msvc_count += 1

        # 3. Apply inheritance hints and synthesize C vtable structs
        hints = inheritance_hints or {}
        final_classes: List[ReconstructedCppClass] = []
        for key, c_obj in sorted(classes_by_name.items()):
            if c_obj.class_name in hints:
                c_obj.base_classes = list(hints[c_obj.class_name])
            elif key in hints:
                c_obj.base_classes = list(hints[key])

            vmethods = c_obj.virtual_methods or ["vfunc_0(void)", "vfunc_1(void)"]
            vtable_fields = "\n".join(
                f"    void (*slot_{idx}_{m.split('(', 1)[0]})(void *this_ptr);"
                for idx, m in enumerate(vmethods)
            )
            base_comment = f" /* : public {', '.join(c_obj.base_classes)} */" if c_obj.base_classes else ""
            c_obj.c_struct_definition = (
                f"typedef struct {c_obj.class_name}_vtable {{\n"
                f"{vtable_fields}\n"
                f"}} {c_obj.class_name}_vtable_t;\n\n"
                f"typedef struct {c_obj.class_name}{base_comment} {{\n"
                f"    const {c_obj.class_name}_vtable_t *vptr;\n"
                f"}} {c_obj.class_name}_t;"
            )
            final_classes.append(c_obj)

        return CppRTTIReport(
            total_classes_recovered=len(final_classes),
            itanium_classes=itanium_count,
            msvc_classes=msvc_count,
            demangled_symbols=demangled_map,
            classes=final_classes,
        )
