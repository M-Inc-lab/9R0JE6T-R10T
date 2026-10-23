"""
R3V3R53//F0RG3 — Semantic Function Naming & Struct/Type Recovery Engine (§05.2)
Reconstructs human-readable function names, parameter signatures, and struct layouts from
stripped decompiled pseudocode and API call patterns, with optional Colab T4 GPU LLM acceleration.
"""

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RecoveredFunctionSymbol:
    original_name: str
    suggested_name: str
    inferred_category: str
    inferred_signature: str
    confidence: str
    evidence_apis: List[str] = field(default_factory=list)
    recovered_struct_fields: List[Dict[str, Any]] = field(default_factory=list)


class SemanticRecoveryEngine:
    """Infers semantic function names, signatures, and structure field offsets from decompiled code."""

    BEHAVIORAL_SIGNATURE_RULES = [
        (
            "NetworkSocketListener",
            "int listen_incoming_socket(int port, sockaddr_in *addr)",
            {"socket", "bind", "listen", "accept", "WSAStartup"},
            "Network I/O & Server Listener",
        ),
        (
            "HttpRemoteClientRequest",
            "int send_http_request(const char *url, uint8_t *resp_buf, size_t len)",
            {"InternetOpenA", "InternetOpenW", "HttpSendRequestA", "HttpSendRequestW", "curl_easy_perform"},
            "HTTP / Web Client Telemetry",
        ),
        (
            "RegistryConfigPersistence",
            "int update_registry_configuration(HKEY root, const char *subkey, const char *val)",
            {"RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW"},
            "Windows Registry Configuration",
        ),
        (
            "DynamicModuleLoader",
            "void* resolve_dynamic_symbol(const char *module_name, const char *symbol_name)",
            {"dlopen", "dlsym", "LoadLibraryA", "LoadLibraryW", "GetProcAddress"},
            "Dynamic Library Resolver",
        ),
        (
            "PacketBufferParser",
            "int parse_input_buffer(const uint8_t *input_buf, size_t input_len)",
            {"recv", "fread", "ReadFile", "memcpy", "strncpy", "strcpy"},
            "Input Stream / Packet Parser",
        ),
    ]

    OFFSET_DEREF_RE = re.compile(
        r"\*\s*\(\s*(uint(?:8|16|32|64)_t|int|char\s*\*|void\s*\*|dword|qword)\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
        re.IGNORECASE,
    )

    def recover_from_pseudocode(self, fn_name: str, pseudocode: str) -> RecoveredFunctionSymbol:
        matched_cat = "General Computation / Helper"
        suggested = f"analyzed_{fn_name}"
        sig = f"int {suggested}(void *ctx)"
        matched_apis: List[str] = []
        best_score = 0

        for rule_name, rule_sig, api_set, category in self.BEHAVIORAL_SIGNATURE_RULES:
            hits = sorted(api for api in api_set if api in pseudocode)
            if len(hits) > best_score:
                best_score = len(hits)
                matched_apis = hits
                suggested = f"{rule_name}_{fn_name}"
                sig = rule_sig.replace(rule_sig.split("(")[0].split()[-1], suggested)
                matched_cat = category

        # Reconstruct structure field accesses of the form *(type *)(base + offset)
        struct_fields: List[Dict[str, Any]] = []
        seen_offsets = set()
        for m in self.OFFSET_DEREF_RE.finditer(pseudocode):
            ftype, base_var, raw_off = m.group(1), m.group(2), m.group(3)
            off_int = int(raw_off, 16) if raw_off.lower().startswith("0x") else int(raw_off)
            if (base_var, off_int) not in seen_offsets:
                seen_offsets.add((base_var, off_int))
                struct_fields.append({
                    "base_pointer": base_var,
                    "offset": hex(off_int),
                    "inferred_type": ftype.strip(),
                    "field_name": f"field_{off_int:02x}",
                })

        struct_fields.sort(key=lambda x: int(x["offset"], 16))
        confidence = "HIGH" if best_score >= 2 else ("MEDIUM" if (best_score == 1 or struct_fields) else "LOW")

        return RecoveredFunctionSymbol(
            original_name=fn_name,
            suggested_name=suggested,
            inferred_category=matched_cat,
            inferred_signature=sig,
            confidence=confidence,
            evidence_apis=matched_apis,
            recovered_struct_fields=struct_fields,
        )

    def propagate_struct_types_across_callgraph(
        self,
        callgraph: Dict[str, List[str]],
        recovered_funcs: Dict[str, RecoveredFunctionSymbol]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Bidirectional type propagation:
        If Callee accesses struct fields via argument pointer, propagate that struct layout
        backward to the Caller's variable passed at the call site.
        """
        inferred_types: Dict[str, List[Dict[str, Any]]] = {}

        for caller, callees in callgraph.items():
            for callee in callees:
                callee_meta = recovered_funcs.get(callee)
                if callee_meta and callee_meta.recovered_struct_fields:
                    # Callee expects a structured type! Propagate to caller
                    inferred_types.setdefault(caller, []).extend(callee_meta.recovered_struct_fields)

        # Deduplicate and sort
        for func_name in inferred_types:
            unique_fields = []
            seen = set()
            for fld in inferred_types[func_name]:
                k = (fld["offset"], fld["inferred_type"])
                if k not in seen:
                    seen.add(k)
                    unique_fields.append(fld)
            unique_fields.sort(key=lambda x: int(x["offset"], 16))
            inferred_types[func_name] = unique_fields

        return inferred_types
