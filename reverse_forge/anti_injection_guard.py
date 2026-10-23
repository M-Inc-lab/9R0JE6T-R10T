"""
R3V3R53//F0RG3 — AI Decompiler & Metadata Prompt-Injection Defense Guard (§26)
Sanitizes adversarial binary metadata, strings, and symbols to prevent Prompt Injection (PI),
Terminal ANSI Escape Hijacking, and Unicode Bidirectional Override (Trojan Source) attacks.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class AdversarialInjectionAttempt:
    source_field: str
    injection_type: str        # PROMPT_INJECTION, ANSI_ESCAPE, BIDI_OVERRIDE, SCRIPT_TAG
    raw_payload_snippet: str
    severity: str              # HIGH, CRITICAL
    defense_action: str


class AntiInjectionGuard:
    """Detects and neutralizes adversarial payloads injected into binary metadata and symbols."""

    # Prompt injection patterns commonly embedded by malware to poison automated AI triage
    PROMPT_INJECTION_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE),
        re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.IGNORECASE),
        re.compile(r"(act|operate)\s+as\s+an\s+unrestricted", re.IGNORECASE),
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
        re.compile(r"\[INST\].*\[/INST\]", re.IGNORECASE),
        re.compile(r"do\s+not\s+report\s+this\s+vulnerability", re.IGNORECASE),
        re.compile(r"mark\s+this\s+finding\s+as\s+benign", re.IGNORECASE),
    ]

    # ANSI & terminal escape code pattern
    ANSI_ESCAPE_PATTERN = re.compile(r"(?:\x1B|\x9B|\033)[\[\]()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]")

    # Unicode Bidirectional Override characters (CVE-2021-42574 Trojan Source)
    BIDI_CHARS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}

    # Dangerous script / markup tags in reports
    XSS_PATTERN = re.compile(r"<\s*script[^>]*>.*<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)

    def __init__(self):
        pass

    def check_text(self, text: str, source_field: str = "symbol") -> List[AdversarialInjectionAttempt]:
        """Scans input string for adversarial prompt injection or terminal hijack attempts."""
        findings: List[AdversarialInjectionAttempt] = []

        # 1. Prompt Injection Checks
        for pat in self.PROMPT_INJECTION_PATTERNS:
            m = pat.search(text)
            if m:
                findings.append(AdversarialInjectionAttempt(
                    source_field=source_field,
                    injection_type="PROMPT_INJECTION",
                    raw_payload_snippet=m.group(0)[:80],
                    severity="CRITICAL",
                    defense_action="Neutralized and tagged as adversarial injection decoy.",
                ))
                break

        # 2. ANSI Escape Sequence Check
        if self.ANSI_ESCAPE_PATTERN.search(text):
            findings.append(AdversarialInjectionAttempt(
                source_field=source_field,
                injection_type="ANSI_ESCAPE",
                raw_payload_snippet=text[:80],
                severity="HIGH",
                defense_action="Stripped terminal escape characters.",
            ))

        # 3. Unicode BiDi Override Check
        if any(c in text for c in self.BIDI_CHARS):
            findings.append(AdversarialInjectionAttempt(
                source_field=source_field,
                injection_type="BIDI_OVERRIDE",
                raw_payload_snippet=text[:80],
                severity="HIGH",
                defense_action="Stripped bidirectional control codes.",
            ))

        # 4. Markup / HTML Tag Check
        if self.XSS_PATTERN.search(text):
            findings.append(AdversarialInjectionAttempt(
                source_field=source_field,
                injection_type="SCRIPT_TAG",
                raw_payload_snippet=text[:80],
                severity="HIGH",
                defense_action="HTML-escaped potentially dangerous tags.",
            ))

        return findings

    def sanitize_text(self, text: str) -> str:
        """Sanitizes text by stripping escape sequences, BiDi markers, and dangerous control characters."""
        # Strip ANSI escape sequences
        s = self.ANSI_ESCAPE_PATTERN.sub("", text)

        # Strip BiDi characters
        for c in self.BIDI_CHARS:
            s = s.replace(c, "")

        # Strip non-printable ASCII control codes except newline and tab
        s = "".join(ch for ch in s if ord(ch) >= 32 or ch in "\n\r\t")

        # HTML entity escape < and > to prevent markdown injection
        s = s.replace("<script", "&lt;script").replace("</script>", "&lt;/script&gt;")

        return s

    def sanitize_metadata_dict(self, metadata: Dict[str, Any]) -> Tuple[Dict[str, Any], List[AdversarialInjectionAttempt]]:
        """Deeply traverses and sanitizes binary metadata, logging any adversarial payload attempts."""
        detected_attacks: List[AdversarialInjectionAttempt] = []

        def _traverse(obj: Any, path: str) -> Any:
            if isinstance(obj, str):
                attempts = self.check_text(obj, source_field=path)
                detected_attacks.extend(attempts)
                return self.sanitize_text(obj)
            elif isinstance(obj, list):
                return [_traverse(item, f"{path}[{i}]") for i, item in enumerate(obj)]
            elif isinstance(obj, dict):
                return {k: _traverse(v, f"{path}.{k}") for k, v in obj.items()}
            return obj

        sanitized = _traverse(metadata, "metadata")
        return sanitized, detected_attacks
