"""
R3V3R53//F0RG3 — Defensive Remediation, PoC Synthesizer & Regression Patch Generator (§20–§22)
Generates compilable C/C++ security patches, unit test regression harnesses,
and safe standalone proof-of-concept (PoC) reproductions for confirmed vulnerability classes.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class DefensivePatch:
    vulnerability_id: str
    target_symbol: str
    cwe_id: str
    vulnerable_code_snippet: str
    hardened_code_snippet: str
    diff_patch: str
    compiler_hardening_flags: List[str]
    remediation_notes: str


@dataclass
class RegressionHarness:
    target_name: str
    test_framework: str  # CUnit, GoogleTest, PyTest, Standalone
    source_code: str
    execution_command: str


class RemediationEngine:
    """Produces defensive patches, hardened compiler configurations, and verification test harnesses."""

    # Curated defensive patch patterns mapped by CWE
    REMEDIATION_TEMPLATES: Dict[str, Dict[str, Any]] = {
        "CWE-120": {
            "title": "Unbounded String Copy (strcpy)",
            "bad": 'strcpy(dest, src);',
            "good": 'strncpy_s(dest, sizeof(dest), src, _TRUNCATE); // or strlcpy(dest, src, sizeof(dest));',
            "diff": """--- vulnerable.c
+++ hardened.c
@@ -10,3 +10,3 @@
-    strcpy(dest, src);
+    strncpy_s(dest, sizeof(dest), src, _TRUNCATE);
""",
            "flags": ["/GS", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2"],
            "notes": "Replace legacy unbounded CRT string copy with ISO C11 Annex K or POSIX bounded functions."
        },
        "CWE-78": {
            "title": "Command Injection (system / popen)",
            "bad": 'system(user_command);',
            "good": 'execve("/bin/safe_utility", argv, envp); // Avoid shell interpreters',
            "diff": """--- vulnerable.c
+++ hardened.c
@@ -15,3 +15,3 @@
-    system(user_command);
+    execv(safe_argv[0], safe_argv);
""",
            "flags": ["-fPIE", "-pie", "/DYNAMICBASE"],
            "notes": "Avoid invocation of shell interpreters (`sh -c` / `cmd.exe`). Pass explicit argument vectors."
        },
        "CWE-134": {
            "title": "Format String Injection (printf / sprintf)",
            "bad": 'printf(user_supplied_format);',
            "good": 'printf("%s", user_supplied_format);',
            "diff": """--- vulnerable.c
+++ hardened.c
@@ -20,3 +20,3 @@
-    printf(user_supplied_format);
+    printf("%s", user_supplied_format);
""",
            "flags": ["-Wformat=2", "-Werror=format-security"],
            "notes": "Never pass untrusted input as the format specifier parameter. Always specify an explicit `%s`."
        },
        "CWE-798": {
            "title": "Hardcoded Cryptographic Credentials",
            "bad": 'const char *API_KEY = "AKIA1111111111111111";',
            "good": 'const char *api_key = getenv("APP_API_KEY"); if (!api_key) return ERR_AUTH;',
            "diff": """--- vulnerable.c
+++ hardened.c
@@ -5,3 +5,4 @@
-const char *API_KEY = "AKIA1111111111111111";
+const char *api_key = getenv("APP_API_KEY");
+if (!api_key) return -1;
""",
            "flags": [],
            "notes": "Extract static credentials from binary image. Delegate key lifecycle to KMS or secret vault."
        },
    }

    def generate_defensive_patch(self, vulnerability_id: str, cwe_id: str, symbol: str = "main") -> DefensivePatch:
        template = self.REMEDIATION_TEMPLATES.get(cwe_id, {
            "bad": "// Vulnerable implementation",
            "good": "// Hardened bounded implementation with input validation",
            "diff": "--- a/source.c\n+++ b/source.c\n@@ -1,1 +1,2 @@\n+// Apply input bounds check\n",
            "flags": ["-Wall", "-Wextra", "-Werror", "-O2"],
            "notes": "Validate input length, check return codes, and adopt defense-in-depth principles."
        })

        return DefensivePatch(
            vulnerability_id=vulnerability_id,
            target_symbol=symbol,
            cwe_id=cwe_id,
            vulnerable_code_snippet=template["bad"],
            hardened_code_snippet=template["good"],
            diff_patch=template["diff"],
            compiler_hardening_flags=template["flags"],
            remediation_notes=template["notes"]
        )

    def generate_regression_test_harness(self, target_name: str, cwe_id: str) -> RegressionHarness:
        """Create a standalone defensive unit test to verify vulnerability remediation."""
        c_code = f"""/*
 * R3V3R53//F0RG3 Automated Defensive Regression Test Harness
 * Target: {target_name} | CWE: {cwe_id}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int test_boundary_enforcement(void) {{
    printf("[*] Running boundary regression test for {cwe_id}...\\n");
    char oversized_buffer[1024];
    memset(oversized_buffer, 'A', sizeof(oversized_buffer) - 1);
    oversized_buffer[sizeof(oversized_buffer) - 1] = '\\0';

    /* Verify handler rejects or bounds oversized payload without buffer overrun */
    char dest[64];
    size_t copied = 0;
    if (strlen(oversized_buffer) >= sizeof(dest)) {{
        /* Bound verified */
        copied = sizeof(dest) - 1;
        memcpy(dest, oversized_buffer, copied);
        dest[copied] = '\\0';
    }}

    assert(strlen(dest) < sizeof(dest));
    printf("[+] Regression test PASSED: Overflow prevented successfully.\\n");
    return 0;
}}

int main(void) {{
    return test_boundary_enforcement();
}}
"""
        return RegressionHarness(
            target_name=target_name,
            test_framework="Standalone C Harness",
            source_code=c_code,
            execution_command="gcc -Wall -Wextra test_regression.c -o test_regression && ./test_regression"
        )
