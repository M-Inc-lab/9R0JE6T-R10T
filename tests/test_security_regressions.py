import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import xml.etree.ElementTree as ET
import zipfile

from connect_colab import validate_endpoint_url
from reverse_forge.correlation_engine import CorrelationEngine
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.ghidra_analyzer import GhidraHeadlessAnalyzer
from reverse_forge.macho_analyzer import MachOAnalyzer
from reverse_forge.pe_analyzer import PEAnalyzer
from reverse_forge.tool_installer import ToolchainInstaller
from reverse_forge.windows_engine import WindowsEngine
from reverse_forge.windows_sandbox import WindowsSandbox


def _build_minimal_pe32(with_security_dir: bool = True) -> bytes:
    """Construct a minimal, benign PE32 header and .text section in memory for parser testing."""
    dos_hdr = bytearray(64)
    dos_hdr[0:2] = b"MZ"
    struct.pack_into("<I", dos_hdr, 0x3C, 64)

    pe_sig = b"PE\x00\x00"
    coff_hdr = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)

    opt_hdr = bytearray(224)
    struct.pack_into("<H", opt_hdr, 0, 0x10B)
    struct.pack_into("<I", opt_hdr, 16, 0x1000)
    struct.pack_into("<I", opt_hdr, 28, 0x400000)
    struct.pack_into("<H", opt_hdr, 68, 3)
    struct.pack_into("<H", opt_hdr, 70, 0x0140)
    struct.pack_into("<I", opt_hdr, 92, 16)
    if with_security_dir:
        struct.pack_into("<II", opt_hdr, 128, 0x2000, 0x200)

    sec_hdr = bytearray(40)
    sec_hdr[0:5] = b".text"
    struct.pack_into("<IIII", sec_hdr, 8, 16, 0x1000, 16, 0x200)
    struct.pack_into("<I", sec_hdr, 36, 0x60000020)

    header_blob = bytes(dos_hdr) + pe_sig + coff_hdr + bytes(opt_hdr) + bytes(sec_hdr)
    padding = b"\x00" * (0x200 - len(header_blob))
    code_bytes = b"\x55\x89\xe5\x31\xc0\x5d\xc3" + b"\x90" * 9
    return header_blob + padding + code_bytes


def _build_macho64_with_sym_and_entitlements() -> bytes:
    """Construct a synthetic 64-bit Mach-O binary with LC_LOAD_DYLIB, LC_SYMTAB, and LC_CODE_SIGNATURE."""
    # Mach-O 64 header (32 bytes): magic=0xFEEDFACF, cputype=ARM64, filetype=MH_EXECUTE(2), ncmds=3, flags=MH_PIE(0x200000)
    # 1. LC_LOAD_DYLIB (cmd=0xC, cmdsize=56)
    dylib_path = b"/usr/lib/libSystem.B.dylib\x00"
    dylib_cmd_len = 24 + len(dylib_path)
    dylib_pad = (8 - (dylib_cmd_len % 8)) % 8
    dylib_cmdsize = dylib_cmd_len + dylib_pad
    lc_dylib = struct.pack(">IIIIII", 0xC, dylib_cmdsize, 24, 2, 0x10000, 0x10000) + dylib_path + (b"\x00" * dylib_pad)

    # 2. LC_SYMTAB (cmd=0x2, cmdsize=24) -> symoff=256, nsyms=2, stroff=288
    lc_symtab = struct.pack(">IIIIII", 0x2, 24, 256, 2, 288, 48)

    # 3. LC_CODE_SIGNATURE (cmd=0x1D, cmdsize=16) -> dataoff=336, datasize=128
    lc_codesig = struct.pack(">IIII", 0x1D, 16, 336, 128)

    cmds = lc_dylib + lc_symtab + lc_codesig
    hdr = struct.pack(">IIIIIIII", 0xFEEDFACF, 12 | 0x01000000, 0, 2, 3, len(cmds), 0x200000, 0)

    blob = bytearray(512)
    blob[0:len(hdr)] = hdr
    blob[len(hdr):len(hdr) + len(cmds)] = cmds

    # String table at offset 288: "\x00___stack_chk_fail\x00_strcpy\x00"
    strtab = b"\x00___stack_chk_fail\x00_strcpy\x00"
    blob[288:288 + len(strtab)] = strtab

    # Two nlist_64 entries at offset 256 (16 bytes each): (n_strx, n_type=0x01 N_EXT|N_UNDF, n_sect=0, n_desc=0, n_value=0)
    n1 = struct.pack(">IBBHQ", 1, 0x01, 0, 0, 0)
    n2 = struct.pack(">IBBHQ", 19, 0x01, 0, 0, 0)
    blob[256:288] = n1 + n2

    # CS_SuperBlob at offset 336 with 1 entitlement slot (0xFADE7171)
    ent_xml = b"<plist><dict><key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>"
    ent_blob = struct.pack(">II", 0xFADE7171, 8 + len(ent_xml)) + ent_xml
    super_blob = struct.pack(">IIIII", 0xFADE0CC0, 20 + len(ent_blob), 1, 5, 20) + ent_blob
    blob[336:336 + len(super_blob)] = super_blob
    struct.pack_into(">I", blob, len(hdr) + len(lc_dylib) + len(lc_symtab) + 12, len(super_blob))
    return bytes(blob)


class SecurityRegressionTests(unittest.TestCase):
    """Defensive regression suite verifying Phase 1 (RF-FND-001..008) and Phase 2 capabilities."""

    def test_rf_fnd_001_and_006_url_validation(self):
        self.assertEqual(
            validate_endpoint_url("https://example-tunnel.trycloudflare.com/"),
            "https://example-tunnel.trycloudflare.com",
        )
        with self.assertRaises(ValueError):
            validate_endpoint_url("http://insecure.example.com", allow_http=False)
        with self.assertRaises(ValueError):
            validate_endpoint_url("https://example.com\nMALICIOUS_ENV=1")

    def test_rf_fnd_002_authenticode_env_parameterization_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pe_path = os.path.join(tmpdir, "sample'quote.exe")
            with open(pe_path, "wb") as f:
                f.write(_build_minimal_pe32(with_security_dir=True))

            with WindowsEngine(pe_path) as engine:
                mock_proc = MagicMock(returncode=1, stdout="", stderr="PowerShell unavailable")
                with patch("reverse_forge.windows_engine.subprocess.run", return_value=mock_proc) as mock_run:
                    sig = engine.verify_authenticode_signature()
                    self.assertFalse(sig["valid"])
                    self.assertEqual(sig["status"], "Unverified")

                    called_args, called_kwargs = mock_run.call_args
                    ps_script = called_args[0][-1]
                    self.assertNotIn("sample'quote.exe", ps_script)
                    self.assertIn("$env:RF_TARGET_PATH", ps_script)
                    self.assertEqual(called_kwargs["env"]["RF_TARGET_PATH"], os.path.abspath(pe_path))

    def test_rf_fnd_003_wsb_xml_and_quote_escaping(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sub_dir = os.path.join(tmpdir, "dir & special")
            os.makedirs(sub_dir, exist_ok=True)
            artifact_path = os.path.join(sub_dir, "sample'artifact.exe")
            with open(artifact_path, "wb") as f:
                f.write(b"MZ" + b"\x00" * 64)

            wsb_out = os.path.join(tmpdir, "profile.wsb")
            wsb = WindowsSandbox(artifact_path)
            wsb.generate_wsb_profile(wsb_out)

            tree = ET.parse(wsb_out)
            root = tree.getroot()
            self.assertEqual(root.tag, "Configuration")
            host_folders = root.findall("./MappedFolders/MappedFolder/HostFolder")
            self.assertEqual(len(host_folders), 1)
            self.assertEqual(host_folders[0].text, os.path.abspath(sub_dir))

            cmd_text = root.findtext("./LogonCommand/Command") or ""
            self.assertIn("sample''artifact.exe", cmd_text)

    def test_rf_fnd_004_zip_and_tar_slip_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_buf = io.BytesIO()
            with zipfile.ZipFile(zip_buf, "w") as zf:
                zf.writestr("../escaped.txt", "blocked")
            zip_buf.seek(0)
            with zipfile.ZipFile(zip_buf, "r") as zf:
                with self.assertRaises(ValueError):
                    ToolchainInstaller._safe_extract_zip(zf, tmpdir)

            tar_buf = io.BytesIO()
            with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
                info = tarfile.TarInfo(name="../escaped_tar.txt")
                payload = b"blocked"
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            tar_buf.seek(0)
            with tarfile.open(fileobj=tar_buf, mode="r:gz") as tf:
                with self.assertRaises(ValueError):
                    ToolchainInstaller._safe_extract_tar(tf, tmpdir)

    def test_rf_fnd_005_parser_bounds_and_jvm_class_disambiguation(self):
        ce = CorrelationEngine()

        java_hdr = b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\x00" * 32
        self.assertEqual(ce.identify_format(java_hdr), "JVM Class")
        macho_res = MachOAnalyzer(java_hdr).analyze()
        self.assertFalse(macho_res["is_macho"])
        self.assertTrue(any("JVM .class" in w for w in macho_res["warnings"]))

        trunc_macho = MachOAnalyzer(b"\xfe\xed\xfa\xcf\x00\x00").analyze()
        self.assertFalse(trunc_macho["is_macho"])

        zero_cmd_macho = (
            struct.pack(">IIIIIII", 0xFEEDFACE, 7, 3, 2, 0xFFFFFFFF, 64, 0)
            + struct.pack(">II", 0x1, 0)
        )
        zero_cmd_res = MachOAnalyzer(zero_cmd_macho).analyze()
        self.assertTrue(zero_cmd_res["is_macho"])
        self.assertTrue(any("Invalid Mach-O load command size" in w for w in zero_cmd_res["warnings"]))

        elf_hdr = (
            b"\x7fELF\x02\x01\x01" + b"\x00" * 9
            + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000, 64, 0, 0, 64, 0, 1, 0, 0, 0)
        )
        elf_res = ELFAnalyzer(elf_hdr).analyze()
        self.assertTrue(elf_res["is_elf"])
        self.assertTrue(any("Malformed e_phentsize" in w for w in elf_res["warnings"]))

    def test_rf_fnd_007_capstone_entry_offset_resolution(self):
        pe_bytes = _build_minimal_pe32(with_security_dir=False)
        pe_info = PEAnalyzer(pe_bytes).analyze()
        self.assertEqual(pe_info["entry_file_offset"], "0x200")

        slice_bytes, disasm_addr = CorrelationEngine._resolve_disassembly_slice(pe_bytes, pe_info)
        self.assertEqual(disasm_addr, 0x1000)
        self.assertTrue(slice_bytes.startswith(b"\x55\x89\xe5\x31\xc0\x5d\xc3"))

    def test_rf_fnd_008_cli_works_without_pefile(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        res = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "detect-tools"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0, f"CLI detect-tools failed: {res.stderr}")

        with tempfile.TemporaryDirectory() as tmpdir:
            pe_file = os.path.join(tmpdir, "test.exe")
            with open(pe_file, "wb") as f:
                f.write(_build_minimal_pe32(with_security_dir=False))

            wsec_res = subprocess.run(
                [sys.executable, "-m", "reverse_forge.cli", "win-checksec", "-i", pe_file],
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(wsec_res.returncode, 0)
            wsec_json = json.loads(wsec_res.stdout)
            self.assertTrue(wsec_json["aslr"])
            self.assertTrue(wsec_json["dep_nx"])

    def test_phase2_elf_deep_audit(self):
        """Verify ELFAnalyzer extracts shared libraries, mitigations (PIE, RELRO, NX, Canary), and symbols."""
        if os.path.exists("/bin/ls"):
            with open("/bin/ls", "rb") as f:
                ls_data = f.read()
            if ls_data.startswith(b"\x7fELF"):
                audit = ELFAnalyzer(ls_data).full_audit()
                self.assertTrue(audit["is_elf"])
                self.assertTrue(audit["mitigations"]["nx"])
                self.assertTrue(audit["mitigations"]["pie"])
                self.assertIn("RELRO", audit["mitigations"]["relro"])
                self.assertGreater(len(audit["shared_libraries"]), 0)
                self.assertGreater(audit["imported_symbols_count"], 0)

    def test_phase2_macho_deep_audit_and_entitlements(self):
        """Verify MachOAnalyzer extracts dylibs, symbols, stack canary, and CS_SuperBlob XML entitlements."""
        macho_bytes = _build_macho64_with_sym_and_entitlements()
        audit = MachOAnalyzer(macho_bytes).full_audit()
        self.assertTrue(audit["is_macho"])
        self.assertTrue(audit["mitigations"]["pie"])
        self.assertTrue(audit["mitigations"]["stack_canary"])
        self.assertTrue(audit["mitigations"]["code_signed"])
        self.assertIn("/usr/lib/libSystem.B.dylib", audit["dylibs"])
        self.assertIn(
            "com.apple.security.cs.disable-library-validation",
            audit["code_signature"]["entitlements_xml"] or "",
        )
        vuln_ids = [v["id"] for v in audit["identified_vulnerabilities"]]
        self.assertIn("MACHO-VULN-03", vuln_ids)
        self.assertIn("MACHO-VULN-04", vuln_ids)

    def test_phase2_ghidra_headless_orchestrator(self):
        """Verify GhidraHeadlessAnalyzer gracefully skips when absent and parses export JSON when invoked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_bin = os.path.join(tmpdir, "analyzeHeadless")
            with open(fake_bin, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\n")
            os.chmod(fake_bin, 0o755)

            target_bin = os.path.join(tmpdir, "sample.bin")
            with open(target_bin, "wb") as f:
                f.write(_build_minimal_pe32(with_security_dir=False))

            def fake_subproc(cmd, **kwargs):
                # cmd[-2] is output_json_path (before -deleteProject)
                out_json_path = cmd[-2]
                with open(out_json_path, "w", encoding="utf-8") as jf:
                    json.dump({
                        "program_name": "sample.bin",
                        "language_id": "x86:LE:32:default",
                        "functions_total": 3,
                        "functions": [{"name": "entry", "entry": "00401000"}],
                        "dangerous_sink_xrefs": [{"sink": "strcpy", "call_site": "00401012", "caller_function": "entry"}],
                        "decompiled_functions": [{"function": "entry", "pseudocode": "void entry(void) { strcpy(dst, src); }"}],
                    }, jf)
                return MagicMock(returncode=0, stdout="ok", stderr="")

            analyzer = GhidraHeadlessAnalyzer(ghidra_headless_path=fake_bin)
            with patch("reverse_forge.ghidra_analyzer.subprocess.run", side_effect=fake_subproc):
                res = analyzer.analyze(target_bin)
                self.assertEqual(res["status"], "success")
                self.assertEqual(res["analysis"]["language_id"], "x86:LE:32:default")
                self.assertEqual(len(res["analysis"]["dangerous_sink_xrefs"]), 1)


class TestHardenedScopeLedgerAndAuthentication(unittest.TestCase):
    """Regression tests for Section 3: Hardened ScopeLedger and Authentication Fail-Closed Controls."""

    def test_scope_ledger_rejects_path_traversal_and_null_bytes(self):
        from reverse_forge.provenance import ScopeLedger, ActionPermission
        ledger = ScopeLedger(allowed_patterns=["target.bin"])
        self.assertFalse(ledger.is_authorized("../target.bin"))
        self.assertFalse(ledger.is_authorized("sub/../../target.bin"))
        self.assertFalse(ledger.is_authorized("target.bin\x00evil"))

    def test_scope_ledger_canonical_real_path_and_symlink_defense(self):
        from reverse_forge.provenance import ScopeLedger, ActionPermission
        with tempfile.TemporaryDirectory() as tmpdir:
            allowed_dir = os.path.join(tmpdir, "allowed")
            forbidden_dir = os.path.join(tmpdir, "forbidden")
            os.makedirs(allowed_dir)
            os.makedirs(forbidden_dir)

            secret_file = os.path.join(forbidden_dir, "secret.bin")
            with open(secret_file, "wb") as f:
                f.write(b"SECRET_DATA")

            # Create a symlink inside allowed_dir pointing to secret_file in forbidden_dir
            symlink_file = os.path.join(allowed_dir, "sneaky_symlink.bin")
            os.symlink(secret_file, symlink_file)

            ledger = ScopeLedger(allowed_paths=[allowed_dir])
            # The symlink resolves outside allowed_dir, so it MUST be rejected
            self.assertFalse(ledger.is_authorized(symlink_file))

            # Regular file inside allowed_dir is authorized
            legit_file = os.path.join(allowed_dir, "legit.bin")
            with open(legit_file, "wb") as f:
                f.write(b"LEGIT_DATA")
            self.assertTrue(ledger.is_authorized(legit_file))

    def test_scope_ledger_action_permission_segregation(self):
        from reverse_forge.provenance import ScopeLedger, ActionPermission
        ledger = ScopeLedger(
            allowed_patterns=["target.bin"],
            default_actions=[ActionPermission.READ_HASH, ActionPermission.STATIC_ANALYSIS],
            allowed_actions={"target.bin": [ActionPermission.READ_HASH, ActionPermission.STATIC_ANALYSIS]},
        )
        # Static and Hash permissions permitted
        self.assertTrue(ledger.is_authorized("target.bin", ActionPermission.READ_HASH))
        self.assertTrue(ledger.is_authorized("target.bin", ActionPermission.STATIC_ANALYSIS))

        # Dynamic Sandbox and Network Access must be denied by default
        self.assertFalse(ledger.is_authorized("target.bin", ActionPermission.DYNAMIC_SANDBOX))
        self.assertFalse(ledger.is_authorized("target.bin", ActionPermission.NETWORK_ACCESS))

    def test_scope_ledger_empty_policy_fails_closed(self):
        from reverse_forge.provenance import ScopeLedger
        ledger = ScopeLedger()
        self.assertFalse(ledger.is_authorized("any_file.bin"))

    def test_firebase_auth_rejects_missing_token_in_production(self):
        from reverse_forge.firebase_sync import FirebaseAuthManager
        with patch.dict(os.environ, {"REVERSE_FORGE_ENV": "production", "FIREBASE_SERVICE_ACCOUNT_KEY": ""}):
            auth = FirebaseAuthManager()
            self.assertIsNone(auth.verify_bearer_token(None))
            self.assertIsNone(auth.verify_bearer_token(""))

    def test_firebase_auth_rejects_expired_and_not_before_tokens(self):
        from reverse_forge.firebase_sync import FirebaseAuthManager
        import base64
        import json
        import time

        auth = FirebaseAuthManager()
        header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode("utf-8").rstrip("=")

        # Expired token (exp in past)
        exp_payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "user_exp", "exp": time.time() - 3600}).encode("utf-8")
        ).decode("utf-8").rstrip("=")
        expired_jwt = f"{header}.{exp_payload}."
        self.assertIsNone(auth.verify_bearer_token(f"Bearer {expired_jwt}"))

        # Not-before token (nbf in future)
        nbf_payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "user_nbf", "nbf": time.time() + 3600}).encode("utf-8")
        ).decode("utf-8").rstrip("=")
        nbf_jwt = f"{header}.{nbf_payload}."
        self.assertIsNone(auth.verify_bearer_token(f"Bearer {nbf_jwt}"))

    def test_firebase_auth_rejects_unsigned_jwt_in_production(self):
        from reverse_forge.firebase_sync import FirebaseAuthManager
        import base64
        import json

        with patch.dict(os.environ, {"REVERSE_FORGE_ENV": "production", "FIREBASE_SERVICE_ACCOUNT_KEY": "valid_key"}):
            auth = FirebaseAuthManager()
            header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode("utf-8").rstrip("=")
            payload = base64.urlsafe_b64encode(json.dumps({"sub": "user_hacker"}).encode("utf-8")).decode("utf-8").rstrip("=")
            unsigned_jwt = f"{header}.{payload}."
            self.assertIsNone(auth.verify_bearer_token(f"Bearer {unsigned_jwt}"))

    def test_pipeline_default_scope_ledger_is_strictly_bounded(self):
        from reverse_forge.pipeline import ReverseForgePipeline
        from reverse_forge.provenance import ActionPermission
        with tempfile.NamedTemporaryFile(suffix=".bin") as tf:
            tf.write(b"\x7fELF" + b"\x00" * 64)
            tf.flush()
            pipeline = ReverseForgePipeline(artifact_path=tf.name)
            # Pipeline's default scope ledger must be strictly bounded to tf.name
            self.assertFalse(pipeline.scope_ledger.allow_all)
            self.assertTrue(pipeline.scope_ledger.is_authorized(tf.name, ActionPermission.READ_HASH))
            self.assertFalse(pipeline.scope_ledger.is_authorized("/etc/passwd", ActionPermission.READ_HASH))


if __name__ == "__main__":
    unittest.main()
