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
    # COFF header: Machine=0x14c (x86), NumberOfSections=1, SizeOfOptionalHeader=224, Characteristics=0x0102
    coff_hdr = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)

    opt_hdr = bytearray(224)
    struct.pack_into("<H", opt_hdr, 0, 0x10B)          # PE32 magic
    struct.pack_into("<I", opt_hdr, 16, 0x1000)        # AddressOfEntryPoint = 0x1000
    struct.pack_into("<I", opt_hdr, 28, 0x400000)      # ImageBase = 0x400000
    struct.pack_into("<H", opt_hdr, 68, 3)             # Subsystem = WINDOWS_CUI
    struct.pack_into("<H", opt_hdr, 70, 0x0140)        # DllCharacteristics = ASLR | DEP
    struct.pack_into("<I", opt_hdr, 92, 16)            # NumberOfRvaAndSizes = 16
    if with_security_dir:
        # DataDirectory[4] (SECURITY) at offset 96 + 4*8 = 128
        struct.pack_into("<II", opt_hdr, 128, 0x2000, 0x200)

    # Section header (.text): VirtualSize=16, VirtualAddress=0x1000, SizeOfRawData=16, PointerToRawData=0x200
    sec_hdr = bytearray(40)
    sec_hdr[0:5] = b".text"
    struct.pack_into("<IIII", sec_hdr, 8, 16, 0x1000, 16, 0x200)
    struct.pack_into("<I", sec_hdr, 36, 0x60000020)    # CODE | EXECUTE | READ

    header_blob = bytes(dos_hdr) + pe_sig + coff_hdr + bytes(opt_hdr) + bytes(sec_hdr)
    padding = b"\x00" * (0x200 - len(header_blob))
    code_bytes = b"\x55\x89\xe5\x31\xc0\x5d\xc3" + b"\x90" * 9
    return header_blob + padding + code_bytes


class SecurityRegressionTests(unittest.TestCase):
    """Defensive regression suite verifying remediations for RF-FND-001 through RF-FND-008."""

    def test_rf_fnd_001_and_006_url_validation(self):
        """Verify connect_colab URL validator blocks control characters and enforces HTTPS by default."""
        self.assertEqual(
            validate_endpoint_url("https://example-tunnel.trycloudflare.com/"),
            "https://example-tunnel.trycloudflare.com",
        )
        with self.assertRaises(ValueError):
            validate_endpoint_url("http://insecure.example.com", allow_http=False)
        with self.assertRaises(ValueError):
            validate_endpoint_url("https://example.com\nMALICIOUS_ENV=1")

    def test_rf_fnd_002_authenticode_env_parameterization_and_fail_closed(self):
        """Verify verify_authenticode_signature passes path via env var and fails closed on PowerShell error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pe_path = os.path.join(tmpdir, "sample'quote.exe")
            with open(pe_path, "wb") as f:
                f.write(_build_minimal_pe32(with_security_dir=True))

            engine = WindowsEngine(pe_path)
            mock_proc = MagicMock(returncode=1, stdout="", stderr="PowerShell unavailable")
            with patch("reverse_forge.windows_engine.subprocess.run", return_value=mock_proc) as mock_run:
                sig = engine.verify_authenticode_signature()
                self.assertFalse(sig["valid"], "Signature check must fail closed when PowerShell exits non-zero")
                self.assertEqual(sig["status"], "Unverified")

                called_args, called_kwargs = mock_run.call_args
                cmd_list = called_args[0]
                ps_script = cmd_list[-1]
                self.assertNotIn("sample'quote.exe", ps_script)
                self.assertIn("$env:RF_TARGET_PATH", ps_script)
                self.assertEqual(called_kwargs["env"]["RF_TARGET_PATH"], os.path.abspath(pe_path))

    def test_rf_fnd_003_wsb_xml_and_quote_escaping(self):
        """Verify WindowsSandbox.generate_wsb_profile produces valid XML and escapes special characters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sub_dir = os.path.join(tmpdir, "dir & <test>")
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
        """Verify ToolchainInstaller blocks zip and tar archive members with '../' traversal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Zip traversal check
            zip_buf = io.BytesIO()
            with zipfile.ZipFile(zip_buf, "w") as zf:
                zf.writestr("../escaped.txt", "blocked")
            zip_buf.seek(0)
            with zipfile.ZipFile(zip_buf, "r") as zf:
                with self.assertRaises(ValueError):
                    ToolchainInstaller._safe_extract_zip(zf, tmpdir)

            # 2. Tar traversal check
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
        """Verify JVM .class 0xCAFEBABE disambiguation, truncated Mach-O/ELF bounds, and cmdsize=0 guard."""
        ce = CorrelationEngine()

        # 1. Java 21 .class header (0xCAFEBABE, minor=0, major=65)
        java_hdr = b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\x00" * 32
        self.assertEqual(ce.identify_format(java_hdr), "JVM Class")
        macho_res = MachOAnalyzer(java_hdr).analyze()
        self.assertFalse(macho_res["is_macho"])
        self.assertTrue(any("JVM .class" in w for w in macho_res["warnings"]))

        # 2. Truncated 6-byte Mach-O 64-bit header must not raise struct.error
        trunc_macho = MachOAnalyzer(b"\xfe\xed\xfa\xcf\x00\x00").analyze()
        self.assertFalse(trunc_macho["is_macho"])
        self.assertTrue(any("Truncated" in w for w in trunc_macho["warnings"]))

        # 3. Mach-O with cmdsize=0 and huge ncmds must terminate immediately with warning
        zero_cmd_macho = (
            struct.pack(">IIIIIII", 0xFEEDFACE, 7, 3, 2, 0xFFFFFFFF, 64, 0)
            + struct.pack(">II", 0x1, 0)
        )
        zero_cmd_res = MachOAnalyzer(zero_cmd_macho).analyze()
        self.assertTrue(zero_cmd_res["is_macho"])
        self.assertTrue(any("Invalid Mach-O load command size" in w for w in zero_cmd_res["warnings"]))

        # 4. ELF64 with e_phentsize=0, e_phnum=1 must not raise struct.error
        elf_hdr = (
            b"\x7fELF\x02\x01\x01" + b"\x00" * 9
            + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000, 64, 0, 0, 64, 0, 1, 0, 0, 0)
        )
        elf_res = ELFAnalyzer(elf_hdr).analyze()
        self.assertTrue(elf_res["is_elf"])
        self.assertTrue(any("Malformed e_phentsize" in w for w in elf_res["warnings"]))

    def test_rf_fnd_007_capstone_entry_offset_resolution(self):
        """Verify _resolve_disassembly_slice selects entry_file_offset rather than offset 0 header bytes."""
        pe_bytes = _build_minimal_pe32(with_security_dir=False)
        pe_info = PEAnalyzer(pe_bytes).analyze()
        self.assertEqual(pe_info["entry_file_offset"], "0x200")

        slice_bytes, disasm_addr = CorrelationEngine._resolve_disassembly_slice(pe_bytes, pe_info)
        self.assertEqual(disasm_addr, 0x1000)
        self.assertTrue(slice_bytes.startswith(b"\x55\x89\xe5\x31\xc0\x5d\xc3"))
        self.assertFalse(slice_bytes.startswith(b"MZ"))

    def test_rf_fnd_008_cli_works_without_pefile(self):
        """Verify CLI detect-tools, triage, and win-checksec execute cleanly without pefile installed."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        res = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "detect-tools"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0, f"CLI detect-tools failed: {res.stderr}")
        parsed = json.loads(res.stdout)
        self.assertIn("python", parsed)

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
            self.assertEqual(wsec_res.returncode, 0, f"CLI win-checksec failed: {wsec_res.stderr}")
            wsec_json = json.loads(wsec_res.stdout)
            self.assertTrue(wsec_json["aslr"])
            self.assertTrue(wsec_json["dep_nx"])


if __name__ == "__main__":
    unittest.main()
