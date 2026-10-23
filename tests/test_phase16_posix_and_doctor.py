"""
Tests for Phase 16: Linux/POSIX Isolated Runner, strace/gdb Telemetry Parser, and System Doctor.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from reverse_forge.posix_sandbox import POSIXSandboxEngine


class TestPhase16POSIXAndDoctor(unittest.TestCase):
    def test_strace_and_gdb_telemetry_parsing_and_correlation(self):
        sample_strace = """
1234  1700000001.100 execve("/bin/sh", ["sh", "-c", "id"], 0x7ffd) = 0
1234  1700000001.200 openat(AT_FDCWD, "/tmp/stage.bin", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3
1234  1700000001.300 connect(4, {sa_family=AF_INET, sin_port=htons(8443), sin_addr=inet_addr("198.51.100.23")}, 16) = 0
"""
        sample_gdb = """
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401234 in parse_header ()
"""
        b_engine = POSIXSandboxEngine.parse_strace_output(sample_strace, default_process="daemon.elf")
        POSIXSandboxEngine.parse_gdb_crash_output(sample_gdb, engine=b_engine, default_process="daemon.elf")

        self.assertEqual(len(b_engine.process_events), 1)
        self.assertEqual(b_engine.process_events[0].image_path, "/bin/sh")
        self.assertEqual(len(b_engine.file_events), 1)
        self.assertEqual(b_engine.file_events[0].operation, "WRITE")
        self.assertEqual(len(b_engine.network_events), 1)
        self.assertEqual(b_engine.network_events[0].destination_ip, "198.51.100.23")
        self.assertEqual(len(b_engine.crash_events), 1)
        self.assertEqual(b_engine.crash_events[0].exception_code, "SIGSEGV")
        self.assertEqual(b_engine.crash_events[0].fault_address, "0x0000000000401234")

        # Correlate with static strings
        matches = b_engine.correlate_with_static_analysis({"strings": {"ips": ["198.51.100.23"], "urls": []}})
        self.assertGreaterEqual(len(matches), 2)

    def test_posix_isolated_runner_generation_and_quoting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bin_path = os.path.join(tmpdir, "sample'file.elf")
            with open(bin_path, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 60)

            out_sh = os.path.join(tmpdir, "runner.sh")
            POSIXSandboxEngine(bin_path).generate_isolated_runner_script(out_sh, timeout_sec=15)
            self.assertTrue(os.path.exists(out_sh))
            with open(out_sh, "r", encoding="utf-8") as f:
                script = f.read()
            self.assertIn("--unshare-all", script)
            self.assertIn("strace -f", script)

    def test_cli_doctor_readiness_command(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        res = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "doctor"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0, f"CLI doctor failed: {res.stderr}")
        doc = json.loads(res.stdout)
        self.assertEqual(doc["phases_implemented"], 40)
        self.assertEqual(doc["internal_engines_status"], "ALL_READY")
        self.assertEqual(doc["internal_engines_count"], 43)


if __name__ == "__main__":
    unittest.main()
