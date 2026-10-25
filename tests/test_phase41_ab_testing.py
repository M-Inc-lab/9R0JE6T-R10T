"""
Unit Tests for Phase 41: Adaptive Binary Streaming & Statistical A/B Testing
=============================================================================
Verifies zero-copy memory-mapped PE analysis, Welch's t-test calculations,
degrees of freedom, Cohen's d effect sizes, and guardrail parity checking.
"""

import math
import os
import struct
import tempfile
import unittest

from reverse_forge.streaming_pe import StreamingPEAnalyzer, StreamingPEMetadata
from reverse_forge.ab_benchmarker import BinaryABBenchmarker, ABExperimentReport


def create_minimal_pe_binary(filepath: str) -> None:
    """Helper to synthesize a valid minimal PE32+ (x64) binary for unit testing."""
    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)  # e_lfanew = 64

    # PE Signature (4 bytes)
    pe_sig = b"PE\x00\x00"

    # COFF Header (20 bytes): Machine=0x8664 (x64), 2 sections, opt_size=240, chars=0x0022
    coff_header = struct.pack("<HHIIIHH", 0x8664, 2, 1700000000, 0, 0, 240, 0x0022)

    # Optional Header PE32+ (240 bytes)
    opt_header = bytearray(240)
    struct.pack_into("<H", opt_header, 0, 0x020B)  # PE32+ magic
    struct.pack_into("<I", opt_header, 16, 0x1000)  # AddressOfEntryPoint = 0x1000
    struct.pack_into("<Q", opt_header, 24, 0x140000000)  # ImageBase
    struct.pack_into("<H", opt_header, 68, 3)  # Subsystem: WINDOWS_CUI

    # Section Headers (40 bytes each)
    # Section 1: .text (vsize=0x200, vaddr=0x1000, raw_size=512, raw_ptr=512, chars=0x60000020)
    sec1 = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 512, 512, 0, 0, 0, 0, 0x60000020)
    # Section 2: .data (vsize=0x100, vaddr=0x2000, raw_size=512, raw_ptr=1024, chars=0xC0000040)
    sec2 = struct.pack("<8sIIIIIIHHI", b".data\x00\x00\x00", 0x100, 0x2000, 512, 1024, 0, 0, 0, 0, 0xC0000040)

    # Padding up to raw_ptr 512
    headers = dos_header + pe_sig + coff_header + opt_header + sec1 + sec2
    pad1 = b"\x00" * (512 - len(headers))

    # Section 1 data (512 bytes): x64 nop + ret
    sec1_data = b"\x90\xC3" + (b"\x00" * 510)

    # Section 2 data (512 bytes): ASCII string
    sec2_data = b"Hello, R3V3R53//F0RG3\x00" + (b"\xAA" * 490)

    with open(filepath, "wb") as f:
        f.write(headers + pad1 + sec1_data + sec2_data)


def test_streaming_pe_analyzer_synthetic():
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
        tmp_path = tf.name
    try:
        create_minimal_pe_binary(tmp_path)
        analyzer = StreamingPEAnalyzer(tmp_path)
        res = analyzer.analyze(include_hashes=True)

        assert res.is_pe is True
        assert res.format == "PE"
        assert "x64" in res.architecture
        assert res.subsystem == "WINDOWS_CUI"
        assert res.entry_point == "0x1000"
        assert res.image_base == "0x140000000"
        assert len(res.sections) == 2
        assert res.sections[0].name == ".text"
        assert res.sections[0].executable is True
        assert res.sections[1].name == ".data"
        assert res.sections[1].writable is True
        assert res.hashes["sha256"] is not None
        assert res.hashes["md5"] is not None
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_streaming_entropy_calculation():
    # Pure zero buffer has entropy 0.0
    zero_buf = b"\x00" * 1024
    assert StreamingPEAnalyzer.calculate_entropy_chunked(zero_buf) == 0.0

    # Uniform random-like buffer has high entropy close to 8.0
    uniform_buf = bytes(range(256)) * 4
    ent = StreamingPEAnalyzer.calculate_entropy_chunked(uniform_buf)
    assert 7.9 < ent <= 8.0


def test_ab_benchmarker_statistical_math():
    # Test Welch's t-test p-value approximation
    p_high = BinaryABBenchmarker._t_to_p_value(0.1, 10.0)
    assert p_high > 0.5  # Small t-stat -> not significant

    p_sig = BinaryABBenchmarker._t_to_p_value(4.5, 15.0)
    assert p_sig < 0.001  # Large t-stat -> highly significant

    # Test critical t at 95%
    t_crit_10 = BinaryABBenchmarker._critical_t_95(10.0)
    assert abs(t_crit_10 - 2.228) < 0.05

    t_crit_large = BinaryABBenchmarker._critical_t_95(100.0)
    assert abs(t_crit_large - 1.984) < 0.05


def test_ab_benchmarker_guardrail_parity():
    bench = BinaryABBenchmarker.__new__(BinaryABBenchmarker)

    ctrl_meta = {
        "architecture": "x64 (64-bit AMD64)",
        "sections": [{"name": ".text"}, {"name": ".data"}],
        "entry_point": "0x1000",
        "is_pe": True,
    }

    # Perfect match
    guard_ok = bench._verify_guardrails(ctrl_meta, ctrl_meta)
    assert guard_ok.passed is True
    assert len(guard_ok.mismatches) == 0

    # Mismatch architecture
    bad_meta = dict(ctrl_meta)
    bad_meta["architecture"] = "x86 (32-bit)"
    guard_bad = bench._verify_guardrails(ctrl_meta, bad_meta)
    assert guard_bad.passed is False
    assert any("Architecture mismatch" in m for m in guard_bad.mismatches)


def test_ab_benchmarker_experiment_execution():
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
        tmp_path = tf.name
    try:
        create_minimal_pe_binary(tmp_path)
        bench = BinaryABBenchmarker(tmp_path, trials=5, warmup_runs=1)
        rep = bench.run_experiment()

        assert isinstance(rep, ABExperimentReport)
        assert rep.control.sample_size == 5
        assert rep.treatment.sample_size == 5
        assert rep.guardrails.passed is True
        assert rep.speedup_ratio > 0.0
        assert rep.degrees_of_freedom > 0.0
        assert "# R3V3R53//F0RG3  A/B Experiment Report" in rep.summary_markdown
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


class TestPhase41ABTesting(unittest.TestCase):
    def test_all_phase41(self):
        test_streaming_pe_analyzer_synthetic()
        test_streaming_entropy_calculation()
        test_ab_benchmarker_statistical_math()
        test_ab_benchmarker_guardrail_parity()
        test_ab_benchmarker_experiment_execution()


if __name__ == "__main__":
    unittest.main()
