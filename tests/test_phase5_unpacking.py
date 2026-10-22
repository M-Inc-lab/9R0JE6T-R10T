"""
Tests for Phase 5: Container Extraction, .NET Metadata, and Universal Fat Slices.
"""

import os
import struct
import tempfile
import unittest
import zipfile

from reverse_forge.layer_unpacker import LayerUnpacker


class TestPhase5LayerUnpacker(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_identify_embedded_containers(self):
        blob = b"\x00" * 32 + b"PK\x03\x04" + b"\x00" * 64 + b"hsqs" + b"\x00" * 128
        containers = LayerUnpacker.identify_embedded_containers(blob)
        types = [c[0] for c in containers]
        self.assertIn("ZIP_ARCHIVE", types)
        self.assertIn("SQUASHFS_IMAGE", types)

    def test_inspect_dotnet_metadata_negative_and_positive(self):
        # Negative
        self.assertFalse(LayerUnpacker.inspect_dotnet_metadata(b"MZ\x00")["is_dotnet"])

        # Construct synthetic PE with CLR directory entry
        dos = bytearray(64)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 64)
        pe_sig = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)
        opt = bytearray(224)
        struct.pack_into("<H", opt, 0, 0x10B)
        # Directory 14 is CLR runtime header: offset 96 + 14 * 8 = 208
        struct.pack_into("<II", opt, 208, 0x2000, 0x48)
        blob = bytes(dos) + pe_sig + coff + bytes(opt)

        res = LayerUnpacker.inspect_dotnet_metadata(blob)
        self.assertTrue(res["is_dotnet"])
        self.assertEqual(res["clr_header_rva"], hex(0x2000))

    def test_inspect_java_archive(self):
        jar_path = os.path.join(self.tmp_dir.name, "test.jar")
        with zipfile.ZipFile(jar_path, "w") as z:
            z.writestr("com/example/Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34")
            z.writestr("META-INF/MANIFEST.MF", "Main-Class: com.example.Main\n")

        res = LayerUnpacker.inspect_java_archive(jar_path)
        self.assertTrue(res["valid_archive"])
        self.assertEqual(res["total_classes"], 1)
        self.assertEqual(res["main_class"], "com.example.Main")

    def test_parse_macho_fat_slices(self):
        # CAFEBABE header with 1 arch slice (ARM64: cputype=0x0100000C)
        fat_hdr = struct.pack(">II", 0xCAFEBABE, 1)
        slice_hdr = struct.pack(">IIIII", 0x0100000C, 0x0, 0x4000, 0x8000, 14)
        blob = fat_hdr + slice_hdr + b"\x00" * 100

        slices = LayerUnpacker.parse_macho_fat_slices(blob)
        self.assertEqual(len(slices), 1)
        self.assertEqual(slices[0]["cputype"], 0x0100000C)
        self.assertEqual(slices[0]["offset"], 0x4000)


if __name__ == "__main__":
    unittest.main()
