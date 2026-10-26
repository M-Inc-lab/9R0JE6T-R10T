import unittest
from reverse_forge.ida_universal_loader import IDAUniversalLoader, IDA_SUPPORTED_FORMATS_CATALOG
from reverse_forge.correlation_engine import CorrelationEngine
from reverse_forge.gui_server import HTML_TEMPLATE


class TestIDAUniversalFormatsV30(unittest.TestCase):
    def test_catalog_has_all_26_ida_format_families(self):
        catalog = IDAUniversalLoader.list_supported_formats()
        self.assertGreaterEqual(len(catalog), 26)
        ids = {c["id"] for c in catalog}
        for expected in (
            "elf64", "pe64", "macho64", "coff_ar", "dotnet_cil", "dex",
            "jvm_class", "wasm", "ebpf", "evm", "pyc", "luac", "llvm_bc",
            "ihex", "srec", "ti_txt", "uf2", "uboot", "android_boot",
            "uefi_te", "esp32", "dos_mz_ne_le", "console_rom", "minidump_pdb",
            "idb_flirt", "raw_multiarch"
        ):
            self.assertIn(expected, ids)

    def test_intel_hex_and_motorola_srec_and_uf2_decoders(self):
        ihex = b":10010000214601360121470136007EFE09D2190140\n:00000001FF\n"
        img_hex = IDAUniversalLoader.inspect_and_load(ihex, "fw.hex")
        self.assertEqual(img_hex.format_name, "Intel HEX Firmware")
        self.assertEqual(img_hex.base_va, 0x100)
        self.assertEqual(len(img_hex.normalized_bytes), 16)

        srec = b"S00F000068656C6C6F202020202000003C\nS113004048656C6C6F2C20576F726C64210A00003B\nS9030040BC\n"
        img_srec = IDAUniversalLoader.inspect_and_load(srec, "ecu.srec")
        self.assertEqual(img_srec.format_name, "Motorola S-Record Firmware")
        self.assertEqual(img_srec.base_va, 0x40)
        self.assertTrue(img_srec.normalized_bytes.startswith(b"Hello, World!"))

        import struct
        uf2_blk = bytearray(512)
        uf2_blk[:4] = b"UF2\n"
        struct.pack_into("<II", uf2_blk, 12, 0x10000100, 8)
        uf2_blk[32:40] = b"\x10\xb5\x04\x48\x19\x21\x10\xbd"
        img_uf2 = IDAUniversalLoader.inspect_and_load(bytes(uf2_blk), "blink.uf2")
        self.assertEqual(img_uf2.format_name, "UF2 Microcontroller Flash Image")
        self.assertEqual(img_uf2.base_va, 0x10000100)
        self.assertEqual(img_uf2.normalized_bytes, b"\x10\xb5\x04\x48\x19\x21\x10\xbd")

    def test_correlation_engine_identifies_all_ida_formats(self):
        ce = CorrelationEngine()
        self.assertEqual(ce.identify_format(b":1001000021460136"), "Intel HEX Firmware")
        self.assertEqual(ce.identify_format(b"S315800040009100"), "Motorola S-Record Firmware")
        self.assertEqual(ce.identify_format(b"UF2\n\x00\x00\x00\x00"), "UF2 Firmware")
        self.assertEqual(ce.identify_format(b"ANDROID!\x00\x10"), "Android Boot Image")
        self.assertEqual(ce.identify_format(b"MDMP\x93\xa7\x00\x00"), "Windows Minidump (MDMP)")
        self.assertEqual(ce.identify_format(b"Microsoft C/C++ MSF 7.00\r\n"), "Microsoft PDB")
        self.assertEqual(ce.identify_format(b"!<arch>\n/       "), "AR Static Archive (.a/.lib)")
        self.assertEqual(ce.identify_format(b"NSO0\x00\x00\x00\x00"), "Nintendo Switch NSO0")
        self.assertEqual(ce.identify_format(b"XBEH\x00\x00\x00\x00"), "Xbox XBE")
        self.assertEqual(ce.identify_format(b"XEX2\x00\x00\x00\x00"), "Xbox 360 XEX2")
        self.assertEqual(ce.identify_format(b"\x1bLuaT\x00\x19\x93"), "Lua Bytecode (.luac)")
        self.assertEqual(ce.identify_format(b"BC\xc0\xde\x35\x14\x00\x00"), "LLVM Bitcode (.bc)")
        self.assertEqual(ce.identify_format(b"\x27\x05\x19\x56\x00\x00\x00\x00"), "U-Boot uImage")
        self.assertEqual(ce.identify_format(b"\xd0\x0d\xfe\xed\x00\x00\x10\x00"), "Flattened Device Tree (DTB/FIT)")

    def test_html_template_has_all_24_bundles_and_ida_presets(self):
        self.assertEqual(HTML_TEMPLATE.count("<!DOCTYPE html>"), 1)
        self.assertNotIn("if (je(", HTML_TEMPLATE)
        self.assertIn("IDA_FORMAT_PRESETS", HTML_TEMPLATE)
        self.assertIn("loadIdaFormatPreset", HTML_TEMPLATE)
        self.assertIn("openIdaFormatsCatalogModal", HTML_TEMPLATE)
        self.assertIn('"0x86e0":', HTML_TEMPLATE)


if __name__ == "__main__":
    unittest.main()
