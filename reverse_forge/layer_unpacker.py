"""
R3V3R53//F0RG3 — Advanced Format Unpackers & Firmware Extraction Engine (§01, §04)
Performs automated multi-layer unpacker identification and payload carving for
.class/JAR/WAR, .NET assemblies, Mach-O Fat binaries, and firmware images (U-Boot, SquashFS, tar, zip).
"""

import io
import os
import struct
import zipfile
import tarfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ExtractedLayer:
    layer_id: int
    format_type: str
    filename: str
    offset: int
    size_bytes: int
    sha256: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class LayerUnpacker:
    """Disassembles recursive container formats, archive envelopes, and firmware packages."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or os.path.join(os.getcwd(), ".extracted_layers")
        os.makedirs(self.output_dir, exist_ok=True)

    @staticmethod
    def identify_embedded_containers(data: bytes) -> List[Tuple[str, int, int]]:
        """Scan byte stream for embedded container magic signatures."""
        containers: List[Tuple[str, int, int]] = []
        length = len(data)

        # 1. ZIP / JAR / APK / WAR: 'PK\x03\x04'
        idx = 0
        while (idx := data.find(b"PK\x03\x04", idx)) != -1:
            containers.append(("ZIP_ARCHIVE", idx, length - idx))
            idx += 4

        # 2. GZIP container: '\x1f\x8b\x08'
        idx = 0
        while (idx := data.find(b"\x1f\x8b\x08", idx)) != -1:
            containers.append(("GZIP_STREAM", idx, length - idx))
            idx += 3

        # 3. SquashFS container: 'hsqs' or 'sqsh'
        idx = 0
        for sig in (b"hsqs", b"sqsh"):
            while (idx := data.find(sig, idx)) != -1:
                containers.append(("SQUASHFS_IMAGE", idx, length - idx))
                idx += 4

        # 4. U-Boot Legacy Image header: 0x27051956
        idx = 0
        while (idx := data.find(b"\x27\x05\x19\x56", idx)) != -1:
            containers.append(("UBOOT_IMAGE", idx, length - idx))
            idx += 4

        return containers

    @staticmethod
    def inspect_dotnet_metadata(data: bytes) -> Dict[str, Any]:
        """Detect .NET CLR metadata header presence and runtime target in PE binaries."""
        if len(data) < 64 or data[:2] != b"MZ":
            return {"is_dotnet": False}

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return {"is_dotnet": False}

        opt_magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
        is_64 = (opt_magic == 0x20B)
        data_dirs_base = e_lfanew + 24 + (112 if is_64 else 96)
        clr_dir_offset = data_dirs_base + 14 * 8

        if clr_dir_offset + 8 <= len(data):
            clr_rva, clr_size = struct.unpack_from("<II", data, clr_dir_offset)
            if clr_rva > 0 and clr_size > 0:
                return {
                    "is_dotnet": True,
                    "clr_header_rva": hex(clr_rva),
                    "clr_header_size": clr_size,
                    "runtime": ".NET Common Language Runtime (CLR)"
                }

        return {"is_dotnet": False}

    @staticmethod
    def inspect_java_archive(jar_path: str) -> Dict[str, Any]:
        """Inspect internal class hierarchy and manifest of a JAR / WAR artifact."""
        if not zipfile.is_zipfile(jar_path):
            return {"valid_archive": False}

        classes = []
        manifest_entries = {}
        with zipfile.ZipFile(jar_path, "r") as z:
            for item in z.infolist():
                if item.filename.endswith(".class"):
                    classes.append(item.filename)
                elif item.filename == "META-INF/MANIFEST.MF":
                    try:
                        for line in z.read(item).decode("utf-8", errors="ignore").splitlines():
                            if ":" in line:
                                k, v = line.split(":", 1)
                                manifest_entries[k.strip()] = v.strip()
                    except Exception:
                        pass

        return {
            "valid_archive": True,
            "total_classes": len(classes),
            "sample_classes": classes[:20],
            "main_class": manifest_entries.get("Main-Class"),
            "manifest": manifest_entries,
        }

    @staticmethod
    def parse_macho_fat_slices(data: bytes) -> List[Dict[str, Any]]:
        """Parse Universal / Fat Mach-O container and extract contained architecture slices."""
        if len(data) < 8:
            return []
        magic = struct.unpack(">I", data[:4])[0]
        if magic != 0xCAFEBABE:
            return []

        # Disambiguate from Java .class (which has minor/major version at offset 4)
        nfat_arch = struct.unpack(">I", data[4:8])[0]
        if nfat_arch > 30:  # Java class major version threshold
            return []

        slices = []
        offset = 8
        for i in range(nfat_arch):
            if offset + 20 > len(data):
                break
            cputype, cpusubtype, arch_offset, arch_size, align = struct.unpack(
                ">IIIII", data[offset:offset + 20]
            )
            slices.append({
                "slice_index": i,
                "cputype": cputype,
                "cpusubtype": cpusubtype,
                "offset": arch_offset,
                "size": arch_size,
                "alignment": align,
            })
            offset += 20
        return slices
