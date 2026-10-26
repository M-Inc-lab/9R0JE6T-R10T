"""
R3V3R53//F0RG3 — Phase 76: Multi-Container Archive, APK/IPA, PyInstaller & Document Dropper Triage Engine
(`archive_container_triage_engine.py`)
In real-world DFIR and automated first-response triage, binaries frequently arrive wrapped inside
containers, mobile packages, or single-file bundlers. This engine provides safe, bounded, in-memory
recursive inspection for:
  1. Android Packages (`.apk` / `.aab` / `.jar`) — extracts and triages `classes*.dex`, `AndroidManifest.xml`,
     and native JNI libraries (`lib/arm64-v8a/*.so`, `lib/x86_64/*.so`)
  2. ZIP / IPA Containers — zip-bomb protected in-memory member extraction with format/entropy/hash triage
  3. PyInstaller Single-File Executables (`MEI\\x0c\\x0b\\x0a\\x0b\\x0e` CArchive cookie detector)
  4. Office OLE2 (`\\xD0\\xCF\\x11\\xE0`) & PDF (`/OpenAction`, `/JavaScript`, `/EmbeddedFiles`) dropper triage
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import io
import re
import struct
from typing import Any, Dict, List, Optional
import zipfile

from reverse_forge.correlation_engine import CorrelationEngine
from reverse_forge.pe_analyzer import PEAnalyzer


@dataclass
class ContainerMemberTriage:
    member_path: str
    compressed_size: int
    uncompressed_size: int
    sha256: str
    detected_format: str
    entropy: float
    is_executable_or_bytecode: bool
    triage_notes: List[str] = field(default_factory=list)


@dataclass
class ContainerTriageReport:
    container_type: str             # ANDROID_APK, ZIP_ARCHIVE, PYINSTALLER_BUNDLE, PDF_DOCUMENT, OLE2_COMPOUND, NATIVE_BINARY
    is_container: bool
    total_members_inspected: int
    executable_payloads_count: int
    zip_bomb_blocked: bool = False
    bundler_metadata: Dict[str, Any] = field(default_factory=dict)
    suspicious_indicators: List[str] = field(default_factory=list)
    members: List[ContainerMemberTriage] = field(default_factory=list)


class ArchiveContainerTriageEngine:
    """
    Safely unpacks and triages nested executables, bytecode modules (`DEX`, `WASM`, `.pyc`),
    and native libraries inside ZIP/APK/JAR archives, PyInstaller bundles, OLE2 files, and PDFs.
    """

    PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
    OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    MAX_MEMBER_BYTES = 16 * 1024 * 1024
    MAX_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
    MAX_COMPRESSION_RATIO = 100.0

    def triage_container(self, data: bytes) -> ContainerTriageReport:
        # 1. Check for PyInstaller CArchive cookie inside PE/ELF overlay
        pyinst_pos = data.rfind(self.PYINSTALLER_MAGIC)
        if pyinst_pos != -1:
            return self._triage_pyinstaller(data, pyinst_pos)

        # 2. Check for ZIP / APK / JAR / IPA / OOXML archive
        if len(data) >= 4 and data[:4] == b"PK\x03\x04":
            return self._triage_zip_or_apk(data)

        # 3. Check for PDF document with risky actions / embedded streams
        if data[:5] == b"%PDF-":
            return self._triage_pdf(data)

        # 4. Check for OLE2 Compound Document (.doc / .xls / .msi)
        if len(data) >= 8 and data[:8] == self.OLE2_MAGIC:
            return self._triage_ole2(data)

        fmt = CorrelationEngine().identify_format(data)
        return ContainerTriageReport(
            container_type=f"NATIVE_{fmt.upper().replace(' ', '_')}",
            is_container=False,
            total_members_inspected=0,
            executable_payloads_count=1 if fmt != "Unknown" else 0,
        )

    def _triage_zip_or_apk(self, data: bytes) -> ContainerTriageReport:
        members_out: List[ContainerMemberTriage] = []
        indicators: List[str] = []
        is_apk = False
        has_manifest = False
        dex_count = 0
        jni_libs: List[str] = []
        exec_count = 0
        total_uncompressed = 0
        bomb_blocked = False
        ce = CorrelationEngine()

        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                infos = zf.infolist()
                for info in infos[:64]:
                    if info.is_dir():
                        continue
                    comp_sz = max(1, info.compress_size)
                    uncomp_sz = info.file_size
                    ratio = uncomp_sz / comp_sz

                    if ratio > self.MAX_COMPRESSION_RATIO or uncomp_sz > self.MAX_MEMBER_BYTES or (total_uncompressed + uncomp_sz) > self.MAX_TOTAL_UNCOMPRESSED_BYTES:
                        bomb_blocked = True
                        indicators.append(f"Blocked potential zip-bomb member '{info.filename}' (ratio={ratio:.1f}x, size={uncomp_sz})")
                        continue

                    raw_member = zf.read(info.filename)
                    total_uncompressed += len(raw_member)
                    sha = hashlib.sha256(raw_member).hexdigest()
                    ent = PEAnalyzer.calculate_entropy(raw_member)
                    fmt = ce.identify_format(raw_member)

                    notes: List[str] = []
                    fname_lower = info.filename.lower()
                    if fname_lower == "androidmanifest.xml":
                        has_manifest = True
                        is_apk = True
                        notes.append("Android binary XML manifest")
                    if fname_lower.endswith(".dex") or fmt == "Android DEX":
                        is_apk = True
                        dex_count += 1
                        notes.append(f"Dalvik Executable #{dex_count}")
                    if fname_lower.startswith("lib/") and fname_lower.endswith(".so"):
                        is_apk = True
                        jni_libs.append(info.filename)
                        notes.append("Native JNI shared library")

                    is_exec = fmt in ("PE", "ELF", "Mach-O", "Android DEX", "WASM", "JVM Class") or fname_lower.endswith(
                        (".exe", ".dll", ".so", ".dylib", ".dex", ".wasm", ".pyc", ".ps1", ".vbs", ".bat", ".sh")
                    )
                    if is_exec:
                        exec_count += 1

                    members_out.append(
                        ContainerMemberTriage(
                            member_path=info.filename,
                            compressed_size=info.compress_size,
                            uncompressed_size=uncomp_sz,
                            sha256=sha,
                            detected_format=fmt,
                            entropy=ent,
                            is_executable_or_bytecode=is_exec,
                            triage_notes=notes,
                        )
                    )
        except Exception as exc:
            indicators.append(f"Malformed ZIP structure: {exc}")

        c_type = "ANDROID_APK" if is_apk else "ZIP_ARCHIVE"
        if is_apk and jni_libs:
            indicators.append(f"APK bundles {len(jni_libs)} native JNI library payload(s): {', '.join(jni_libs[:5])}")

        return ContainerTriageReport(
            container_type=c_type,
            is_container=True,
            total_members_inspected=len(members_out),
            executable_payloads_count=exec_count,
            zip_bomb_blocked=bomb_blocked,
            bundler_metadata={
                "has_android_manifest": has_manifest,
                "dex_files_count": dex_count,
                "native_jni_libraries": jni_libs,
            },
            suspicious_indicators=indicators,
            members=members_out,
        )

    def _triage_pyinstaller(self, data: bytes, cookie_offset: int) -> ContainerTriageReport:
        py_ver = "Python 3.x"
        if cookie_offset + 24 <= len(data):
            _, _, _, py_vers_raw = struct.unpack_from("!8siii", data, cookie_offset)
            if 300 <= py_vers_raw <= 399:
                py_ver = f"Python {py_vers_raw // 100}.{py_vers_raw % 100}"
            elif 30 <= py_vers_raw <= 39:
                py_ver = f"Python {py_vers_raw // 10}.{py_vers_raw % 10}"

        # Extract embedded module names near PyInstaller table of contents
        mod_names = [
            m.group(0).decode("ascii", errors="ignore")
            for m in re.finditer(rb"[a-zA-Z0-9_]{3,40}\.pyc?", data[max(0, cookie_offset - 4096) : cookie_offset + 512])
        ]
        return ContainerTriageReport(
            container_type="PYINSTALLER_BUNDLE",
            is_container=True,
            total_members_inspected=len(mod_names) or 1,
            executable_payloads_count=len(mod_names) or 1,
            bundler_metadata={
                "cookie_offset": hex(cookie_offset),
                "python_version": py_ver,
                "embedded_modules": list(dict.fromkeys(mod_names))[:20],
            },
            suspicious_indicators=[
                f"PyInstaller CArchive ('MEI') detected at offset {hex(cookie_offset)} ({py_ver})"
            ],
        )

    def _triage_pdf(self, data: bytes) -> ContainerTriageReport:
        indicators: List[str] = []
        for tag in (b"/OpenAction", b"/AA", b"/JavaScript", b"/JS", b"/Launch", b"/EmbeddedFiles", b"/RichMedia"):
            cnt = data.count(tag)
            if cnt > 0:
                indicators.append(f"PDF contains {cnt} '{tag.decode('ascii')}' directive(s)")
        return ContainerTriageReport(
            container_type="PDF_DOCUMENT",
            is_container=True,
            total_members_inspected=1,
            executable_payloads_count=1 if indicators else 0,
            suspicious_indicators=indicators,
        )

    def _triage_ole2(self, data: bytes) -> ContainerTriageReport:
        indicators: List[str] = []
        if b"VBA" in data or b"Attribute VB_Name" in data:
            indicators.append("OLE2 Compound Document contains embedded VBA Macro stream")
        if b"SummaryInformation" in data and b"MSI" in data:
            indicators.append("Windows Installer (MSI) OLE2 package detected")
        return ContainerTriageReport(
            container_type="OLE2_COMPOUND",
            is_container=True,
            total_members_inspected=1,
            executable_payloads_count=1 if indicators else 0,
            suspicious_indicators=indicators,
        )
