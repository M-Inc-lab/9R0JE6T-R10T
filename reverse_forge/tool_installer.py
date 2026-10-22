import hashlib
import inspect
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from typing import Dict, Any, Optional

TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")
MANIFEST_PATH = os.path.join(TOOLS_DIR, "tools_manifest.json")


class ToolchainInstaller:
    """Cross-platform toolchain installer and environment manager."""

    def __init__(self):
        os.makedirs(TOOLS_DIR, exist_ok=True)
        self.os_type = platform.system().lower()  # 'windows', 'linux', 'darwin'
        self.arch = platform.machine().lower()    # 'amd64', 'x86_64', 'arm64', 'aarch64'

    @staticmethod
    def _safe_extract_zip(z: zipfile.ZipFile, dest_dir: str) -> None:
        """Extract zip archive members while preventing path traversal (Zip Slip)."""
        abs_dest = os.path.abspath(dest_dir)
        for member in z.infolist():
            target_path = os.path.abspath(os.path.join(abs_dest, member.filename))
            if os.path.commonpath([abs_dest, target_path]) != abs_dest:
                raise ValueError(f"Unsafe zip member path blocked: {member.filename}")
        z.extractall(abs_dest)

    @staticmethod
    def _safe_extract_tar(t: tarfile.TarFile, dest_dir: str) -> None:
        """Extract tar archive members while preventing path traversal and unsafe links (Tar Slip)."""
        abs_dest = os.path.abspath(dest_dir)
        for member in t.getmembers():
            target_path = os.path.abspath(os.path.join(abs_dest, member.name))
            if os.path.commonpath([abs_dest, target_path]) != abs_dest:
                raise ValueError(f"Unsafe tar member path blocked: {member.name}")
            if member.issym() or member.islnk() or member.isdev():
                link_target = os.path.abspath(os.path.join(os.path.dirname(target_path), member.linkname))
                if member.isdev() or os.path.commonpath([abs_dest, link_target]) != abs_dest:
                    raise ValueError(f"Unsafe tar link/device blocked: {member.name}")

        if "filter" in inspect.signature(t.extractall).parameters:
            t.extractall(abs_dest, filter="data")
        else:
            t.extractall(abs_dest)

    def get_manifest(self) -> Dict[str, Any]:
        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def save_manifest(self, data: Dict[str, Any]):
        with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def detect_all(self) -> Dict[str, Any]:
        manifest = self.get_manifest()
        tools = {
            "radare2": self._find_r2(manifest),
            "ghidra": self._find_ghidra(manifest),
            "python": {"available": True, "path": sys.executable},
            "system_disassemblers": self._find_system_disassemblers()
        }
        return tools

    def _find_r2(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        sys_path = shutil.which("r2") or shutil.which("radare2")
        if sys_path:
            return {"available": True, "path": sys_path, "type": "system"}

        r2_bin = manifest.get("radare2", {}).get("binary_path")
        if r2_bin and os.path.exists(r2_bin):
            return {"available": True, "path": r2_bin, "type": "managed"}

        for root, _, files in os.walk(TOOLS_DIR):
            for file in files:
                if file in ("radare2.exe", "r2.exe", "r2"):
                    candidate = os.path.join(root, file)
                    return {"available": True, "path": candidate, "type": "managed"}

        return {"available": False, "path": None, "type": None}

    def _find_ghidra(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        sys_path = shutil.which("analyzeHeadless") or shutil.which("ghidra")
        if sys_path:
            return {"available": True, "path": sys_path, "type": "system"}

        ghidra_bin = manifest.get("ghidra", {}).get("binary_path")
        if ghidra_bin and os.path.exists(ghidra_bin):
            return {"available": True, "path": ghidra_bin, "type": "managed"}

        for root, _, files in os.walk(TOOLS_DIR):
            for file in files:
                if file in ("analyzeHeadless.bat", "analyzeHeadless"):
                    candidate = os.path.join(root, file)
                    return {"available": True, "path": candidate, "type": "managed"}

        return {"available": False, "path": None, "type": None}

    def _find_system_disassemblers(self) -> Dict[str, Any]:
        return {
            "objdump": shutil.which("objdump") is not None,
            "dumpbin": shutil.which("dumpbin") is not None,
            "gdb": shutil.which("gdb") is not None,
            "pwsh": shutil.which("pwsh") is not None
        }

    def install_radare2(self, expected_sha256: Optional[str] = None) -> Dict[str, Any]:
        """Download prebuilt portable release of radare2 from GitHub releases with safe extraction."""
        print(f"[*] Bootstrapping Radare2 for {self.os_type} ({self.arch})...")
        manifest = self.get_manifest()

        tag = "5.9.8"
        base_url = f"https://github.com/radareorg/radare2/releases/download/{tag}"

        if self.os_type == "windows":
            filename = f"radare2-{tag}-w64.zip" if "64" in self.arch else f"radare2-{tag}-w32.zip"
            url = f"{base_url}/{filename}"
            is_zip = True
        elif self.os_type == "darwin":
            filename = f"radare2-{tag}-macos.tar.gz"
            url = f"{base_url}/{filename}"
            is_zip = False
        else:
            linux_arch = "arm64" if self.arch in ("arm64", "aarch64") else "x86_64"
            filename = f"radare2-{tag}-linux-{linux_arch}.tar.gz"
            url = f"{base_url}/{filename}"
            is_zip = False

        dest_folder = os.path.join(TOOLS_DIR, "radare2")
        os.makedirs(dest_folder, exist_ok=True)

        try:
            print(f"[*] Fetching archive: {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "R3V3R53-F0RG3-Installer/1.0"})
            with urllib.request.urlopen(req, timeout=60) as response:
                archive_bytes = response.read()

            actual_sha256 = hashlib.sha256(archive_bytes).hexdigest()
            if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
                raise ValueError(
                    f"SHA-256 mismatch for {filename}: expected {expected_sha256}, got {actual_sha256}"
                )

            print("[*] Extracting portable toolchain safely...")
            if is_zip:
                with zipfile.ZipFile(io.BytesIO(archive_bytes)) as z:
                    self._safe_extract_zip(z, dest_folder)
            else:
                with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as t:
                    self._safe_extract_tar(t, dest_folder)

            found_bin = None
            for root, _, files in os.walk(dest_folder):
                for f in files:
                    if f in ("radare2.exe", "r2.exe", "r2"):
                        found_bin = os.path.join(root, f)
                        break
                if found_bin:
                    break

            if found_bin:
                if self.os_type != "windows":
                    os.chmod(found_bin, 0o755)
                manifest["radare2"] = {
                    "version": tag,
                    "binary_path": found_bin,
                    "archive_sha256": actual_sha256,
                    "installed_at": TOOLS_DIR,
                }
                self.save_manifest(manifest)
                print(f"[+] Radare2 installed successfully: {found_bin}")
                return {"success": True, "path": found_bin, "sha256": actual_sha256}
            return {"success": False, "error": "Extracted archive did not contain r2 binary"}

        except Exception as e:
            print(f"[-] Radare2 installation failed: {e}")
            return {"success": False, "error": str(e)}

    def install_capstone_disassembler(self) -> Dict[str, Any]:
        """Optionally install pure Python disassembler wrapper if pip is available."""
        print("[*] Checking Python disassembly bindings (capstone)...")
        try:
            import capstone  # noqa: F401
            return {"success": True, "installed": True, "type": "builtin"}
        except ImportError:
            print("[*] Installing capstone via pip...")
            res = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "capstone"], capture_output=True)
            if res.returncode == 0:
                print("[+] Capstone installed successfully.")
                return {"success": True, "installed": True, "type": "pip"}
            return {"success": False, "error": res.stderr.decode("utf-8", errors="ignore")}

    def bootstrap_all(self) -> Dict[str, Any]:
        """Run complete self-installation of required disassemblers and helper tools."""
        results = {}
        status = self.detect_all()

        if not status["radare2"]["available"]:
            results["radare2"] = self.install_radare2()
        else:
            results["radare2"] = {"success": True, "message": "Already present", "path": status["radare2"]["path"]}

        results["capstone"] = self.install_capstone_disassembler()
        return results
