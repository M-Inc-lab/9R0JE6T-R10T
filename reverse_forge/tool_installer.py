import io
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile
import tarfile
from typing import Dict, Any, Optional

TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")
MANIFEST_PATH = os.path.join(TOOLS_DIR, "tools_manifest.json")

class ToolchainInstaller:
    """Cross-platform toolchain installer and environment manager."""

    def __init__(self):
        os.makedirs(TOOLS_DIR, exist_ok=True)
        self.os_type = platform.system().lower()  # 'windows', 'linux', 'darwin'
        self.arch = platform.machine().lower()    # 'amd64', 'x86_64', 'arm64', 'aarch64'

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
        # Check system path first
        sys_path = shutil.which("r2") or shutil.which("radare2")
        if sys_path:
            return {"available": True, "path": sys_path, "type": "system"}

        # Check local bootstrap folder
        r2_bin = manifest.get("radare2", {}).get("binary_path")
        if r2_bin and os.path.exists(r2_bin):
            return {"available": True, "path": r2_bin, "type": "managed"}

        # Search inside TOOLS_DIR
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

    def install_radare2(self) -> Dict[str, Any]:
        """Download prebuilt portable release of radare2 from github releases."""
        print(f"[*] Bootstrapping Radare2 for {self.os_type} ({self.arch})...")
        manifest = self.get_manifest()

        # Target GitHub release mapping
        # Using official radare2 release asset
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
        else: # linux
            filename = f"radare2-{tag}-linux-x86_64.tar.gz"
            url = f"{base_url}/{filename}"
            is_zip = False

        dest_folder = os.path.join(TOOLS_DIR, "radare2")
        os.makedirs(dest_folder, exist_ok=True)

        try:
            print(f"[*] Fetching archive: {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "R3V3R53-F0RG3-Installer/1.0"})
            with urllib.request.urlopen(req, timeout=60) as response:
                archive_bytes = response.read()

            print("[*] Extracting portable toolchain...")
            if is_zip:
                with zipfile.ZipFile(io.BytesIO(archive_bytes)) as z:
                    z.extractall(dest_folder)
            else:
                with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as t:
                    t.extractall(dest_folder)

            # Locate r2 binary
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
                    "installed_at": TOOLS_DIR
                }
                self.save_manifest(manifest)
                print(f"[+] Radare2 installed successfully: {found_bin}")
                return {"success": True, "path": found_bin}
            else:
                return {"success": False, "error": "Extracted archive did not contain r2 binary"}

        except Exception as e:
            print(f"[-] Radare2 installation failed: {e}")
            return {"success": False, "error": str(e)}

    def install_capstone_disassembler(self) -> Dict[str, Any]:
        """Optionally install pure Python disassembler wrapper if pip is available."""
        print("[*] Checking Python disassembly bindings (capstone)...")
        try:
            import capstone
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
