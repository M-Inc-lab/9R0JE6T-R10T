import os
import xml.etree.ElementTree as ET
from typing import Dict, Any


class WindowsSandbox:
    """Manages isolated Windows Sandbox (.wsb) execution profile generation."""

    def __init__(self, target_filepath: str):
        self.target_filepath = os.path.abspath(target_filepath)
        self.target_dir = os.path.dirname(self.target_filepath)
        self.filename = os.path.basename(self.target_filepath)

    def generate_wsb_profile(self, output_wsb_path: str, enable_networking: bool = False) -> str:
        """Create a dedicated .wsb XML file mapping the artifact folder read-only."""
        if not os.path.exists(self.target_filepath):
            raise FileNotFoundError(f"Target artifact not found: {self.target_filepath}")

        clean_name = self.filename.replace("\r", "").replace("\n", "")
        safe_ps_name = clean_name.replace("'", "''").replace('"', '`"')

        root = ET.Element("Configuration")
        ET.SubElement(root, "VGpu").text = "Disable"
        ET.SubElement(root, "Networking").text = "Default" if enable_networking else "Disable"

        mapped_folders = ET.SubElement(root, "MappedFolders")
        mapped_folder = ET.SubElement(mapped_folders, "MappedFolder")
        ET.SubElement(mapped_folder, "HostFolder").text = self.target_dir
        ET.SubElement(mapped_folder, "SandboxFolder").text = r"C:\Analysis"
        ET.SubElement(mapped_folder, "ReadOnly").text = "true"

        logon_command = ET.SubElement(root, "LogonCommand")
        ET.SubElement(logon_command, "Command").text = (
            f"powershell -NoExit -Command \"Write-Host '[*] Artifact staged at C:\\Analysis\\{safe_ps_name}'; "
            f"Set-Location C:\\Analysis\""
        )

        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(output_wsb_path, encoding="utf-8", xml_declaration=False)
        return os.path.abspath(output_wsb_path)

    def launch_sandbox(self, wsb_path: str) -> Dict[str, Any]:
        """Launch Windows Sandbox if supported and installed."""
        if not os.path.exists(wsb_path):
            return {"status": "error", "error": f"WSB profile not found: {wsb_path}"}
        if not hasattr(os, "startfile"):
            return {"status": "unsupported", "error": "Windows Sandbox execution requires a Windows host"}

        try:
            os.startfile(wsb_path)  # type: ignore[attr-defined]
            return {"status": "launched", "profile": wsb_path, "message": "Windows Sandbox dispatched."}
        except Exception as e:
            return {"status": "failed", "error": str(e)}
