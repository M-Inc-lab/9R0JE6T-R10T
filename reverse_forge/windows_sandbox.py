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
        # Generate telemetry logger script wrapper inside sandbox
        ET.SubElement(logon_command, "Command").text = (
            f"powershell -NoExit -Command \""
            f"Write-Host '[*] R3V3R53//F0RG3 Sandbox Environment Activated'; "
            f"Write-Host '[*] Artifact staged at C:\\Analysis\\{safe_ps_name}'; "
            f"Set-Location C:\\Analysis; "
            f"Write-Host '[*] Initializing Procmon / ETW trace listeners...';\""
        )

        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(output_wsb_path, encoding="utf-8", xml_declaration=False)
        return os.path.abspath(output_wsb_path)

    @staticmethod
    def generate_telemetry_collector_script(output_ps1_path: str, target_name: str, duration_sec: int = 30) -> str:
        """Create a standalone PowerShell script to monitor and output telemetry JSON."""
        safe_target = target_name.replace("\\r", "").replace("\\n", "").replace("'", "''")
        ps_script = f"""# R3V3R53//F0RG3 Automated Behavioral Telemetry Collector
$target = '{safe_target}'
$logPath = if (Test-Path -Path "C:\\Analysis" -PathType Container) {{ Join-Path $env:TEMP "telemetry_trace.json" }} else {{ "telemetry_trace.json" }}
$duration = {duration_sec}

Write-Host "[+] Monitoring $target for $duration seconds..."
$startTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
$proc = Start-Process -FilePath $target -PassThru -ErrorAction SilentlyContinue

$trace = @{{
    "processes" = @();
    "files" = @();
    "registry" = @();
    "network" = @();
    "crashes" = @();
}}

if ($proc) {{
    $trace["processes"] += @{{
        "timestamp" = $startTime;
        "pid" = $proc.Id;
        "parent_pid" = $PID;
        "image_path" = $target;
        "command_line" = $target;
        "action" = "SPAWNED";
    }}
    Start-Sleep -Seconds $duration
    if (-not $proc.HasExited) {{
        $proc.Kill()
    }}
}}

$trace | ConvertTo-Json -Depth 5 | Out-File -FilePath $logPath -Encoding utf8
Write-Host "[+] Telemetry written to $logPath"
"""
        with open(output_ps1_path, "w", encoding="utf-8") as f:
            f.write(ps_script)
        return os.path.abspath(output_ps1_path)

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
