import os
import subprocess
from typing import Dict, Any

class WindowsSandbox:
    """Manages isolated Windows Sandbox (.wsb) execution profile generation."""

    def __init__(self, target_filepath: str):
        self.target_filepath = os.path.abspath(target_filepath)
        self.target_dir = os.path.dirname(self.target_filepath)
        self.filename = os.path.basename(self.target_filepath)

    def generate_wsb_profile(self, output_wsb_path: str, enable_networking: bool = False) -> str:
        """Create a dedicated .wsb file mapping the artifact folder read-only."""
        net_str = "Default" if enable_networking else "Disable"
        wsb_content = f"""<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>{net_str}</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{self.target_dir}</HostFolder>
      <SandboxFolder>C:\\Analysis</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell -NoExit -Command "Write-Host '[*] Artifact staged at C:\\Analysis\\{self.filename}'; Set-Location C:\\Analysis"</Command>
  </LogonCommand>
</Configuration>
"""
        with open(output_wsb_path, "w", encoding="utf-8") as f:
            f.write(wsb_content)
        return os.path.abspath(output_wsb_path)

    def launch_sandbox(self, wsb_path: str) -> Dict[str, Any]:
        """Launch Windows Sandbox if supported and installed."""
        if not os.path.exists(wsb_path):
            return {"status": "error", "error": f"WSB profile not found: {wsb_path}"}

        try:
            # Starts Windows Sandbox using default handler
            os.startfile(wsb_path)
            return {"status": "launched", "profile": wsb_path, "message": "Windows Sandbox dispatched."}
        except Exception as e:
            return {"status": "failed", "error": str(e)}
