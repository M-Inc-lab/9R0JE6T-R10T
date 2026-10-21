import os
import json
import urllib.request
import urllib.error
from typing import Dict, Any

class ColabGPUClient:
    """Lightweight Python client to offload tasks to remote Colab T4 GPU."""
    def __init__(self, endpoint: str = None):
        if not endpoint:
            # Check environment or .env file
            endpoint = os.environ.get("COLAB_GPU_ENDPOINT")
            if not endpoint and os.path.exists(".env"):
                with open(".env", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("COLAB_GPU_ENDPOINT="):
                            endpoint = line.strip().split("=", 1)[1]
                            break
        if not endpoint:
            raise ValueError("Endpoint not found. Set COLAB_GPU_ENDPOINT in .env or pass directly.")
        self.endpoint = endpoint.rstrip("/")

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self.endpoint}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "Antigravity-Client/1.0"}
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())

    def get_health(self) -> Dict[str, Any]:
        """Fetch remote GPU specs and VRAM status."""
        req = urllib.request.Request(f"{self.endpoint}/health")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())

    def run_command(self, cmd: str) -> Dict[str, Any]:
        """Execute bash command with GPU acceleration on Colab."""
        return self._post("/api/run", {"cmd": cmd})

    def run_inference(self, prompt: str) -> Dict[str, Any]:
        """Run remote inference task."""
        return self._post("/api/infer", {"prompt": prompt})

if __name__ == "__main__":
    try:
        client = ColabGPUClient()
        print("[*] Checking remote Colab GPU health...")
        print(client.get_health())
        print("[*] Running nvidia-smi on Colab...")
        res = client.run_command("nvidia-smi")
        print(res.get("stdout"))
    except Exception as e:
        print(f"[-] Client execution error: {e}")
        print("Hint: Run `python connect_colab.py --url <YOUR_URL>` first.")
