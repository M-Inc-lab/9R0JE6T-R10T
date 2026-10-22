import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Any, Optional


class ColabGPUClient:
    """Authenticated Python client to offload tasks to remote Colab T4 GPU."""

    def __init__(self, endpoint: Optional[str] = None, token: Optional[str] = None, allow_http: bool = False):
        env_values: Dict[str, str] = {}
        if os.path.exists(".env"):
            with open(".env", "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#") and "=" in stripped:
                        k, v = stripped.split("=", 1)
                        env_values[k.strip()] = v.strip()

        if not endpoint:
            endpoint = os.environ.get("COLAB_GPU_ENDPOINT") or env_values.get("COLAB_GPU_ENDPOINT")
        if not endpoint:
            raise ValueError("Endpoint not found. Set COLAB_GPU_ENDPOINT in .env or pass directly.")

        parsed = urllib.parse.urlparse(endpoint.strip())
        allowed_schemes = ("https", "http") if allow_http else ("https",)
        if parsed.scheme not in allowed_schemes or not parsed.netloc:
            raise ValueError(f"Invalid or insecure endpoint URL: {endpoint!r}")

        self.endpoint = endpoint.strip().rstrip("/")
        self.token = token or os.environ.get("COLAB_GPU_TOKEN") or env_values.get("COLAB_GPU_TOKEN")

    def _headers(self, content_type: Optional[str] = None) -> Dict[str, str]:
        headers = {"User-Agent": "Antigravity-Client/1.0"}
        if content_type:
            headers["Content-Type"] = content_type
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self.endpoint}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers=self._headers(content_type="application/json"),
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def get_health(self) -> Dict[str, Any]:
        """Fetch remote GPU specs and VRAM status."""
        req = urllib.request.Request(f"{self.endpoint}/health", headers=self._headers())
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def run_command(self, cmd: str) -> Dict[str, Any]:
        """Execute allowlisted command on Colab."""
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
        print("Hint: Run `python connect_colab.py --url <YOUR_URL> --token <YOUR_TOKEN>` first.")
