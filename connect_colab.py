import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional


def validate_endpoint_url(raw_url: str, allow_http: bool = False) -> str:
    """Validate and normalize the remote endpoint URL."""
    cleaned = raw_url.strip()
    if any(ch in cleaned for ch in ("\r", "\n", "\x00")):
        raise ValueError("URL contains forbidden control characters")

    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"

    parsed = urllib.parse.urlparse(cleaned)
    allowed_schemes = ("https", "http") if allow_http else ("https",)
    if parsed.scheme not in allowed_schemes:
        raise ValueError(f"URL scheme '{parsed.scheme}' not permitted (use https://)")
    if not parsed.netloc or " " in parsed.netloc:
        raise ValueError(f"Invalid URL hostname: {parsed.netloc!r}")

    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")


def check_health(base_url: str, token: Optional[str] = None) -> bool:
    health_url = f"{base_url.rstrip('/')}/health"
    print(f"[*] Pinging {health_url}...")
    start_time = time.time()
    headers = {"User-Agent": "Antigravity-Client/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(health_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            latency = round((time.time() - start_time) * 1000, 2)
            data = json.loads(response.read().decode("utf-8"))
            print(f"[+] Server responding! Latency: {latency}ms")
            print(f"[+] Remote Status: {json.dumps(data, indent=2)}")
            return True
    except Exception as e:
        print(f"[-] Health check failed: {e}")
        return False


def update_env(base_url: str, token: Optional[str] = None) -> None:
    env_path = os.path.join(os.getcwd(), ".env")
    clean_url = base_url.rstrip("/")
    if any(ch in clean_url for ch in ("\r", "\n")):
        raise ValueError("Refusing to write newline characters to .env")
    if token and any(ch in token for ch in ("\r", "\n")):
        raise ValueError("Refusing to write newline characters in token to .env")

    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    found_url = False
    found_token = False
    new_lines = []
    for line in lines:
        if line.startswith("COLAB_GPU_ENDPOINT="):
            new_lines.append(f"COLAB_GPU_ENDPOINT={clean_url}\n")
            found_url = True
        elif line.startswith("COLAB_GPU_TOKEN=") and token is not None:
            new_lines.append(f"COLAB_GPU_TOKEN={token}\n")
            found_token = True
        else:
            new_lines.append(line)

    if not found_url:
        new_lines.append(f"COLAB_GPU_ENDPOINT={clean_url}\n")
    if token is not None and not found_token:
        new_lines.append(f"COLAB_GPU_TOKEN={token}\n")

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    if os.name == "posix":
        os.chmod(env_path, 0o600)
    print(f"[+] Updated .env with COLAB_GPU_ENDPOINT={clean_url}")


def update_mcp_config(base_url: str, token: Optional[str] = None, update_global: bool = False) -> None:
    clean_url = base_url.rstrip("/")
    sse_url = f"{clean_url}/sse"

    server_entry = {
        "url": sse_url,
        "transport": "sse",
    }
    if token:
        server_entry["headers"] = {"Authorization": f"Bearer {token}"}

    # 1. Workspace .antigravity/mcp.json
    target_dir = os.path.join(os.getcwd(), ".antigravity")
    os.makedirs(target_dir, exist_ok=True)
    mcp_file = os.path.join(target_dir, "mcp.json")

    data = {"mcpServers": {}}
    if os.path.exists(mcp_file):
        try:
            with open(mcp_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"mcpServers": {}}

    data.setdefault("mcpServers", {})["colab-t4-gpu"] = server_entry

    with open(mcp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    if os.name == "posix":
        os.chmod(mcp_file, 0o600)
    print(f"[+] Configured workspace MCP bridge: {mcp_file}")

    # 2. Global config only when explicitly requested via --global-mcp
    if update_global:
        user_home = os.path.expanduser("~")
        global_mcp_path = os.path.join(user_home, ".gemini", "antigravity-ide", "mcp_config.json")
        if os.path.exists(os.path.dirname(global_mcp_path)):
            try:
                gdata = {"mcpServers": {}}
                if os.path.exists(global_mcp_path):
                    with open(global_mcp_path, "r", encoding="utf-8") as gf:
                        gdata = json.load(gf)
                gdata.setdefault("mcpServers", {})["colab-t4-gpu"] = server_entry
                with open(global_mcp_path, "w", encoding="utf-8") as gf:
                    json.dump(gdata, gf, indent=2)
                print(f"[+] Configured global Antigravity MCP bridge: {global_mcp_path}")
            except Exception as ex:
                print(f"[!] Note: Global MCP config update skipped: {ex}")


def main():
    parser = argparse.ArgumentParser(description="Connect local Antigravity environment to Colab T4 GPU")
    parser.add_argument("--url", type=str, help="Cloudflare tunnel URL (e.g. https://xxx.trycloudflare.com)")
    parser.add_argument("--token", type=str, default=None, help="Bearer token generated by Colab server")
    parser.add_argument("--allow-insecure-http", action="store_true", help="Allow cleartext http:// endpoints (for local testing only)")
    parser.add_argument("--global-mcp", action="store_true", help="Also update global ~/.gemini/antigravity-ide/mcp_config.json")
    args = parser.parse_args()

    raw_url = args.url
    if not raw_url:
        raw_url = input("Enter Colab Cloudflare URL: ").strip()

    try:
        url = validate_endpoint_url(raw_url, allow_http=args.allow_insecure_http)
    except ValueError as exc:
        sys.exit(f"[FAIL] Invalid endpoint URL: {exc}")

    token = args.token or os.environ.get("COLAB_GPU_TOKEN")

    if check_health(url, token=token):
        update_env(url, token=token)
        update_mcp_config(url, token=token, update_global=args.global_mcp)
        print("\n[SUCCESS] Colab T4 GPU Bridge fully connected!")
        print("You can now run tasks remotely using `gpu_client.py` or Antigravity MCP tools.")
    else:
        print("\n[FAIL] Connection test failed. Verify the Colab notebook is running and the Bearer token is valid.")


if __name__ == "__main__":
    main()
