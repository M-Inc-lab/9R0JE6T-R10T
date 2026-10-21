import os
import sys
import json
import time
import argparse
import urllib.request
import urllib.error

def check_health(base_url: str):
    health_url = f"{base_url.rstrip('/')}/health"
    print(f"[*] Pinging {health_url}...")
    start_time = time.time()
    try:
        req = urllib.request.Request(health_url, headers={"User-Agent": "Antigravity-Client/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            latency = round((time.time() - start_time) * 1000, 2)
            data = json.loads(response.read().decode())
            print(f"[+] Server responding! Latency: {latency}ms")
            print(f"[+] Remote Status: {json.dumps(data, indent=2)}")
            return True
    except Exception as e:
        print(f"[-] Health check failed: {e}")
        return False

def update_env(base_url: str):
    env_path = os.path.join(os.getcwd(), ".env")
    clean_url = base_url.rstrip('/')
    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    
    found = False
    new_lines = []
    for line in lines:
        if line.startswith("COLAB_GPU_ENDPOINT="):
            new_lines.append(f"COLAB_GPU_ENDPOINT={clean_url}\n")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"COLAB_GPU_ENDPOINT={clean_url}\n")
    
    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    print(f"[+] Updated .env with COLAB_GPU_ENDPOINT={clean_url}")

def update_mcp_config(base_url: str):
    clean_url = base_url.rstrip('/')
    sse_url = f"{clean_url}/sse"
    
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
    
    data.setdefault("mcpServers", {})["colab-t4-gpu"] = {
        "url": sse_url,
        "transport": "sse"
    }
    
    with open(mcp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Configured workspace MCP bridge: {mcp_file}")
    
    # 2. Antigravity IDE global config if accessible
    user_home = os.path.expanduser("~")
    global_mcp_path = os.path.join(user_home, ".gemini", "antigravity-ide", "mcp_config.json")
    if os.path.exists(os.path.dirname(global_mcp_path)):
        try:
            gdata = {"mcpServers": {}}
            if os.path.exists(global_mcp_path):
                with open(global_mcp_path, "r", encoding="utf-8") as gf:
                    gdata = json.load(gf)
            gdata.setdefault("mcpServers", {})["colab-t4-gpu"] = {
                "url": sse_url,
                "transport": "sse"
            }
            with open(global_mcp_path, "w", encoding="utf-8") as gf:
                json.dump(gdata, gf, indent=2)
            print(f"[+] Configured global Antigravity MCP bridge: {global_mcp_path}")
        except Exception as ex:
            print(f"[!] Note: Global MCP config update skipped: {ex}")

def main():
    parser = argparse.ArgumentParser(description="Connect local Antigravity environment to Colab T4 GPU")
    parser.add_argument("--url", type=str, help="Cloudflare tunnel URL (e.g. https://xxx.trycloudflare.com)")
    args = parser.parse_args()

    url = args.url
    if not url:
        url = input("Enter Colab Cloudflare URL: ").strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    if check_health(url):
        update_env(url)
        update_mcp_config(url)
        print("\n[SUCCESS] Colab T4 GPU Bridge fully connected!")
        print("You can now run tasks remotely using `gpu_client.py` or Antigravity MCP tools.")
    else:
        print("\n[FAIL] Connection test failed. Make sure the Colab notebook is actively running.")

if __name__ == "__main__":
    main()
