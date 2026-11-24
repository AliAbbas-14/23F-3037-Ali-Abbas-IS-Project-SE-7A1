import subprocess
import sys
import time
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
venv_python = ROOT / ".venv" / "Scripts" / "python.exe"
if not venv_python.exists():
    venv_python = Path(sys.executable)

# 1. Start uvicorn server binding to 0.0.0.0 so all loopbacks work
env = dict(**dict(subprocess.os.environ))
env["VAULTGUARD_HOST"] = "0.0.0.0"
env["VAULTGUARD_PORT"] = "8000"

server_proc = subprocess.Popen(
    [str(venv_python), "run_server.py"],
    cwd=str(ROOT),
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

time.sleep(3)

# Verify local server is responding
try:
    with urllib.request.urlopen("http://127.0.0.1:8000/login", timeout=5) as resp:
        print(f"Local server verified running! Status: {resp.status}")
except Exception as e:
    print(f"Local server check failed: {e}")

# 2. Start ssh tunnel forwarding to 127.0.0.1:8000
tunnel_proc = subprocess.Popen(
    ["ssh", "-o", "StrictHostKeyChecking=no", "-R", "80:127.0.0.1:8000", "nokey@localhost.run"],
    cwd=str(ROOT),
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

url_found = None
url_file = ROOT / "live_website_url.txt"

print("Waiting for live tunnel URL from localhost.run...")
for line in iter(tunnel_proc.stdout.readline, ''):
    print(line, end='', flush=True)
    match = re.search(r'(https://[a-zA-Z0-9.-]+\.lhr\.life)', line)
    if match:
        url_found = match.group(1)
        url_file.write_text(url_found)
        print("\n" + "="*50)
        print(f"DEPLOYED LIVE WEBSITE LINK: {url_found}")
        print("="*50 + "\n", flush=True)
        break

# Keep both running
try:
    while True:
        time.sleep(1)
        if server_proc.poll() is not None or tunnel_proc.poll() is not None:
            break
except KeyboardInterrupt:
    server_proc.terminate()
    tunnel_proc.terminate()
