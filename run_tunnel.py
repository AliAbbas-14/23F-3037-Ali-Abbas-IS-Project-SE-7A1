import subprocess
import sys
import time
import re
import os
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
venv_python = ROOT / ".venv" / "Scripts" / "python.exe"

# 1. Start server
env = dict(os.environ)
env["VAULTGUARD_HOST"] = "0.0.0.0"
env["VAULTGUARD_PORT"] = "8000"

print("Starting server...")
server = subprocess.Popen(
    [str(venv_python), "run_server.py"],
    cwd=str(ROOT),
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

# Wait until local server responds
time.sleep(2)
for attempt in range(10):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/login", timeout=2) as r:
            if r.status == 200:
                print("Server is UP and ready on port 8000!")
                break
    except Exception:
        time.sleep(1)

# 2. Start SSH tunnel using direct IP (no DNS failure)
print("Starting tunnel to 54.161.197.247...")
tunnel = subprocess.Popen(
    [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "ServerAliveInterval=15",
        "-R", "80:127.0.0.1:8000",
        "nokey@54.161.197.247"
    ],
    cwd=str(ROOT),
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

url = None
for line in iter(tunnel.stdout.readline, ''):
    print(line, end='', flush=True)
    m = re.search(r'(https://[a-zA-Z0-9.-]+\.lhr\.life)', line)
    if m:
        url = m.group(1)
        print("\n" + "="*60)
        print(f"DEPLOYED LIVE URL: {url}")
        print("="*60 + "\n", flush=True)
        break

time.sleep(2)
if url:
    try:
        req = urllib.request.Request(f"{url}/login", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f"Verified live public endpoint! HTTP Status: {r.status}")
    except Exception as e:
        print(f"Public endpoint test error: {e}")

# Keep both running
while True:
    time.sleep(1)
