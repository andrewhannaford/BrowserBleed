#!/usr/bin/env python3
"""
Extract complete browser session including cookies and storage.
Use this while Chrome is open with Claude.ai loaded.
"""

import json
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def extract_storage_from_current_chrome():
    """Connect to existing Chrome and extract localStorage/sessionStorage."""

    print("Connecting to existing Chrome instance...")

    # Connect to existing Chrome DevTools instance
    options = Options()
    options.add_experimental_option("debuggerAddress", "127.0.0.1:9222")

    try:
        driver = webdriver.Chrome(options=options)
    except:
        print("Could not connect to existing Chrome. Make sure Chrome is running with --remote-debugging-port=9222")
        return None

    # Get current cookies
    print("Extracting cookies...")
    cookies = driver.get_cookies()

    # Extract localStorage and sessionStorage from claude.ai
    print("Extracting localStorage/sessionStorage...")

    # Navigate to claude.ai to extract its storage
    driver.get("https://claude.ai")
    time.sleep(2)

    storage_data = {
        "localStorage": {},
        "sessionStorage": {},
        "cookies": cookies
    }

    # Extract localStorage for claude.ai
    try:
        local_storage = driver.execute_script("""
            const items = {};
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                items[key] = localStorage.getItem(key);
            }
            return items;
        """)
        storage_data["localStorage"][".claude.ai"] = local_storage
        print(f"  ✓ Extracted {len(local_storage)} localStorage items")
    except Exception as e:
        print(f"  Warning: Could not extract localStorage: {e}")

    # Extract sessionStorage for claude.ai
    try:
        session_storage = driver.execute_script("""
            const items = {};
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                items[key] = sessionStorage.getItem(key);
            }
            return items;
        """)
        storage_data["sessionStorage"][".claude.ai"] = session_storage
        print(f"  ✓ Extracted {len(session_storage)} sessionStorage items")
    except Exception as e:
        print(f"  Warning: Could not extract sessionStorage: {e}")

    return storage_data, driver


def save_session_data(storage_data, cookies_file="claude_full_session.json"):
    """Save complete session data to file."""

    with open(cookies_file, "w") as f:
        json.dump(storage_data, f, indent=2)

    print(f"\n✅ Complete session saved to: {cookies_file}")
    print(f"   - Cookies: {len(storage_data['cookies'])}")
    print(f"   - localStorage items: {sum(len(v) for v in storage_data['localStorage'].values())}")
    print(f"   - sessionStorage items: {sum(len(v) for v in storage_data['sessionStorage'].values())}")


if __name__ == "__main__":
    import sys

    # Extract from current Chrome
    result = extract_storage_from_current_chrome()

    if result:
        storage_data, driver = result
        save_session_data(storage_data)
        driver.quit()
    else:
        print("❌ Failed to extract session")
        sys.exit(1)
