"""
Browser Session Manager — Open authenticated sessions for valid credentials
"""

import os
import sys
import time
import json
from typing import Optional, Dict, List, TYPE_CHECKING
from urllib.parse import urljoin

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    webdriver = None  # type: ignore

if TYPE_CHECKING:
    from selenium.webdriver import Chrome


# Service login URLs
SERVICE_URLS = {
    "GitHub": "https://github.com",
    "Google": "https://google.com",
    "Anthropic": "https://claude.ai",
    "OpenAI": "https://openai.com",
    "Slack": "https://slack.com/workspace-signin",
    "Discord": "https://discord.com/app",
    "AWS": "https://console.aws.amazon.com",
    "Stripe": "https://dashboard.stripe.com",
    "HuggingFace": "https://huggingface.co",
    "Spotify": "https://open.spotify.com",
    "LinkedIn": "https://linkedin.com/feed",
    "Twitter": "https://twitter.com/home",
    "Microsoft": "https://office.com",
}

# Cookie configurations per service
COOKIE_CONFIGS = {
    "GitHub": [
        {"name": "logged_in", "domain": ".github.com"},
        {"name": "user_session", "domain": ".github.com"},
    ],
    "LinkedIn": [
        {"name": "li_at", "domain": ".linkedin.com"},
        {"name": "JSESSIONID", "domain": ".linkedin.com"},
    ],
    "Slack": [
        {"name": "d", "domain": ".slack.com"},
    ],
    "Discord": [
        {"name": "authorization", "domain": ".discord.com"},
    ],
    "Google": [
        {"name": "1P_JAR", "domain": ".google.com"},
    ],
    "Anthropic": [
        {"name": "__Secure-next-auth.session-token", "domain": ".claude.ai"},
    ],
}


def open_authenticated_session(
    service: str,
    token_value: str,
    headless: bool = False,
    wait_seconds: int = 0,
    auto_close: bool = False
) -> Optional["Chrome"]:
    """
    Open a browser with an authenticated session for a service.

    Args:
        service: Service name (e.g., "GitHub", "LinkedIn")
        token_value: The credential/token/cookie value
        headless: Run browser in headless mode (default: False - show window)
        wait_seconds: Seconds to wait before closing (0 = keep open indefinitely)
        auto_close: Auto-close after wait_seconds (default: False - keep open)

    Returns:
        WebDriver instance if successful, None otherwise.
        Browser stays open for manual interaction unless auto_close=True.
    """
    if not SELENIUM_AVAILABLE:
        print(f"  [!] Selenium not installed. Install with: pip install selenium")
        return None

    service_url = SERVICE_URLS.get(service, f"https://{service.lower()}.com")
    cookies = COOKIE_CONFIGS.get(service, [])

    if not cookies:
        print(f"  [!] No cookie config for {service}")
        return None

    try:
        # Setup Chrome options
        options = Options()
        if headless:
            options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")

        # Create driver
        driver = webdriver.Chrome(options=options)

        # Navigate to service first (to set domain)
        driver.get(service_url)
        time.sleep(1)

        # Inject cookie(s)
        for cookie_config in cookies:
            cookie = {
                "name": cookie_config["name"],
                "value": token_value,
                "domain": cookie_config["domain"],
                "path": "/",
                "secure": True,
                "httpOnly": True,
            }
            try:
                driver.add_cookie(cookie)
            except Exception as e:
                print(f"    Warning: Failed to set {cookie_config['name']}: {e}")

        # Refresh to apply cookies
        driver.refresh()
        time.sleep(2)

        # Verify we're actually authenticated by checking if redirect happened
        current_url = driver.current_url
        if "login" in current_url.lower() or "signin" in current_url.lower():
            print(f"  [✗] Still at login page - cookie may not be valid: {current_url}")
            driver.quit()
            return None

        print(f"  [✓] Authenticated {service} session opened")
        print(f"      URL: {current_url}")
        print(f"      Browser is open for interaction. Close manually or call driver.quit()")

        # Auto-close if requested, otherwise keep open
        if auto_close and wait_seconds > 0:
            print(f"      Auto-closing in {wait_seconds} seconds...")
            time.sleep(wait_seconds)
            driver.quit()
            return None
        else:
            return driver

    except Exception as e:
        print(f"  [!] Failed to open {service} session: {e}")
        return None


def open_sessions_for_results(results: List[Dict], keep_open: bool = False) -> List:
    """
    Open browser sessions for all valid credentials from sessiontest results.

    Args:
        results: List of Result objects from sessiontest
        keep_open: Keep browsers open (True) or close after 5 seconds (False)

    Returns:
        List of open WebDriver instances
    """
    if not SELENIUM_AVAILABLE:
        print("[!] Selenium required. Install with: pip install selenium")
        return []

    drivers = []
    valid_count = 0

    for result in results:
        if result.status == "valid":
            wait = 0 if keep_open else 5
            driver = open_authenticated_session(
                result.service,
                result.value,
                headless=False,
                wait_seconds=wait
            )
            if driver:
                drivers.append((result.service, driver))
                valid_count += 1

    if valid_count > 0 and keep_open:
        print(f"\n[+] {valid_count} authenticated session(s) opened. Press Ctrl+C to close all.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Closing sessions...")
            for service, driver in drivers:
                driver.quit()
                print(f"  [-] Closed {service}")

    return drivers


if __name__ == "__main__":
    print("Browser Session Manager\n"
          "Usage: from browser_sessions import open_authenticated_session\n"
          "       open_authenticated_session('GitHub', 'ghp_token_value')")
