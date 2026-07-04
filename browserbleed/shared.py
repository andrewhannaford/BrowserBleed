"""
Shared constants and utility functions for BrowserBleed across all platforms.
"""

import re
from datetime import datetime, timedelta, timezone

# ── Memory scraping patterns ───────────────────────────────────────────────────
CREDENTIAL_PATTERNS: dict[str, re.Pattern] = {
    "JWT token":           re.compile(rb"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    "Bearer token":        re.compile(rb"(?i)Bearer\s+[A-Za-z0-9\-._~+/]{20,}"),
    "Authorization header":re.compile(rb"Authorization:\s*[A-Za-z]+\s+[A-Za-z0-9\-._~+/=]{20,}"),
    "Cookie header":       re.compile(rb"Cookie:\s*[\x20-\x7e]{40,512}"),
    "Set-Cookie header":   re.compile(rb"Set-Cookie:\s*[\x20-\x7e]{20,512}"),
    "OAuth access_token":  re.compile(rb"(?i)access_?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=]{20,256})(?=[\"'\s\x00&,;:\r\n]|$)"),
    "OAuth refresh_token": re.compile(rb"(?i)refresh_?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=]{20,256})(?=[\"'\s\x00&,;:\r\n]|$)"),
    "Session token":       re.compile(rb"(?i)session[_-]?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=%]{20,256})"),
    "Session ID":          re.compile(rb"(?i)session[_-]?id[\"'\s]*[=:][\"'\s]*([A-Fa-f0-9\-]{16,128})"),
    "Password (POST body)":re.compile(rb"(?im)(?:^|&|\?)password=([A-Za-z0-9!@#$%^&*()\-_+=,.?:;~]{8,128})(?:&|$|\s|\x00)"),
    "Password (JSON/API)": re.compile(rb'(?i)"password"\s*:\s*"([A-Za-z0-9!@#$%^&*()\-_+=,.?:;~]{8,128})"'),
    "Google SAPISID":      re.compile(rb"SAPISID=[A-Za-z0-9_/\-]{20,}"),
    "Slack token":         re.compile(rb"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    "GitHub token":        re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
    "Discord token":       re.compile(rb"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}"),
    "AWS Access Key":      re.compile(rb"(?<![A-Z0-9])(A(?:KIA|SIA|ROA|IDA)[A-Z0-9]{16})(?![A-Z0-9])"),
    "Stripe key":          re.compile(rb"sk_(?:live|test)_[A-Za-z0-9]{24,}"),
    "npm token":           re.compile(rb"npm_[A-Za-z0-9]{36}"),
    "HuggingFace token":   re.compile(rb"hf_[A-Za-z0-9]{34,}"),
    "Vault token":         re.compile(rb"hvs\.[A-Za-z0-9]{90,}"),
    "Anthropic API key":   re.compile(rb"sk-ant-[A-Za-z0-9\-_]{90,}"),
    "SSH private key":     re.compile(rb"(-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[^-]{100,4096}-----END (?:[A-Z ]+ )?PRIVATE KEY-----)"),
    "Anthropic session":   re.compile(rb"20111[A-Za-z0-9\-_]{20,}"),
    "Session key":         re.compile(rb"(?i)sessionKey[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/]{20,256})"),
    "LinkedIn li_at":      re.compile(rb"li_at=([A-Za-z0-9%._\-]{30,})"),
    "LinkedIn JSESSIONID": re.compile(rb"JSESSIONID=([A-Za-z0-9\-]{32,})"),
    "Twitter auth_token":  re.compile(rb"auth_token=([A-Fa-f0-9]{32,40})"),
    "Sendgrid token":      re.compile(rb"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}"),
    "Slack xoxp":          re.compile(rb"xoxp-[A-Za-z0-9\-]{10,}"),
    "Slack xoxb":          re.compile(rb"xoxb-[A-Za-z0-9\-]{10,}"),
    "OpenAI API key":      re.compile(rb"sk-[A-Za-z0-9]{20,}"),
}

_NOISE_BYTES = re.compile(
    rb'%[a-z]'                       # C format string: %s %d %f
    rb'|\{[a-zA-Z_][a-zA-Z0-9_]*\}' # template placeholder: {token} {pageSize}
    rb'|"type":"string"'             # JSON schema fragment
    rb'|:\s*boolean[,\s]'            # TypeScript type annotation
    rb'|JwkSymKey'                   # 1Password type annotation
    rb'|LoggableString'              # type annotation
    rb'|\(function\s*\('             # minified JS source (not a real credential)
    rb'|\|\|\(\w+=\{\}\)\)'          # minified JS enum pattern
    rb'|[a-z]\.[a-zA-Z]+\.[a-zA-Z]+[Tt]oken'  # JS property chain: x.y.zToken
)

_NOISE_EXACT: frozenset[str] = frozenset([
    "Password=true",
    "password://settings/developers",
])

_HIT_TIER: dict[str, int] = {
    "AWS Access Key": 0, "Anthropic API key": 0, "Anthropic API Key": 0,
    "SSH private key": 0, "SSH Private Key": 0,
    "Stripe key": 0, "Stripe Secret Key": 0,
    "Vault token": 0, "Vault Token": 0,
    "GitHub token": 0, "Slack token": 0, "Discord token": 0,
    "npm token": 0, "npm Token": 0,
    "HuggingFace token": 0, "HuggingFace Token": 0,
    "Password (POST body)": 1, "Password (JSON/API)": 1,
    "JWT token": 1, "Bearer token": 1, "Authorization header": 1,
    "Google SAPISID": 1,
    "OAuth access_token": 1, "OAuth refresh_token": 1,
    "Session token": 1,
    "Session ID": 2, "Cookie header": 2, "Set-Cookie header": 2,
    "Anthropic session": 0,
    "LinkedIn li_at":    0,
    "LinkedIn JSESSIONID": 0,
    "Twitter auth_token": 0,
    "Sendgrid token":    0,
    "Discord token":     0,
    "Slack xoxp":        0,
    "Slack xoxb":        0,
    "Anthropic API key": 0,
    "OpenAI API key":    0,
    "Session key":       1,
}

_QUICK_PREFIXES: tuple[bytes, ...] = (
    b"eyJ",            # JWT
    b"Bearer ",        # Bearer / Authorization headers
    b"Authorization:",  # Specific: Authorization header, not generic Cookie:
    b"access_token", b"refresh_token", b"session_token", b"session_id",
    b"password",
    b"SAPISID=",
    b"xox",            # Slack
    b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_",  # GitHub
    b"sk_live_", b"sk_test_",  # Stripe
    b"npm_",
    b"hf_",            # HuggingFace
    b"hvs.",           # Vault
    b"sk-ant-",        # Anthropic
    b"AKIA", b"ASIA", b"AROA", b"AIDA",  # AWS
    b"-----BEGIN",     # SSH / PEM keys
    b"20111",          # Anthropic session token
    b"li_at=",         # LinkedIn auth cookie
    b"JSESSIONID=",    # LinkedIn / Java sessions
    b"auth_token=",    # Twitter/X auth cookie
    b"SG.",            # SendGrid API key
    b"xoxp-", b"xoxb-", # Slack tokens
    b"sk-",            # Anthropic, OpenAI, etc. keys
    b"sessionKey",     # Anthropic / generic session key
)


def _trunc(val: str, n: int = 80) -> str:
    return val[:n] + "…" if len(val) > n else val


def _has_credential_hint(data: bytes) -> bool:
    return any(p in data for p in _QUICK_PREFIXES)


def _is_noise(raw: bytes, decoded: str) -> bool:
    """Return True if this match is a known false positive."""
    if decoded.strip() in _NOISE_EXACT:
        return True
    if _NOISE_BYTES.search(raw):
        return True
    return False


def _parse_cookies_from_header(cookie_header: str) -> list[tuple[str, str]]:
    """
    Parse individual cookies from a Cookie/Set-Cookie header value.
    Returns list of (name, value) tuples.
    """
    cookies = []
    parts = cookie_header.split(";")
    for part in parts:
        part = part.strip()
        if "=" in part:
            name, value = part.split("=", 1)
            name = name.strip()
            if name and not name.lower() in ("path", "domain", "expires", "max-age", "secure", "httponly", "samesite"):
                cookies.append((name, value.strip()))
    return cookies


def deduplicate(hits: list[dict]) -> list[dict]:
    """Two-pass dedup: group by label:value[:50], keep shortest. Also post-process cookies."""
    groups: dict[str, list[dict]] = {}
    for h in hits:
        key = f"{h['label']}:{h['value'][:50]}"
        groups.setdefault(key, []).append(h)
    result = [min(g, key=lambda h: len(h["value"])) for g in groups.values()]

    by_label: dict[str, list[dict]] = {}
    for h in result:
        by_label.setdefault(h["label"], []).append(h)

    final: list[dict] = []
    for label, group in by_label.items():
        group.sort(key=lambda h: len(h["value"]))
        kept: list[dict] = []
        for h in group:
            v = h["value"]
            upgraded = False
            for i, k in enumerate(kept):
                if len(k["value"]) >= 20 and v.startswith(k["value"]):
                    kept[i] = h
                    upgraded = True
                    break
            if not upgraded:
                kept.append(h)
        final.extend(kept)

    final.sort(key=lambda h: int(h["address"], 16))

    # Post-process Cookie headers to extract individual cookies
    expanded: list[dict] = []
    for h in final:
        if h["label"] in ("Cookie header", "Set-Cookie header"):
            try:
                cookies = _parse_cookies_from_header(h["value"])
                for name, value in cookies:
                    expanded.append({
                        **h,
                        "label": f"Cookie ({name})",
                        "value": f"{name}={value}",
                    })
            except Exception:
                expanded.append(h)
        else:
            expanded.append(h)

    return expanded


def chrome_epoch_to_str(us: int) -> str:
    if not us:
        return "session"
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(us)


def unix_ts_to_str(ts: float) -> str:
    if ts <= 0:
        return "session"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _get_domain_from_service(service: str) -> str:
    """Extract domain from service name."""
    service_domains = {
        "Google": ".google.com",
        "GitHub": ".github.com",
        "LinkedIn": ".linkedin.com",
        "AWS": ".aws.amazon.com",
        "Anthropic": ".claude.ai",
        "Discord": ".discord.com",
        "Slack": ".slack.com",
    }
    for key, domain in service_domains.items():
        if key.lower() in service.lower():
            return domain
    parts = service.split()
    if parts:
        return f".{parts[0].lower()}.com"
    return ""
