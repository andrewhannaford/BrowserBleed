"""
BrowserBleed macOS - unit tests.

Tests all pure-Python logic: crypto, regex patterns, deduplication, noise
filtering, service identification, and context-based domain scanning.
No macOS required - the Mach API is never called here.

Run:
    python -m pytest test_browserbleed_mac.py -v
    python test_browserbleed_mac.py
"""

import sys
import os
import json
import base64
import unittest
from unittest.mock import patch

# ── Import module under test ───────────────────────────────────────────────────
# BrowserBleed_mac.py guards the CDLL load behind sys.platform == "darwin",
# so it imports cleanly on any platform - no mocking needed.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import BrowserBleed_mac as bb

# Detect whether the cryptography package is available
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ── Helpers ────────────────────────────────────────────────────────────────────
def _make_jwt(payload: dict, header: dict | None = None) -> str:
    """Build a JWT string (unsigned) from header and payload dicts."""
    h = header or {"alg": "HS256", "typ": "JWT"}
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc(h)}.{enc(payload)}.fakesignature"


def _aes_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt using AES-128-CBC with the Chrome macOS IV (16 spaces)."""
    iv      = b" " * 16
    pad_len = 16 - (len(plaintext) % 16)
    padded  = plaintext + bytes([pad_len] * pad_len)
    cipher  = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc     = cipher.encryptor()
    return b"v10" + enc.update(padded) + enc.finalize()


# ══════════════════════════════════════════════════════════════════════════════
# Noise filter
# ══════════════════════════════════════════════════════════════════════════════
class TestNoiseFilter(unittest.TestCase):

    def test_format_string_is_noise(self):
        self.assertTrue(bb._is_noise(b"session_id: %s", "session_id: %s"))

    def test_template_placeholder_is_noise(self):
        self.assertTrue(bb._is_noise(b'session_token: {token}', 'session_token: {token}'))

    def test_type_string_is_noise(self):
        self.assertTrue(bb._is_noise(b'"type":"string"', '"type":"string"'))

    def test_boolean_type_annotation_is_noise(self):
        self.assertTrue(bb._is_noise(b': boolean,', ': boolean,'))

    def test_js_property_chain_is_noise(self):
        self.assertTrue(bb._is_noise(b't.content.accessToken', 't.content.accessToken'))

    def test_jwk_sym_key_is_noise(self):
        self.assertTrue(bb._is_noise(b'JwkSymKey', 'JwkSymKey'))

    def test_exact_noise_entry(self):
        self.assertTrue(bb._is_noise(b'Password=true', 'Password=true'))

    def test_valid_jwt_not_noise(self):
        jwt = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        self.assertFalse(bb._is_noise(jwt, jwt.decode()))

    def test_valid_bearer_not_noise(self):
        raw = b'Bearer ya29.a0AT3oNZ9WpegYkueVZ7Fv_gUUYKnvtWzcnKqprTn5Ob-4q008'
        self.assertFalse(bb._is_noise(raw, raw.decode()))

    def test_valid_session_token_not_noise(self):
        raw = b'session_token="20111GDqECYuMQ-Vhciczs3T-mwadEQ7KN5oKjEfm1ec6"'
        self.assertFalse(bb._is_noise(raw, raw.decode()))


# ══════════════════════════════════════════════════════════════════════════════
# Credential patterns
# ══════════════════════════════════════════════════════════════════════════════
class TestCredentialPatterns(unittest.TestCase):

    def test_jwt_pattern_matches(self):
        jwt = b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        self.assertIsNotNone(bb.CREDENTIAL_PATTERNS["JWT token"].search(jwt))

    def test_jwt_pattern_too_short(self):
        self.assertIsNone(bb.CREDENTIAL_PATTERNS["JWT token"].search(b'eyJhbGci.eyJzdWI.sig'))

    def test_bearer_pattern_matches(self):
        data = b'Authorization: Bearer ya29.a0AT3oNZ9WpegYkueVZ7Fv_gUUYKnvtWzcnKqprTn5Ob'
        self.assertIsNotNone(bb.CREDENTIAL_PATTERNS["Bearer token"].search(data))

    def test_session_token_captures_group(self):
        data = b'session_token="abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"'
        m = bb.CREDENTIAL_PATTERNS["Session token"].search(data)
        self.assertIsNotNone(m)
        self.assertIsNotNone(m.lastindex)
        # Capture group should be just the value, not including the key prefix
        self.assertEqual(m.group(m.lastindex), b'abcdefghijklmnopqrstuvwxyz0123456789ABCDEF')

    def test_session_id_captures_group(self):
        data = b'session_id="7dc87a3d9c83415f83ffd683a9be8cd7"'
        m = bb.CREDENTIAL_PATTERNS["Session ID"].search(data)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(m.lastindex), b'7dc87a3d9c83415f83ffd683a9be8cd7')

    def test_oauth_access_token_captures_group(self):
        data = b'access_token="ya29.a0AT3oNZ9WpegYkueVZ7Fv_gUUYKnvtWzcnKqprTn5Ob"'
        m = bb.CREDENTIAL_PATTERNS["OAuth access_token"].search(data)
        self.assertIsNotNone(m)
        self.assertTrue(m.group(m.lastindex).startswith(b'ya29.'))

    def test_google_sapisid_matches(self):
        data = b'SAPISID=jcVfV5cj6P6PkVGu/APuJltyHrGn3QFg08'
        self.assertIsNotNone(bb.CREDENTIAL_PATTERNS["Google SAPISID"].search(data))

    def test_slack_token_matches(self):
        # Split across concat so secret scanners don't see a contiguous token
        data = b"xoxb-" + b"FAKE0TOKEN0AA-" + b"FAKE0TOKEN0BBBBBBBB"
        self.assertIsNotNone(bb.CREDENTIAL_PATTERNS["Slack token"].search(data))

    def test_github_token_matches(self):
        data = b'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab'
        self.assertIsNotNone(bb.CREDENTIAL_PATTERNS["GitHub token"].search(data))

    def test_discord_token_matches(self):
        # Split across concat so secret scanners don't see a contiguous token
        data = (b"MTIzNDU2Nzg5MDEyMzQ1Njc4" + b"." +
                b"ABCDEF" + b"." + b"ABCDEFGHIJKLMNOPQRSTUVWXYZab")
        self.assertIsNotNone(bb.CREDENTIAL_PATTERNS["Discord token"].search(data))


# ══════════════════════════════════════════════════════════════════════════════
# Deduplication
# ══════════════════════════════════════════════════════════════════════════════
class TestDeduplicate(unittest.TestCase):

    def _hit(self, value: str, dedup_key: str | None = None, addr: str = "0x1000") -> dict:
        return {"label": "Test", "value": value, "dedup_key": dedup_key or value[:120],
                "address": addr, "pid": 1}

    def test_dedup_collapses_same_key(self):
        # deduplicate() groups by label:value[:50].  Use values that share the same
        # first 50 characters so they land in the same group.
        prefix = "A" * 50
        hits = [
            self._hit(prefix,       None, "0x1000"),
            self._hit(prefix + "X", None, "0x2000"),
        ]
        result = bb.deduplicate(hits)
        self.assertEqual(len(result), 1)

    def test_dedup_shortest_wins(self):
        hits = [
            self._hit("abc123def456",    "abc123def", "0x1000"),
            self._hit("abc123def456abc", "abc123def", "0x2000"),
        ]
        result = bb.deduplicate(hits)
        self.assertEqual(result[0]["value"], "abc123def456")

    def test_dedup_different_keys_kept(self):
        hits = [
            self._hit("token_aaa_111111111111111111111", "token_aaa_111111", "0x1000"),
            self._hit("token_bbb_222222222222222222222", "token_bbb_222222", "0x2000"),
        ]
        result = bb.deduplicate(hits)
        self.assertEqual(len(result), 2)

    def test_dedup_sorted_by_address(self):
        hits = [
            self._hit("bbbbbbbbbbbbbbbbbbbbbbbbb", "bbb", "0x3000"),
            self._hit("aaaaaaaaaaaaaaaaaaaaaaaa",  "aaa", "0x1000"),
        ]
        result = bb.deduplicate(hits)
        self.assertEqual(result[0]["address"], "0x1000")
        self.assertEqual(result[1]["address"], "0x3000")

    def test_dedup_empty_input(self):
        self.assertEqual(bb.deduplicate([]), [])

    def test_session_id_rstrip_dash(self):
        hits = [
            self._hit("7dc87a3d9c83415f",   "7dc87a3d9c83415f",  "0x1000"),
            self._hit("7dc87a3d9c83415f2d-", "7dc87a3d9c83415f2d", "0x2000"),
        ]
        # These have different dedup keys - they stay separate (different session IDs)
        result = bb.deduplicate(hits)
        self.assertEqual(len(result), 2)

    def test_session_id_prefix_upgrade_to_longer(self):
        # Pass 2 of dedup: if value A is a prefix of value B (and A ≥ 20 chars),
        # B replaces A.  "7dc87a3d9c83415f83ff" is a prefix of "7dc87a3d9c83415f83ff-"
        # so they collapse to 1 hit and the longer value wins.
        hits = [
            self._hit("7dc87a3d9c83415f83ff",  None, "0x1000"),
            self._hit("7dc87a3d9c83415f83ff-", None, "0x2000"),
        ]
        result = bb.deduplicate(hits)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["value"], "7dc87a3d9c83415f83ff-")


# ══════════════════════════════════════════════════════════════════════════════
# JWT decode
# ══════════════════════════════════════════════════════════════════════════════
class TestDecodeJwtClaims(unittest.TestCase):

    def test_valid_jwt_returns_claims(self):
        payload = {"iss": "https://accounts.google.com", "sub": "12345", "exp": 9999999999}
        token   = _make_jwt(payload)
        claims  = bb._decode_jwt_claims(token)
        self.assertEqual(claims["iss"], "https://accounts.google.com")
        self.assertEqual(claims["exp"], 9999999999)

    def test_malformed_returns_empty(self):
        self.assertEqual(bb._decode_jwt_claims("not.a.jwt.with.too.many.parts"), {})

    def test_invalid_base64_returns_empty(self):
        self.assertEqual(bb._decode_jwt_claims("header.!!!bad!!!.sig"), {})

    def test_two_part_returns_empty(self):
        self.assertEqual(bb._decode_jwt_claims("only.twoparts"), {})

    def test_urlsafe_base64_padding(self):
        # Payload length not a multiple of 4 - padding must be added
        payload = {"k": "v" * 5}  # produces b64 that needs padding
        token   = _make_jwt(payload)
        claims  = bb._decode_jwt_claims(token)
        self.assertIn("k", claims)


# ══════════════════════════════════════════════════════════════════════════════
# Domain matching
# ══════════════════════════════════════════════════════════════════════════════
class TestDomainMatches(unittest.TestCase):

    def test_exact_match(self):
        self.assertTrue(bb._domain_matches("slack.com", "slack.com"))

    def test_subdomain_match(self):
        self.assertTrue(bb._domain_matches("slack.com", "api.slack.com"))

    def test_deep_subdomain(self):
        self.assertTrue(bb._domain_matches("google.com", "accounts.google.com"))

    def test_no_false_positive_suffix(self):
        # "noslack.com" must NOT match "slack.com"
        self.assertFalse(bb._domain_matches("slack.com", "noslack.com"))

    def test_no_false_positive_prefix(self):
        self.assertFalse(bb._domain_matches("github.com", "notgithub.com"))

    def test_prefix_frag_no_dot(self):
        # "cognito-idp" has no dot - match as startswith
        self.assertTrue(bb._domain_matches("cognito-idp", "cognito-idp.us-east-1.amazonaws.com"))

    def test_prefix_frag_exact(self):
        self.assertTrue(bb._domain_matches("cognito-idp", "cognito-idp"))


# ══════════════════════════════════════════════════════════════════════════════
# Context-based service detection
# ══════════════════════════════════════════════════════════════════════════════
class TestServiceFromContext(unittest.TestCase):

    def test_url_in_context(self):
        ctx = b'POST https://api.github.com/repos/user/repo HTTP/1.1'
        self.assertEqual(bb._service_from_context(ctx), "GitHub")

    def test_host_header(self):
        ctx = b'GET /auth/session HTTP/1.1\r\nHost: claude.ai\r\nCookie: session=xxx'
        self.assertEqual(bb._service_from_context(ctx), "Anthropic / Claude")

    def test_cookie_domain_attribute(self):
        ctx = b'Set-Cookie: _ga=GA1.2; Domain=.google.com; Path=/'
        self.assertEqual(bb._service_from_context(ctx), "Google")

    def test_json_iss_field(self):
        ctx = b'{"iss":"accounts.google.com","sub":"12345","exp":9999999999}'
        self.assertEqual(bb._service_from_context(ctx), "Google Accounts")

    def test_json_domain_field(self):
        ctx = b'{"domain":"api.slack.com","path":"/api/auth.test"}'
        self.assertEqual(bb._service_from_context(ctx), "Slack")

    def test_anthropic_api_url(self):
        ctx = b'POST https://api.anthropic.com/v1/messages HTTP/1.1\r\nAuthorization: Bearer sk-ant-xxx'
        self.assertEqual(bb._service_from_context(ctx), "Anthropic / Claude")

    def test_microsoft_login_url(self):
        ctx = b'https://login.microsoftonline.com/tenant/oauth2/v2.0/token'
        self.assertEqual(bb._service_from_context(ctx), "Microsoft / Azure AD")

    def test_cognito_url(self):
        ctx = b'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123'
        self.assertEqual(bb._service_from_context(ctx), "AWS Cognito")

    def test_stripe_host_header(self):
        ctx = b'POST /v1/charges HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer sk-live-xxx'
        self.assertEqual(bb._service_from_context(ctx), "Stripe")

    def test_no_domain_returns_none(self):
        ctx = b'some random binary bytes without any recognizable domains'
        self.assertIsNone(bb._service_from_context(ctx))

    def test_empty_context_returns_none(self):
        self.assertIsNone(bb._service_from_context(b""))

    def test_localhost_ignored(self):
        # localhost doesn't match any service
        ctx = b'Host: localhost:9222\r\nContent-Type: application/json'
        self.assertIsNone(bb._service_from_context(ctx))


# ══════════════════════════════════════════════════════════════════════════════
# Service identification (integrated)
# ══════════════════════════════════════════════════════════════════════════════
class TestIdentifyService(unittest.TestCase):

    def test_google_oauth_ya29(self):
        result = bb.identify_service("Bearer token", "ya29.a0AT3oNZ9WpegYkueVZ7Fv")
        self.assertEqual(result, "Google OAuth2")

    def test_bearer_prefix_stripped(self):
        result = bb.identify_service("Bearer token", "Bearer ya29.a0AT3oNZ9WpegYkueVZ7Fv")
        self.assertEqual(result, "Google OAuth2")

    def test_github_personal_token(self):
        result = bb.identify_service("GitHub token", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
        self.assertEqual(result, "GitHub (personal)")

    def test_github_oauth_token(self):
        result = bb.identify_service("GitHub token", "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
        self.assertEqual(result, "GitHub (OAuth app)")

    def test_slack_bot_token(self):
        # Split across concat so secret scanners don't see a contiguous token
        tok = "xoxb-" + "FAKE0TOKEN-" + "FAKE0VALUEFAKE0VALUEFAKE"
        result = bb.identify_service("Slack token", tok)
        self.assertEqual(result, "Slack (bot token)")

    def test_openai_sk(self):
        result = bb.identify_service("Bearer token", "sk-proj-abc123defgh456ijklmno789pqrstu")
        self.assertEqual(result, "OpenAI")

    def test_anthropic_session_token(self):
        result = bb.identify_service("Session token", "20111GDqECYuMQ-Vhciczs3T-mwadEQ7KN5oKjEfm1ec6")
        self.assertEqual(result, "Anthropic / Claude")

    def test_google_sapisid_label(self):
        result = bb.identify_service("Google SAPISID", "SAPISID=jcVfV5cj6P6PkVGu/APuJltyHrGn3QFg08")
        self.assertEqual(result, "Google (YouTube / Gmail)")

    def test_discord_label(self):
        result = bb.identify_service("Discord token", "MTIzNDU2Nzg5MDEyMzQ1Njc4.ABCDEF.xxx")
        self.assertEqual(result, "Discord")

    def test_jwt_google_issuer(self):
        token  = _make_jwt({"iss": "https://accounts.google.com", "sub": "123"})
        result = bb.identify_service("JWT token", token)
        self.assertIn("Google", result)

    def test_jwt_github_issuer(self):
        token  = _make_jwt({"iss": "github.com", "aud": "release-assets.githubusercontent.com"})
        result = bb.identify_service("JWT token", token)
        self.assertIn("GitHub", result)

    def test_jwt_unknown_issuer_context_fallback(self):
        token = _make_jwt({"sub": "user123", "exp": 9999999999})  # no iss
        ctx   = b'Host: api.anthropic.com\r\nAuthorization: Bearer sk-ant-xxx'
        result = bb.identify_service("JWT token", token, ctx)
        self.assertIn("Anthropic", result)

    def test_jwt_redirect_uri_claim_fallback(self):
        # No iss, but redirect_uri contains a known domain
        token  = _make_jwt({"api": "user_management", "redirect_uri": "https://ollama.com/auth/callback"})
        result = bb.identify_service("JWT token", token)
        self.assertIn("Ollama", result)

    def test_jwt_redirect_uri_unknown_domain_reported(self):
        # Unknown domain in redirect_uri - should still report the host rather than "unknown issuer"
        token  = _make_jwt({"redirect_uri": "https://authkit.cline.bot/callback"})
        result = bb.identify_service("JWT token", token)
        self.assertIn("cline.bot", result)
        self.assertNotEqual(result, "JWT - unknown issuer")

    def test_context_fallback_session_id(self):
        ctx    = b'POST /api/auth/session HTTP/1.1\r\nHost: api.github.com'
        result = bb.identify_service("Session ID", "7dc87a3d9c83415f83ff", ctx)
        self.assertEqual(result, "GitHub")

    def test_unknown_service_no_context(self):
        result = bb.identify_service("Session ID", "7dc87a3d9c83415f83ffd683a9be8cd7")
        self.assertEqual(result, "Unknown service")


# ══════════════════════════════════════════════════════════════════════════════
# Chrome epoch conversion
# ══════════════════════════════════════════════════════════════════════════════
class TestChromeEpoch(unittest.TestCase):

    def test_zero_is_session(self):
        self.assertEqual(bb.chrome_epoch_to_str(0), "session")

    def test_known_date(self):
        from datetime import datetime, timezone, timedelta
        target = datetime(2024, 1, 1, tzinfo=timezone.utc)
        epoch  = datetime(1601, 1, 1, tzinfo=timezone.utc)
        us     = int((target - epoch).total_seconds() * 1_000_000)
        self.assertEqual(bb.chrome_epoch_to_str(us), "2024-01-01 00:00:00 UTC")

    def test_negative_returns_session(self):
        # Negative values should not crash
        result = bb.chrome_epoch_to_str(-1)
        self.assertIsInstance(result, str)


# ══════════════════════════════════════════════════════════════════════════════
# Crypto (AES-128-CBC / PBKDF2) - requires cryptography package
# ══════════════════════════════════════════════════════════════════════════════
@unittest.skipUnless(HAS_CRYPTO, "cryptography package not installed")
class TestCrypto(unittest.TestCase):

    def test_decrypt_v10_roundtrip(self):
        key       = b"\x01" * 16
        plaintext = "correct horse battery staple"
        encrypted = _aes_cbc_encrypt(key, plaintext.encode())
        self.assertEqual(bb.decrypt_value(key, encrypted), plaintext)

    def test_decrypt_unicode_roundtrip(self):
        key       = b"\xAB" * 16
        plaintext = "p@ssw0rd!£€¥"
        encrypted = _aes_cbc_encrypt(key, plaintext.encode("utf-8"))
        self.assertEqual(bb.decrypt_value(key, encrypted), plaintext)

    def test_decrypt_empty_returns_empty(self):
        self.assertEqual(bb.decrypt_value(b"\x00" * 16, b""), "")

    def test_decrypt_non_v10_returns_plaintext(self):
        # Data without v10 prefix is treated as raw UTF-8
        self.assertEqual(bb.decrypt_value(b"\x00" * 16, b"plaintext_value"), "plaintext_value")

    def test_decrypt_wrong_key_returns_error_string(self):
        key1 = b"\x01" * 16
        key2 = b"\x02" * 16
        encrypted = _aes_cbc_encrypt(key1, b"secret")
        result = bb.decrypt_value(key2, encrypted)
        # Should not raise; returns an error string or garbage, not "secret"
        self.assertIsInstance(result, str)
        self.assertNotEqual(result, "secret")

    def test_pbkdf2_key_derivation(self):
        """get_master_key must use PBKDF2-HMAC-SHA1, 1003 iterations, salt=saltysalt, 16 bytes."""
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        password = b"peanuts"
        kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=16, salt=b"saltysalt",
                         iterations=1003, backend=default_backend())
        expected = kdf.derive(password)

        with patch.object(bb, "get_keychain_password", return_value=password):
            actual = bb.get_master_key("/fake/UserData", "Chrome")

        self.assertEqual(actual, expected)

    def test_pbkdf2_output_is_16_bytes(self):
        with patch.object(bb, "get_keychain_password", return_value=b"anypassword"):
            key = bb.get_master_key("/fake/UserData", "Chrome")
        self.assertEqual(len(key), 16)


# ══════════════════════════════════════════════════════════════════════════════
# JWT header decoding
# ══════════════════════════════════════════════════════════════════════════════
class TestDecodeJwtHeader(unittest.TestCase):

    def test_extracts_kid_and_alg(self):
        token = _make_jwt({"sub": "u1"}, header={"alg": "HS384", "kid": "key-1564028078"})
        h = bb._decode_jwt_header(token)
        self.assertEqual(h.get("kid"), "key-1564028078")
        self.assertEqual(h.get("alg"), "HS384")

    def test_empty_on_invalid_token(self):
        self.assertEqual(bb._decode_jwt_header("notajwt"), {})

    def test_empty_on_bad_base64(self):
        self.assertEqual(bb._decode_jwt_header("!!!.payload.sig"), {})

    def test_kid_map_resolves_google_key_id(self):
        token = _make_jwt({"plaintext": "abc"}, header={"alg": "HS384", "kid": "key-1564028078"})
        result = bb.identify_service("JWT token", token)
        self.assertEqual(result, "JWT - Google")

    def test_kid_map_ignores_non_numeric_kid(self):
        # Only key-<digits> should match; arbitrary strings should not
        token = _make_jwt({"sub": "u1"}, header={"alg": "RS256", "kid": "some-arbitrary-kid"})
        result = bb.identify_service("JWT token", token)
        self.assertNotEqual(result, "JWT - Google")


# ══════════════════════════════════════════════════════════════════════════════
# OIDC discovery
# ══════════════════════════════════════════════════════════════════════════════
class TestOidcDiscover(unittest.TestCase):

    def setUp(self):
        bb._oidc_cache.clear()
        bb._do_oidc = True  # _oidc_discover() returns None immediately when False

    def tearDown(self):
        bb._do_oidc = False

    def test_known_domain_from_oidc_response(self):
        fake_response = (200, {"issuer": "https://accounts.google.com"})
        with patch.object(bb, "_http_get", return_value=fake_response):
            result = bb._oidc_discover("https://accounts.google.com")
        self.assertEqual(result, "Google Accounts")

    def test_unknown_domain_returns_raw_host(self):
        fake_response = (200, {"issuer": "https://auth.someunknownservice.io"})
        with patch.object(bb, "_http_get", return_value=fake_response):
            result = bb._oidc_discover("https://auth.someunknownservice.io")
        self.assertEqual(result, "auth.someunknownservice.io")

    def test_non_200_returns_none(self):
        with patch.object(bb, "_http_get", return_value=(404, {})):
            result = bb._oidc_discover("https://example.com")
        self.assertIsNone(result)

    def test_result_is_cached(self):
        fake_response = (200, {"issuer": "https://accounts.google.com"})
        with patch.object(bb, "_http_get", return_value=fake_response) as mock_get:
            bb._oidc_discover("https://accounts.google.com")
            bb._oidc_discover("https://accounts.google.com")
        mock_get.assert_called_once()

    def test_network_error_returns_none(self):
        with patch.object(bb, "_http_get", side_effect=Exception("timeout")):
            result = bb._oidc_discover("https://example.com")
        self.assertIsNone(result)

    def test_oidc_discovery_used_for_unknown_jwt_issuer(self):
        token = _make_jwt({"iss": "https://auth.mycompany.internal", "sub": "user"})
        fake_oidc = (200, {"issuer": "https://slack.com"})
        bb._oidc_cache.clear()
        with patch.object(bb, "_http_get", return_value=fake_oidc):
            result = bb.identify_service("JWT token", token)
        self.assertIn("Slack", result)


# ══════════════════════════════════════════════════════════════════════════════
# PID → site map
# ══════════════════════════════════════════════════════════════════════════════
class TestPidSiteMap(unittest.TestCase):

    def test_parses_site_instance_site(self):
        # _pid_site_map runs: ps -ww -A -o pid=,command=
        # Output format is "PID cmd..." (PID is the first whitespace-separated token)
        ps_output = (
            " 1234 /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper"
            " --type=renderer --site-instance-site=https://github.com --something-else\n"
            " 5678 /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper"
            " --type=renderer --site-instance-site=https://accounts.google.com\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ps_output
            result = bb._pid_site_map("Google Chrome Helper")
        self.assertEqual(result.get(1234), "https://github.com")
        self.assertEqual(result.get(5678), "https://accounts.google.com")

    def test_ignores_processes_without_flag(self):
        ps_output = "andrewh  9999  0.0  0.1  ... Google Chrome Helper --type=gpu-process\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ps_output
            result = bb._pid_site_map("Google Chrome Helper")
        self.assertNotIn(9999, result)

    def test_returns_empty_on_subprocess_error(self):
        with patch("subprocess.run", side_effect=Exception("no ps")):
            result = bb._pid_site_map("Google Chrome Helper")
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
