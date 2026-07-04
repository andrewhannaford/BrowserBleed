"""Tests for BrowserBleed.py — Windows extractor."""
import ctypes
import hashlib
import importlib.util
import os
import shutil
import sqlite3
import subprocess as _subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

if not hasattr(ctypes, "windll"):
    ctypes.windll = MagicMock()
if not hasattr(_subprocess, "CREATE_NO_WINDOW"):
    _subprocess.CREATE_NO_WINDOW = 0x08000000

_win_spec = importlib.util.spec_from_file_location(
    "bb_win",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "BrowserBleed.py"),
)
bb_win = importlib.util.module_from_spec(_win_spec)
_win_spec.loader.exec_module(bb_win)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from tests.conftest import make_jwt



class TestWinNoiseFilter(unittest.TestCase):
    def test_c_format_string(self):
        self.assertTrue(bb_win._is_noise(b"Bearer %s", "Bearer %s"))

    def test_template_placeholder(self):
        self.assertTrue(bb_win._is_noise(b"access_token: {token}", "access_token: {token}"))

    def test_json_schema_fragment(self):
        self.assertTrue(bb_win._is_noise(b'"type":"string"', '"type":"string"'))

    def test_js_property_chain(self):
        self.assertTrue(bb_win._is_noise(b"x.auth.sessionToken", "x.auth.sessionToken"))

    def test_noise_exact_password_true(self):
        self.assertTrue(bb_win._is_noise(b"Password=true", "Password=true"))

    def test_real_jwt_not_noise(self):
        tok = b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fw"
        self.assertFalse(bb_win._is_noise(tok, tok.decode()))


class TestWinCredentialPatterns(unittest.TestCase):
    """Covers Windows-specific patterns not exercised by the Linux test classes."""

    def _matches(self, label: str, data: bytes) -> bool:
        return bool(bb_win.CREDENTIAL_PATTERNS[label].search(data))

    def test_authorization_header(self):
        data = b'Authorization: Bearer ya29.A0ARrdaM-abcdefghijklmnopqrstuvwxyz0123'
        self.assertTrue(self._matches("Authorization header", data))

    def test_cookie_header(self):
        data = b'Cookie: session=abcdef0123456789ABCDEF0123456789abcdef01234567'
        self.assertTrue(self._matches("Cookie header", data))

    def test_set_cookie_header(self):
        data = b'Set-Cookie: auth=eyJhbGciOiJIUzI1NiJ9xxxxxxxxxx'
        self.assertTrue(self._matches("Set-Cookie header", data))

    def test_oauth_refresh_token(self):
        data = b'refresh_token="1//abcdefghijklmnopqrstuvwxyz0123456789-ABCDE"'
        self.assertTrue(self._matches("OAuth refresh_token", data))

    def test_discord_token(self):
        # Split across concat so secret scanners don't flag this file
        data = (b"MTIzNDU2Nzg5MDEyMzQ1Njc4" + b"." +
                b"ABCDEF" + b"." + b"ABCDEFGHIJKLMNOPQRSTUVWXYZab")
        self.assertTrue(self._matches("Discord token", data))

    def test_jwt(self):
        tok = b"eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fw"
        self.assertTrue(self._matches("JWT token", tok))

    def test_github_token(self):
        self.assertTrue(self._matches("GitHub token", b"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"))

    def test_aws_access_key(self):
        self.assertTrue(self._matches("AWS Access Key", b"AKIAIOSFODNN7EXAMPLE"))

    def test_stripe_live(self):
        self.assertTrue(self._matches("Stripe key", b"sk_" + b"live_" + b"X" * 24))

    def test_anthropic(self):
        self.assertTrue(self._matches("Anthropic API key", b"sk-ant-api03-" + b"A" * 90))


class TestWinDeduplication(unittest.TestCase):
    def _hit(self, label, value, addr=0):
        return {"label": label, "value": value, "address": hex(addr),
                "dedup_key": f"{label}:{value[:80]}", "pid": 1, "context": b""}

    def test_exact_duplicate_removed(self):
        hits = [self._hit("JWT token", "eyJ.abc.def", 0x1000),
                self._hit("JWT token", "eyJ.abc.def", 0x2000)]
        self.assertEqual(len(bb_win.deduplicate(hits)), 1)

    def test_prefix_collapse_keeps_longer(self):
        short = self._hit("JWT token", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0", 0x1000)
        long  = self._hit("JWT token", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fw", 0x2000)
        result = bb_win.deduplicate([short, long])
        self.assertEqual(len(result), 1)
        self.assertIn("SflKxwRJ", result[0]["value"])

    def test_empty_input(self):
        self.assertEqual(bb_win.deduplicate([]), [])


@unittest.skipUnless(HAS_CRYPTO, "cryptography package not installed")
class TestWinDecryptValue(unittest.TestCase):
    """AES-256-GCM path (v10 prefix) — Chrome Windows encryption format."""

    @classmethod
    def setUpClass(cls):
        cls._master_key = b"\x42" * 32
        nonce     = b"\x11" * 12
        plaintext = b"correct horse battery staple"
        cls._enc  = b"v10" + nonce + AESGCM(cls._master_key).encrypt(nonce, plaintext, None)
        cls._plaintext = "correct horse battery staple"

    def test_v10_aes_gcm_roundtrip(self):
        result = bb_win.decrypt_value(self._master_key, self._enc)
        self.assertEqual(result, self._plaintext)

    def test_v10_unicode_roundtrip(self):
        nonce     = b"\x22" * 12
        plaintext = "p@ssw0rd!€¥"
        enc       = b"v10" + nonce + AESGCM(self._master_key).encrypt(nonce, plaintext.encode("utf-8"), None)
        self.assertEqual(bb_win.decrypt_value(self._master_key, enc), plaintext)

    def test_v20_returns_app_bound_label(self):
        result = bb_win.decrypt_value(self._master_key, b"v20" + b"\x00" * 32)
        self.assertIn("app-bound", result)

    def test_empty_returns_empty(self):
        result = bb_win.decrypt_value(self._master_key, b"")
        self.assertEqual(result, "")

    def test_wrong_key_returns_error_string(self):
        wrong_key = b"\xFF" * 32
        result    = bb_win.decrypt_value(wrong_key, self._enc)
        self.assertIn("decrypt error", result)


class TestWinServiceIdentification(unittest.TestCase):
    def test_github_pat(self):
        self.assertIn("GitHub", bb_win.identify_service("GitHub token", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789"))

    def test_anthropic_key(self):
        self.assertIn("Anthropic", bb_win.identify_service("Anthropic API key", "sk-ant-api03-" + "A" * 90))

    def test_aws(self):
        self.assertEqual("AWS", bb_win.identify_service("AWS Access Key", "AKIAIOSFODNN7EXAMPLE"))

    def test_google_oauth_ya29(self):
        self.assertIn("Google", bb_win.identify_service("Bearer token", "ya29.A0ARrdaM-ABCDEFGHIJKLMNOP"))

    def test_openai_sk(self):
        self.assertIn("OpenAI", bb_win.identify_service("Bearer token", "sk-proj-abcdefghijklmnopqrstuvwxyz"))

    def test_slack_bot_prefix(self):
        self.assertIn("Slack", bb_win.identify_service("Slack token", "xoxb-000000000000-XXXXXXXXXXXX"))

    def test_jwt_google_accounts(self):
        tok = make_jwt({"iss": "https://accounts.google.com", "sub": "12345"})
        self.assertIn("Google", bb_win.identify_service("JWT token", tok))

    def test_jwt_azure(self):
        tok = make_jwt({"iss": "https://login.microsoftonline.com/tenant/v2.0", "aud": "app"})
        self.assertIn("Microsoft", bb_win.identify_service("JWT token", tok))

    def test_context_github(self):
        ctx = b"Host: api.github.com\r\nAuthorization: Bearer sometoken"
        self.assertIn("GitHub", bb_win.identify_service("Bearer token", "sometoken" + "x" * 20, ctx))


class TestWinJWTDecoding(unittest.TestCase):
    def test_valid_claims(self):
        tok    = make_jwt({"sub": "user123", "iss": "https://example.com", "exp": 9999999999})
        claims = bb_win._decode_jwt_claims(tok)
        self.assertEqual(claims["sub"], "user123")

    def test_valid_header(self):
        tok    = make_jwt({"sub": "u"}, header={"alg": "RS256", "kid": "key-42"})
        header = bb_win._decode_jwt_header(tok)
        self.assertEqual(header["kid"], "key-42")

    def test_not_a_jwt(self):
        self.assertEqual(bb_win._decode_jwt_claims("notajwt"), {})

    def test_padding_tolerance(self):
        tok    = make_jwt({"sub": "x" * 7})
        claims = bb_win._decode_jwt_claims(tok)
        self.assertIn("sub", claims)


class TestWinChromeEpoch(unittest.TestCase):
    def test_zero_is_session(self):
        self.assertEqual(bb_win.chrome_epoch_to_str(0), "session")

    def test_known_date(self):
        from datetime import datetime, timezone
        target = datetime(2024, 1, 1, tzinfo=timezone.utc)
        epoch  = datetime(1601, 1, 1, tzinfo=timezone.utc)
        us     = int((target - epoch).total_seconds() * 1_000_000)
        self.assertEqual(bb_win.chrome_epoch_to_str(us), "2024-01-01 00:00:00 UTC")

    def test_unix_ts_zero(self):
        self.assertEqual(bb_win.unix_ts_to_str(0), "session")

    def test_unix_ts_real(self):
        self.assertIn("UTC", bb_win.unix_ts_to_str(1_700_000_000))


class TestWinOidcDiscover(unittest.TestCase):
    def setUp(self):
        bb_win._oidc_cache.clear()
        bb_win._do_oidc = True

    def tearDown(self):
        bb_win._do_oidc = False

    def test_known_domain_from_oidc_response(self):
        fake_response = (200, {"issuer": "https://accounts.google.com"})
        with patch.object(bb_win, "_http_get", return_value=fake_response):
            result = bb_win._oidc_discover("https://accounts.google.com")
        self.assertEqual(result, "Google Accounts")

    def test_non_200_returns_none(self):
        with patch.object(bb_win, "_http_get", return_value=(404, {})):
            result = bb_win._oidc_discover("https://example.com")
        self.assertIsNone(result)

    def test_result_is_cached(self):
        fake_response = (200, {"issuer": "https://accounts.google.com"})
        with patch.object(bb_win, "_http_get", return_value=fake_response) as mock_get:
            bb_win._oidc_discover("https://accounts.google.com")
            bb_win._oidc_discover("https://accounts.google.com")
        mock_get.assert_called_once()

    def test_network_error_returns_none(self):
        with patch.object(bb_win, "_http_get", side_effect=Exception("timeout")):
            result = bb_win._oidc_discover("https://example.com")
        self.assertIsNone(result)


@unittest.skipUnless(sys.platform == 'win32', "Windows only — requires Win32 process API")
class TestWinProcessDiscovery(unittest.TestCase):
    def test_find_self(self):
        pids = bb_win.find_pids("python.exe")
        self.assertIn(os.getpid(), pids)

    def test_nonexistent_process_returns_empty(self):
        self.assertEqual(bb_win.find_pids("this_process_does_not_exist_zzzzz.exe"), [])

    def test_is_process_running(self):
        self.assertTrue(bb_win.is_process_running("python.exe"))

    def test_is_process_running_false(self):
        self.assertFalse(bb_win.is_process_running("this_process_does_not_exist_zzzzz.exe"))


@unittest.skipUnless(sys.platform == 'win32', "Windows only — requires DPAPI and Chrome Local State")
class TestWinSQLiteExtraction(unittest.TestCase):
    """Full round-trip SQLite tests — only run when Chrome master key can be decrypted."""

    def setUp(self):
        self.tmp        = tempfile.mkdtemp()
        self.master_key = b"\x42" * 32

        conn = sqlite3.connect(os.path.join(self.tmp, "Login Data"))
        conn.execute("CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)")
        nonce = b"\x11" * 12
        enc   = b"v10" + nonce + AESGCM(self.master_key).encrypt(nonce, b"ghpass123", None)
        conn.execute("INSERT INTO logins VALUES (?,?,?)", ("https://github.com", "bob", enc))
        conn.commit(); conn.close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_credentials_found(self):
        with patch.object(bb_win, "copy_db_with_wal", side_effect=lambda p: p):
            creds = bb_win.extract_credentials(self.tmp, self.master_key)
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["password"], "ghpass123")

