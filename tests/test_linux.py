"""Tests for BrowserBleed_linux.py — Linux extractor."""
import hashlib
import importlib.util
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="BrowserBleed_linux requires Unix")

if sys.platform != "win32":
    _linux_spec = importlib.util.spec_from_file_location(
        "bb_linux",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "BrowserBleed_linux.py"),
    )
    bb_linux = importlib.util.module_from_spec(_linux_spec)
    _linux_spec.loader.exec_module(bb_linux)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from tests.conftest import make_jwt


def _make_jwt_linux(header: dict, payload: dict) -> str:
    return make_jwt(payload, header)


def _v10_encrypt(plaintext: str, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    iv = b" " * 16
    data = plaintext.encode("utf-8")
    pad = 16 - (len(data) % 16)
    padded = data + bytes([pad] * pad)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return b"v10" + enc.update(padded) + enc.finalize()



class TestLinuxPreFilter(unittest.TestCase):
    def test_jwt_prefix(self):
        self.assertTrue(bb_linux._has_credential_hint(b"eyJhbGciOiJSUzI1NiJ9.payload.sig"))

    def test_bearer_header(self):
        self.assertTrue(bb_linux._has_credential_hint(b"Authorization: Bearer sometoken"))

    def test_github_token(self):
        self.assertTrue(bb_linux._has_credential_hint(b"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234"))

    def test_anthropic_key(self):
        self.assertTrue(bb_linux._has_credential_hint(b"sk-ant-api03-" + b"A" * 90))

    def test_aws_key(self):
        self.assertTrue(bb_linux._has_credential_hint(b"AKIAIOSFODNN7EXAMPLE"))

    def test_ssh_key(self):
        self.assertTrue(bb_linux._has_credential_hint(b"-----BEGIN RSA PRIVATE KEY-----"))

    def test_random_data_miss(self):
        self.assertFalse(bb_linux._has_credential_hint(b"the quick brown fox jumps over the lazy dog"))

    def test_empty(self):
        self.assertFalse(bb_linux._has_credential_hint(b""))


class TestLinuxNoiseFilter(unittest.TestCase):
    def test_c_format_string(self):
        self.assertTrue(bb_linux._is_noise(b"Bearer %s", "Bearer %s"))

    def test_template_placeholder(self):
        self.assertTrue(bb_linux._is_noise(b"access_token: {token}", "access_token: {token}"))

    def test_json_schema_fragment(self):
        self.assertTrue(bb_linux._is_noise(b'"type":"string"', '"type":"string"'))

    def test_js_property_chain(self):
        self.assertTrue(bb_linux._is_noise(b"x.auth.sessionToken", "x.auth.sessionToken"))

    def test_noise_exact_password_true(self):
        self.assertTrue(bb_linux._is_noise(b"Password=true", "Password=true"))

    def test_real_token_passes(self):
        tok = b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.fakesig"
        self.assertFalse(bb_linux._is_noise(tok, tok.decode()))

    def test_real_github_token_passes(self):
        tok = b"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789"
        self.assertFalse(bb_linux._is_noise(tok, tok.decode()))


class TestLinuxCredentialPatterns(unittest.TestCase):
    def _matches(self, label: str, data: bytes) -> bool:
        return bool(bb_linux.CREDENTIAL_PATTERNS[label].search(data))

    def test_jwt(self):
        tok = b"eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fw"
        self.assertTrue(self._matches("JWT token", tok))

    def test_github_pat(self):
        self.assertTrue(self._matches("GitHub token", b"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"))

    def test_github_oauth(self):
        self.assertTrue(self._matches("GitHub token", b"gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"))

    def test_slack_bot(self):
        self.assertTrue(self._matches("Slack token", b"xoxb-000000000000-000000000000-XXXXXXXXXXXX"))

    def test_slack_user(self):
        self.assertTrue(self._matches("Slack token", b"xoxp-000000000000-000000000000-XXXXXXXXXXXX"))

    def test_aws_akia(self):
        self.assertTrue(self._matches("AWS Access Key", b"AKIAIOSFODNN7EXAMPLE"))

    def test_aws_asia(self):
        self.assertTrue(self._matches("AWS Access Key", b"ASIAIOSFODNN7EXAMPLE"))

    def test_anthropic(self):
        tok = b"sk-ant-api03-" + b"A" * 90
        self.assertTrue(self._matches("Anthropic API key", tok))

    def test_stripe_live(self):
        tok = (b"sk_" + b"live_" + b"X" * 24)
        self.assertTrue(self._matches("Stripe key", tok))

    def test_stripe_test(self):
        tok = (b"sk_" + b"test_" + b"X" * 24)
        self.assertTrue(self._matches("Stripe key", tok))

    def test_npm_token(self):
        self.assertTrue(self._matches("npm token", b"npm_" + b"A" * 36))

    def test_huggingface(self):
        self.assertTrue(self._matches("HuggingFace token", b"hf_" + b"A" * 34))

    def test_vault(self):
        self.assertTrue(self._matches("Vault token", b"hvs." + b"A" * 90))

    def test_ssh_rsa_key(self):
        key = b"-----BEGIN RSA PRIVATE KEY-----\n" + b"A" * 200 + b"\n-----END RSA PRIVATE KEY-----"
        self.assertTrue(self._matches("SSH private key", key))

    def test_ssh_openssh_key(self):
        key = b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + b"A" * 200 + b"\n-----END OPENSSH PRIVATE KEY-----"
        self.assertTrue(self._matches("SSH private key", key))

    def test_bearer_token(self):
        self.assertTrue(self._matches("Bearer token", b"Authorization: Bearer ya29.A0ARrdaM-ABCDEF"))

    def test_password_post_body(self):
        self.assertTrue(self._matches("Password (POST body)", b"username=alice&password=S3cur3P@ssword&submit=1"))

    def test_password_json(self):
        self.assertTrue(self._matches("Password (JSON/API)", b'{"username":"alice","password":"S3cur3P@ssword"}'))

    def test_oauth_access_token(self):
        data = b'access_token="ya29.A0ARrdaM-abcdefghijklmnopqrstuvwxyz01234567890"'
        self.assertTrue(self._matches("OAuth access_token", data))

    def test_sapisid(self):
        self.assertTrue(self._matches("Google SAPISID", b"SAPISID=abcdefghijklmnopqrstuvwxyz_ABCDEF"))


class TestLinuxCredentialPatternsInBuffer(unittest.TestCase):
    def test_jwt_in_http_response(self):
        data = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                b'{"token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fw"}')
        m = bb_linux.CREDENTIAL_PATTERNS["JWT token"].search(data)
        self.assertIsNotNone(m)

    def test_github_token_in_config(self):
        data = b'[github]\n  token = ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890\n'
        m = bb_linux.CREDENTIAL_PATTERNS["GitHub token"].search(data)
        self.assertIsNotNone(m)

    def test_aws_key_in_credentials_file(self):
        data = b'[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI\n'
        m = bb_linux.CREDENTIAL_PATTERNS["AWS Access Key"].search(data)
        self.assertIsNotNone(m)


class TestLinuxDeduplication(unittest.TestCase):
    def _hit(self, label, value, addr=0):
        return {"label": label, "value": value, "address": hex(addr),
                "dedup_key": f"{label}:{value[:80]}", "pid": 1, "context": b""}

    def test_exact_duplicate_removed(self):
        hits = [self._hit("JWT token", "eyJ.abc.def", 0x1000),
                self._hit("JWT token", "eyJ.abc.def", 0x2000)]
        self.assertEqual(len(bb_linux.deduplicate(hits)), 1)

    def test_prefix_collapse_keeps_longer(self):
        short = self._hit("JWT token", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0", 0x1000)
        long  = self._hit("JWT token", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fw", 0x2000)
        result = bb_linux.deduplicate([short, long])
        self.assertEqual(len(result), 1)
        self.assertIn("SflKxwRJ", result[0]["value"])

    def test_different_labels_both_kept(self):
        hits = [self._hit("JWT token",    "eyJ.abc.def"),
                self._hit("GitHub token", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789")]
        self.assertEqual(len(bb_linux.deduplicate(hits)), 2)

    def test_empty_input(self):
        self.assertEqual(bb_linux.deduplicate([]), [])

    def test_sorted_by_address(self):
        hits = [self._hit("JWT token", "eyJ.a.b", 0x3000),
                self._hit("AWS Access Key", "AKIAIOSFODNN7EXAMPLE", 0x1000)]
        result = bb_linux.deduplicate(hits)
        addrs = [int(h["address"], 16) for h in result]
        self.assertEqual(addrs, sorted(addrs))


class TestLinuxServiceIdentification(unittest.TestCase):
    def test_github_pat(self):
        self.assertIn("GitHub", bb_linux.identify_service("GitHub token", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789"))

    def test_github_oauth(self):
        self.assertIn("GitHub", bb_linux.identify_service("GitHub token", "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789"))

    def test_anthropic_key(self):
        self.assertIn("Anthropic", bb_linux.identify_service("Anthropic API key", "sk-ant-api03-" + "A" * 90))

    def test_aws(self):
        self.assertEqual("AWS", bb_linux.identify_service("AWS Access Key", "AKIAIOSFODNN7EXAMPLE"))

    def test_stripe_live(self):
        tok = "sk_" + "live_" + "X" * 24
        self.assertIn("Stripe", bb_linux.identify_service("Stripe key", tok))

    def test_google_oauth_ya29(self):
        self.assertIn("Google", bb_linux.identify_service("Bearer token", "ya29.A0ARrdaM-ABCDEFGHIJKLMNOP"))

    def test_openai_sk(self):
        self.assertIn("OpenAI", bb_linux.identify_service("Bearer token", "sk-proj-abcdefghijklmnopqrstuvwxyz"))

    def test_slack_bot_prefix(self):
        self.assertIn("Slack", bb_linux.identify_service("Slack token", "xoxb-000000000000-XXXXXXXXXXXX"))

    def test_huggingface(self):
        self.assertIn("HuggingFace", bb_linux.identify_service("HuggingFace token", "hf_" + "A" * 34))

    def test_vault(self):
        self.assertIn("Vault", bb_linux.identify_service("Vault token", "hvs." + "A" * 90))

    def test_ssh_key(self):
        self.assertIn("SSH", bb_linux.identify_service("SSH private key", "-----BEGIN RSA PRIVATE KEY-----"))

    def test_jwt_google_accounts(self):
        tok = _make_jwt_linux({"alg": "RS256"}, {"iss": "https://accounts.google.com", "sub": "12345"})
        self.assertIn("Google", bb_linux.identify_service("JWT token", tok))

    def test_jwt_github(self):
        tok = _make_jwt_linux({"alg": "RS256"}, {"iss": "https://github.com", "sub": "user"})
        self.assertIn("GitHub", bb_linux.identify_service("JWT token", tok))

    def test_jwt_azure(self):
        tok = _make_jwt_linux({"alg": "RS256"}, {"iss": "https://login.microsoftonline.com/tenant/v2.0", "aud": "app"})
        self.assertIn("Microsoft", bb_linux.identify_service("JWT token", tok))

    def test_jwt_kid_google(self):
        tok = _make_jwt_linux({"alg": "RS256", "kid": "key-1"}, {"sub": "user"})
        self.assertIn("Google", bb_linux.identify_service("JWT token", tok))

    def test_context_github(self):
        ctx = b"Host: api.github.com\r\nAuthorization: Bearer sometoken"
        self.assertIn("GitHub", bb_linux.identify_service("Bearer token", "sometoken" + "x" * 20, ctx))

    def test_context_anthropic(self):
        ctx = b"POST https://api.anthropic.com/v1/messages"
        self.assertIn("Anthropic", bb_linux.identify_service("Bearer token", "sometoken" + "x" * 20, ctx))


class TestLinuxJWTDecoding(unittest.TestCase):
    def test_valid_claims(self):
        tok    = _make_jwt_linux({"alg": "RS256"}, {"sub": "user123", "iss": "https://example.com", "exp": 9999999999})
        claims = bb_linux._decode_jwt_claims(tok)
        self.assertEqual(claims["sub"], "user123")
        self.assertEqual(claims["exp"], 9999999999)

    def test_valid_header(self):
        tok    = _make_jwt_linux({"alg": "RS256", "kid": "key-42"}, {"sub": "u"})
        header = bb_linux._decode_jwt_header(tok)
        self.assertEqual(header["kid"], "key-42")

    def test_not_a_jwt(self):
        self.assertEqual(bb_linux._decode_jwt_claims("notajwt"), {})
        self.assertEqual(bb_linux._decode_jwt_claims("only.two"), {})

    def test_padding_tolerance(self):
        tok = _make_jwt_linux({"alg": "RS256"}, {"sub": "x" * 7})
        claims = bb_linux._decode_jwt_claims(tok)
        self.assertIn("sub", claims)


class TestLinuxCrypto(unittest.TestCase):
    TEST_KEY = hashlib.pbkdf2_hmac("sha1", b"peanuts", b"saltysalt", 1, 16)

    def test_peanuts_key_length(self):
        self.assertEqual(len(self.TEST_KEY), 16)

    def test_roundtrip_short(self):
        enc    = _v10_encrypt("hunter2", self.TEST_KEY)
        result = bb_linux.decrypt_value(self.TEST_KEY, enc)
        self.assertEqual(result, "hunter2")

    def test_roundtrip_long(self):
        plaintext = "this is a longer password with special chars !@#$%^"
        enc       = _v10_encrypt(plaintext, self.TEST_KEY)
        result    = bb_linux.decrypt_value(self.TEST_KEY, enc)
        self.assertEqual(result, plaintext)

    def test_v11_prefix_also_decrypts(self):
        enc     = _v10_encrypt("mypass", self.TEST_KEY)
        enc_v11 = b"v11" + enc[3:]
        result  = bb_linux.decrypt_value(self.TEST_KEY, enc_v11)
        self.assertEqual(result, "mypass")

    def test_v20_returns_label(self):
        result = bb_linux.decrypt_value(self.TEST_KEY, b"v20" + b"\x00" * 32)
        self.assertIn("app-bound", result)

    def test_empty_blob_returns_empty(self):
        self.assertEqual(bb_linux.decrypt_value(self.TEST_KEY, b""), "")

    def test_plaintext_fallback(self):
        result = bb_linux.decrypt_value(self.TEST_KEY, b"plainvalue")
        self.assertEqual(result, "plainvalue")

    def test_wrong_key_does_not_return_plaintext(self):
        enc     = _v10_encrypt("secret", self.TEST_KEY)
        bad_key = hashlib.pbkdf2_hmac("sha1", b"wrong", b"saltysalt", 1, 16)
        result  = bb_linux.decrypt_value(bad_key, enc)
        self.assertNotEqual(result, "secret")


class TestLinuxSQLiteExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp  = tempfile.mkdtemp()
        self.key  = hashlib.pbkdf2_hmac("sha1", b"peanuts", b"saltysalt", 1, 16)

        conn = sqlite3.connect(os.path.join(self.tmp, "Login Data"))
        conn.execute("CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)")
        conn.execute("INSERT INTO logins VALUES (?,?,?)", ("https://example.com", "alice", b"plain"))
        conn.execute("INSERT INTO logins VALUES (?,?,?)", ("https://github.com",  "bob",   _v10_encrypt("ghpass123", self.key)))
        conn.commit(); conn.close()

        conn = sqlite3.connect(os.path.join(self.tmp, "Cookies"))
        conn.execute("""CREATE TABLE cookies (
            host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB,
            path TEXT, expires_utc INTEGER, is_secure INTEGER,
            is_httponly INTEGER, samesite INTEGER)""")
        conn.execute("INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?,?)",
                     (".example.com", "session", "", _v10_encrypt("sess_abc123", self.key), "/", 0, 1, 1, 1))
        conn.execute("INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?,?)",
                     (".github.com", "user_session", "", _v10_encrypt("user-abc-def", self.key), "/", 0, 1, 1, 1))
        conn.commit(); conn.close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_credentials_found(self):
        creds = bb_linux.extract_credentials(self.tmp, self.key)
        self.assertEqual(len(creds), 2)

    def test_credential_urls(self):
        creds = bb_linux.extract_credentials(self.tmp, self.key)
        urls  = {c["url"] for c in creds}
        self.assertIn("https://example.com", urls)
        self.assertIn("https://github.com",  urls)

    def test_v10_password_decrypted(self):
        creds  = bb_linux.extract_credentials(self.tmp, self.key)
        github = next(c for c in creds if c["url"] == "https://github.com")
        self.assertEqual(github["password"], "ghpass123")

    def test_cookies_found(self):
        cookies = bb_linux.extract_cookies(self.tmp, self.key)
        self.assertEqual(len(cookies), 2)

    def test_cookie_decrypted(self):
        cookies = bb_linux.extract_cookies(self.tmp, self.key)
        sess    = next(c for c in cookies if c["name"] == "session")
        self.assertEqual(sess["value"], "sess_abc123")

    def test_cookie_metadata(self):
        cookies = bb_linux.extract_cookies(self.tmp, self.key)
        sess    = next(c for c in cookies if c["name"] == "session")
        self.assertTrue(sess["secure"])
        self.assertTrue(sess["httponly"])

    def test_missing_db_returns_empty(self):
        creds = bb_linux.extract_credentials("/nonexistent/path", self.key)
        self.assertEqual(creds, [])


class TestLinuxProcessDiscovery(unittest.TestCase):
    def test_find_self(self):
        self_exe = os.path.basename(os.readlink(f"/proc/{os.getpid()}/exe"))
        pids     = bb_linux.find_pids(self_exe)
        self.assertIn(os.getpid(), pids)

    def test_nonexistent_process_returns_empty(self):
        self.assertEqual(bb_linux.find_pids("this_process_does_not_exist_zzzzz"), [])

    def test_is_process_running(self):
        self_exe = os.path.basename(os.readlink(f"/proc/{os.getpid()}/exe"))
        self.assertTrue(bb_linux.is_process_running(self_exe))

    def test_is_process_running_false(self):
        self.assertFalse(bb_linux.is_process_running("this_process_does_not_exist_zzzzz"))


class TestLinuxSelfMemoryScrape(unittest.TestCase):
    _PLANTED_GITHUB = b"ghp_SelfScrapeTestTokenABCDEFGHIJKLMNOPQRSTUV"
    _PLANTED_AWS    = b"AKIAIOSFODNN7SELFTES"

    def _scrape(self):
        try:
            return bb_linux.scrape_pid(os.getpid(), max_hits=50000)
        except PermissionError as e:
            self.skipTest(f"Cannot read /proc/self/mem: {e}")

    def test_scrape_completes_without_exception(self):
        hits = self._scrape()
        self.assertIsInstance(hits, list)

    @unittest.skipIf(os.environ.get("CI"), "flaky in CI — GC may collect planted bytes before scan")
    def test_planted_github_token_found(self):
        _keep = self._PLANTED_GITHUB
        hits  = self._scrape()
        found = any(h["value"].encode() in self._PLANTED_GITHUB or
                    self._PLANTED_GITHUB[4:] in h["value"].encode()
                    for h in hits if h["label"] == "GitHub token")
        self.assertTrue(found, f"Planted GitHub token not found in {len(hits)} hits")

    def test_planted_aws_key_found(self):
        _keep = self._PLANTED_AWS
        hits  = self._scrape()
        found = any(self._PLANTED_AWS in h["value"].encode()
                    for h in hits if h["label"] == "AWS Access Key")
        self.assertTrue(found, f"Planted AWS key not found in {len(hits)} hits")

    def test_dedup_works_on_scrape_results(self):
        hits   = self._scrape()
        deduped = bb_linux.deduplicate(hits)
        self.assertLessEqual(len(deduped), len(hits))


class TestLinuxUtilities(unittest.TestCase):
    def test_trunc_short_string(self):
        self.assertEqual(bb_linux._trunc("hello", 10), "hello")

    def test_trunc_long_string(self):
        result = bb_linux._trunc("A" * 100, 80)
        self.assertTrue(result.endswith("…"))
        self.assertEqual(len(result), 81)

    def test_chrome_epoch_zero(self):
        self.assertEqual(bb_linux.chrome_epoch_to_str(0), "session")

    def test_chrome_epoch_real_value(self):
        result = bb_linux.chrome_epoch_to_str(13_000_000_000_000_000)
        self.assertIn("UTC", result)
        self.assertIn("2012", result)

    def test_unix_ts_zero(self):
        self.assertEqual(bb_linux.unix_ts_to_str(0), "session")

    def test_unix_ts_negative(self):
        self.assertEqual(bb_linux.unix_ts_to_str(-1), "session")

    def test_unix_ts_real(self):
        self.assertIn("UTC", bb_linux.unix_ts_to_str(1_700_000_000))

    def test_is_root_returns_bool(self):
        self.assertIsInstance(bb_linux.is_root(), bool)

    def test_keyring_fallback_to_peanuts(self):
        pw = bb_linux._get_keyring_password("Chrome")
        self.assertEqual(pw, "peanuts")

    def test_app_name_chrome(self):
        self.assertEqual(bb_linux._app_name_for_path("/home/u/.config/google-chrome"), "Chrome")

    def test_app_name_brave(self):
        self.assertEqual(bb_linux._app_name_for_path("/home/u/.config/BraveSoftware/Brave-Browser"), "Brave")

    def test_app_name_chromium(self):
        self.assertEqual(bb_linux._app_name_for_path("/home/u/.config/chromium"), "Chromium")

    def test_app_name_edge(self):
        self.assertEqual(bb_linux._app_name_for_path("/home/u/.config/microsoft-edge"), "Microsoft Edge")

    def test_app_name_vivaldi(self):
        self.assertEqual(bb_linux._app_name_for_path("/home/u/.config/vivaldi"), "Vivaldi")

    def test_app_name_opera(self):
        self.assertEqual(bb_linux._app_name_for_path("/home/u/.config/opera"), "Opera")

    def test_get_profiles_default_only(self):
        tmp = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(tmp, "Default"))
            profiles = bb_linux._get_profiles(tmp)
            self.assertEqual(len(profiles), 1)
            self.assertEqual(profiles[0][0], "Default")
        finally:
            shutil.rmtree(tmp)

    def test_get_profiles_multiple(self):
        tmp = tempfile.mkdtemp()
        try:
            for d in ["Default", "Profile 1", "Profile 2"]:
                os.makedirs(os.path.join(tmp, d))
            profiles = bb_linux._get_profiles(tmp)
            labels   = [p[0] for p in profiles]
            self.assertIn("Default",   labels)
            self.assertIn("Profile 1", labels)
            self.assertIn("Profile 2", labels)
        finally:
            shutil.rmtree(tmp)


class TestLinuxFirefoxExtraction(unittest.TestCase):
    def setUp(self):
        self.orig_home = bb_linux.HOME
        self.tmp       = tempfile.mkdtemp()
        ff_dir         = os.path.join(self.tmp, ".mozilla", "firefox", "abc123.default")
        os.makedirs(ff_dir)
        conn = sqlite3.connect(os.path.join(ff_dir, "cookies.sqlite"))
        conn.execute("""CREATE TABLE moz_cookies (
            host TEXT, name TEXT, value TEXT, path TEXT,
            expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER)""")
        conn.execute("INSERT INTO moz_cookies VALUES (?,?,?,?,?,?,?,?)",
                     (".mozilla.org", "ff_session", "abc123xyz", "/", 0, 1, 1, 0))
        conn.commit(); conn.close()
        bb_linux.HOME = self.tmp

    def tearDown(self):
        bb_linux.HOME = self.orig_home
        shutil.rmtree(self.tmp)

    def test_firefox_cookies_found(self):
        ff_dir  = os.path.join(self.tmp, ".mozilla", "firefox")
        cookies = bb_linux._extract_moz_cookies(ff_dir, "Firefox")
        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]["name"],  "ff_session")
        self.assertEqual(cookies[0]["value"], "abc123xyz")
        self.assertEqual(cookies[0]["host"],  ".mozilla.org")

