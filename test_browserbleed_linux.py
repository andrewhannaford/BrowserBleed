"""
Test suite for BrowserBleed_linux.py
Exercises individual components without running the full extraction tool.
"""

import os
import sys
import json
import base64
import sqlite3
import hashlib
import tempfile
import shutil
import unittest

# Import the module under test
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "bb", os.path.join(os.path.dirname(os.path.abspath(__file__)), "BrowserBleed_linux.py")
)
bb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bb)


# ── Helpers ────────────────────────────────────────────────────────────────────
def _make_jwt(header: dict, payload: dict) -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.fakesignature"


def _v10_encrypt(plaintext: str, key: bytes) -> bytes:
    """AES-128-CBC encrypt with v10 prefix and spaces IV — matches Chrome Linux format."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    iv     = b" " * 16
    data   = plaintext.encode("utf-8")
    pad    = 16 - (len(data) % 16)
    padded = data + bytes([pad] * pad)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc    = cipher.encryptor()
    return b"v10" + enc.update(padded) + enc.finalize()


# ── Tests ──────────────────────────────────────────────────────────────────────
class TestPreFilter(unittest.TestCase):
    def test_jwt_prefix(self):
        self.assertTrue(bb._has_credential_hint(b"eyJhbGciOiJSUzI1NiJ9.payload.sig"))

    def test_bearer_header(self):
        self.assertTrue(bb._has_credential_hint(b"Authorization: Bearer sometoken"))

    def test_github_token(self):
        self.assertTrue(bb._has_credential_hint(b"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234"))

    def test_anthropic_key(self):
        self.assertTrue(bb._has_credential_hint(b"sk-ant-api03-" + b"A" * 90))

    def test_aws_key(self):
        self.assertTrue(bb._has_credential_hint(b"AKIAIOSFODNN7EXAMPLE"))

    def test_ssh_key(self):
        self.assertTrue(bb._has_credential_hint(b"-----BEGIN RSA PRIVATE KEY-----"))

    def test_random_data_miss(self):
        self.assertFalse(bb._has_credential_hint(b"the quick brown fox jumps over the lazy dog"))

    def test_empty(self):
        self.assertFalse(bb._has_credential_hint(b""))


class TestNoiseFilter(unittest.TestCase):
    def test_c_format_string(self):
        self.assertTrue(bb._is_noise(b"Bearer %s", "Bearer %s"))

    def test_template_placeholder(self):
        self.assertTrue(bb._is_noise(b"access_token: {token}", "access_token: {token}"))

    def test_json_schema_fragment(self):
        self.assertTrue(bb._is_noise(b'"type":"string"', '"type":"string"'))

    def test_js_property_chain(self):
        self.assertTrue(bb._is_noise(b"x.auth.sessionToken", "x.auth.sessionToken"))

    def test_noise_exact_password_true(self):
        self.assertTrue(bb._is_noise(b"Password=true", "Password=true"))

    def test_real_token_passes(self):
        tok = b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.fakesig"
        self.assertFalse(bb._is_noise(tok, tok.decode()))

    def test_real_github_token_passes(self):
        tok = b"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789"
        self.assertFalse(bb._is_noise(tok, tok.decode()))


class TestCredentialPatterns(unittest.TestCase):
    def _matches(self, label: str, data: bytes) -> bool:
        return bool(bb.CREDENTIAL_PATTERNS[label].search(data))

    def test_jwt(self):
        # Each of the three JWT parts must be ≥20 base64url chars per the pattern.
        # Part 2 "eyJzdWIiOiJ1c2VyIn0" is only 19 chars, so extend the payload.
        tok = b"eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fw"
        self.assertTrue(self._matches("JWT token", tok))

    def test_github_pat(self):
        # Pattern requires gh[pousr]_[A-Za-z0-9]{36,} — need 36+ chars after the prefix
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
        # split prefix so GitHub secret scanning doesn't flag the test file
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
        # Pattern requires 20+ chars after "Bearer " — ya29.A0ARrdaM-ABCDE is only 19
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


class TestCredentialPatternsInBuffer(unittest.TestCase):
    """Test patterns embedded in realistic memory-like buffers."""

    def test_jwt_in_http_response(self):
        # Each JWT part must be ≥20 chars; use a full-length token
        data = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                b'{"token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fw"}')
        m = bb.CREDENTIAL_PATTERNS["JWT token"].search(data)
        self.assertIsNotNone(m)

    def test_github_token_in_config(self):
        # Pattern requires 36+ chars after gh[pousr]_ prefix
        data = b'[github]\n  token = ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890\n'
        m = bb.CREDENTIAL_PATTERNS["GitHub token"].search(data)
        self.assertIsNotNone(m)

    def test_aws_key_in_credentials_file(self):
        data = b'[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI\n'
        m = bb.CREDENTIAL_PATTERNS["AWS Access Key"].search(data)
        self.assertIsNotNone(m)


class TestDeduplication(unittest.TestCase):
    def _hit(self, label, value, addr=0):
        return {"label": label, "value": value, "address": hex(addr),
                "dedup_key": f"{label}:{value[:80]}", "pid": 1, "context": b""}

    def test_exact_duplicate_removed(self):
        hits = [self._hit("JWT token", "eyJ.abc.def", 0x1000),
                self._hit("JWT token", "eyJ.abc.def", 0x2000)]
        self.assertEqual(len(bb.deduplicate(hits)), 1)

    def test_prefix_collapse_keeps_longer(self):
        short = self._hit("JWT token", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0", 0x1000)
        long  = self._hit("JWT token", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fw", 0x2000)
        result = bb.deduplicate([short, long])
        self.assertEqual(len(result), 1)
        self.assertIn("SflKxwRJ", result[0]["value"])

    def test_different_labels_both_kept(self):
        hits = [self._hit("JWT token",    "eyJ.abc.def"),
                self._hit("GitHub token", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789")]
        self.assertEqual(len(bb.deduplicate(hits)), 2)

    def test_empty_input(self):
        self.assertEqual(bb.deduplicate([]), [])

    def test_sorted_by_address(self):
        hits = [self._hit("JWT token", "eyJ.a.b", 0x3000),
                self._hit("AWS Access Key", "AKIAIOSFODNN7EXAMPLE", 0x1000)]
        result = bb.deduplicate(hits)
        addrs = [int(h["address"], 16) for h in result]
        self.assertEqual(addrs, sorted(addrs))


class TestServiceIdentification(unittest.TestCase):
    def test_github_pat(self):
        self.assertIn("GitHub", bb.identify_service("GitHub token", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789"))

    def test_github_oauth(self):
        self.assertIn("GitHub", bb.identify_service("GitHub token", "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789"))

    def test_anthropic_key(self):
        self.assertIn("Anthropic", bb.identify_service("Anthropic API key", "sk-ant-api03-" + "A" * 90))

    def test_aws(self):
        self.assertEqual("AWS", bb.identify_service("AWS Access Key", "AKIAIOSFODNN7EXAMPLE"))

    def test_stripe_live(self):
        tok = "sk_" + "live_" + "X" * 24
        self.assertIn("Stripe", bb.identify_service("Stripe key", tok))

    def test_google_oauth_ya29(self):
        self.assertIn("Google", bb.identify_service("Bearer token", "ya29.A0ARrdaM-ABCDEFGHIJKLMNOP"))

    def test_openai_sk(self):
        self.assertIn("OpenAI", bb.identify_service("Bearer token", "sk-proj-abcdefghijklmnopqrstuvwxyz"))

    def test_slack_bot_prefix(self):
        self.assertIn("Slack", bb.identify_service("Slack token", "xoxb-000000000000-XXXXXXXXXXXX"))

    def test_huggingface(self):
        self.assertIn("HuggingFace", bb.identify_service("HuggingFace token", "hf_" + "A" * 34))

    def test_vault(self):
        self.assertIn("Vault", bb.identify_service("Vault token", "hvs." + "A" * 90))

    def test_ssh_key(self):
        self.assertIn("SSH", bb.identify_service("SSH private key", "-----BEGIN RSA PRIVATE KEY-----"))

    def test_jwt_google_accounts(self):
        tok = _make_jwt({"alg": "RS256"}, {"iss": "https://accounts.google.com", "sub": "12345"})
        self.assertIn("Google", bb.identify_service("JWT token", tok))

    def test_jwt_github(self):
        tok = _make_jwt({"alg": "RS256"}, {"iss": "https://github.com", "sub": "user"})
        self.assertIn("GitHub", bb.identify_service("JWT token", tok))

    def test_jwt_azure(self):
        tok = _make_jwt({"alg": "RS256"}, {"iss": "https://login.microsoftonline.com/tenant/v2.0", "aud": "app"})
        self.assertIn("Microsoft", bb.identify_service("JWT token", tok))

    def test_jwt_kid_google(self):
        tok = _make_jwt({"alg": "RS256", "kid": "key-1"}, {"sub": "user"})
        self.assertIn("Google", bb.identify_service("JWT token", tok))

    def test_context_github(self):
        ctx = b"Host: api.github.com\r\nAuthorization: Bearer sometoken"
        self.assertIn("GitHub", bb.identify_service("Bearer token", "sometoken" + "x" * 20, ctx))

    def test_context_anthropic(self):
        ctx = b"POST https://api.anthropic.com/v1/messages"
        self.assertIn("Anthropic", bb.identify_service("Bearer token", "sometoken" + "x" * 20, ctx))


class TestJWTDecoding(unittest.TestCase):
    def test_valid_claims(self):
        tok    = _make_jwt({"alg": "RS256"}, {"sub": "user123", "iss": "https://example.com", "exp": 9999999999})
        claims = bb._decode_jwt_claims(tok)
        self.assertEqual(claims["sub"], "user123")
        self.assertEqual(claims["exp"], 9999999999)

    def test_valid_header(self):
        tok    = _make_jwt({"alg": "RS256", "kid": "key-42"}, {"sub": "u"})
        header = bb._decode_jwt_header(tok)
        self.assertEqual(header["kid"], "key-42")

    def test_not_a_jwt(self):
        self.assertEqual(bb._decode_jwt_claims("notajwt"), {})
        self.assertEqual(bb._decode_jwt_claims("only.two"), {})

    def test_padding_tolerance(self):
        # JWT segments often omit base64 padding - make sure we handle it
        tok = _make_jwt({"alg": "RS256"}, {"sub": "x" * 7})  # odd-length payload
        claims = bb._decode_jwt_claims(tok)
        self.assertIn("sub", claims)


class TestCrypto(unittest.TestCase):
    TEST_KEY = hashlib.pbkdf2_hmac("sha1", b"peanuts", b"saltysalt", 1, 16)

    def test_peanuts_key_length(self):
        self.assertEqual(len(self.TEST_KEY), 16)

    def test_roundtrip_short(self):
        enc    = _v10_encrypt("hunter2", self.TEST_KEY)
        result = bb.decrypt_value(self.TEST_KEY, enc)
        self.assertEqual(result, "hunter2")

    def test_roundtrip_long(self):
        plaintext = "this is a longer password with special chars !@#$%^"
        enc       = _v10_encrypt(plaintext, self.TEST_KEY)
        result    = bb.decrypt_value(self.TEST_KEY, enc)
        self.assertEqual(result, plaintext)

    def test_v11_prefix_also_decrypts(self):
        enc    = _v10_encrypt("mypass", self.TEST_KEY)
        enc_v11 = b"v11" + enc[3:]
        result  = bb.decrypt_value(self.TEST_KEY, enc_v11)
        self.assertEqual(result, "mypass")

    def test_v20_returns_label(self):
        result = bb.decrypt_value(self.TEST_KEY, b"v20" + b"\x00" * 32)
        self.assertIn("app-bound", result)

    def test_empty_blob_returns_empty(self):
        self.assertEqual(bb.decrypt_value(self.TEST_KEY, b""), "")

    def test_plaintext_fallback(self):
        result = bb.decrypt_value(self.TEST_KEY, b"plainvalue")
        self.assertEqual(result, "plainvalue")

    def test_wrong_key_does_not_return_plaintext(self):
        enc     = _v10_encrypt("secret", self.TEST_KEY)
        bad_key = hashlib.pbkdf2_hmac("sha1", b"wrong", b"saltysalt", 1, 16)
        result  = bb.decrypt_value(bad_key, enc)
        self.assertNotEqual(result, "secret")


class TestSQLiteExtraction(unittest.TestCase):
    """End-to-end disk extraction against a synthetic Chrome-like SQLite database."""

    def setUp(self):
        self.tmp  = tempfile.mkdtemp()
        self.key  = hashlib.pbkdf2_hmac("sha1", b"peanuts", b"saltysalt", 1, 16)

        # Login Data
        conn = sqlite3.connect(os.path.join(self.tmp, "Login Data"))
        conn.execute("CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)")
        conn.execute("INSERT INTO logins VALUES (?,?,?)", ("https://example.com", "alice", b"plain"))
        conn.execute("INSERT INTO logins VALUES (?,?,?)", ("https://github.com",  "bob",   _v10_encrypt("ghpass123", self.key)))
        conn.commit(); conn.close()

        # Cookies
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
        creds = bb.extract_credentials(self.tmp, self.key)
        self.assertEqual(len(creds), 2)

    def test_credential_urls(self):
        creds = bb.extract_credentials(self.tmp, self.key)
        urls  = {c["url"] for c in creds}
        self.assertIn("https://example.com", urls)
        self.assertIn("https://github.com",  urls)

    def test_v10_password_decrypted(self):
        creds  = bb.extract_credentials(self.tmp, self.key)
        github = next(c for c in creds if c["url"] == "https://github.com")
        self.assertEqual(github["password"], "ghpass123")

    def test_cookies_found(self):
        cookies = bb.extract_cookies(self.tmp, self.key)
        self.assertEqual(len(cookies), 2)

    def test_cookie_decrypted(self):
        cookies = bb.extract_cookies(self.tmp, self.key)
        sess    = next(c for c in cookies if c["name"] == "session")
        self.assertEqual(sess["value"], "sess_abc123")

    def test_cookie_metadata(self):
        cookies = bb.extract_cookies(self.tmp, self.key)
        sess    = next(c for c in cookies if c["name"] == "session")
        self.assertTrue(sess["secure"])
        self.assertTrue(sess["httponly"])

    def test_missing_db_returns_empty(self):
        creds = bb.extract_credentials("/nonexistent/path", self.key)
        self.assertEqual(creds, [])


class TestProcessDiscovery(unittest.TestCase):
    def test_find_self(self):
        self_exe = os.path.basename(os.readlink(f"/proc/{os.getpid()}/exe"))
        pids     = bb.find_pids(self_exe)
        self.assertIn(os.getpid(), pids)

    def test_nonexistent_process_returns_empty(self):
        self.assertEqual(bb.find_pids("this_process_does_not_exist_zzzzz"), [])

    def test_is_process_running(self):
        self_exe = os.path.basename(os.readlink(f"/proc/{os.getpid()}/exe"))
        self.assertTrue(bb.is_process_running(self_exe))

    def test_is_process_running_false(self):
        self.assertFalse(bb.is_process_running("this_process_does_not_exist_zzzzz"))


class TestSelfMemoryScrape(unittest.TestCase):
    """Scrape our own process memory — no root needed for self."""

    # Plant a recognisable token at module level so it survives GC
    _PLANTED_GITHUB = b"ghp_SelfScrapeTestTokenABCDEFGHIJKLMNOPQRSTUV"
    # AWS pattern captures exactly 20 chars (AKIA + 16); keep planted key at that length
    # so the substring check (planted_key in extracted_value) works both ways.
    _PLANTED_AWS    = b"AKIAIOSFODNN7SELFTES"

    def _scrape(self):
        # Use a high cap so the planted tokens aren't missed when many other
        # patterns (session IDs, cookies) are found in earlier memory regions.
        try:
            return bb.scrape_pid(os.getpid(), max_hits=50000)
        except PermissionError as e:
            self.skipTest(f"Cannot read /proc/self/mem: {e}")

    def test_scrape_completes_without_exception(self):
        hits = self._scrape()
        self.assertIsInstance(hits, list)

    def test_planted_github_token_found(self):
        # Keep a reference so the bytes object stays alive in our heap
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
        deduped = bb.deduplicate(hits)
        self.assertLessEqual(len(deduped), len(hits))


class TestUtilities(unittest.TestCase):
    def test_trunc_short_string(self):
        self.assertEqual(bb._trunc("hello", 10), "hello")

    def test_trunc_long_string(self):
        result = bb._trunc("A" * 100, 80)
        self.assertTrue(result.endswith("…"))
        self.assertEqual(len(result), 81)

    def test_chrome_epoch_zero(self):
        self.assertEqual(bb.chrome_epoch_to_str(0), "session")

    def test_chrome_epoch_real_value(self):
        result = bb.chrome_epoch_to_str(13_000_000_000_000_000)
        self.assertIn("UTC", result)
        self.assertIn("2012", result)

    def test_unix_ts_zero(self):
        self.assertEqual(bb.unix_ts_to_str(0), "session")

    def test_unix_ts_negative(self):
        self.assertEqual(bb.unix_ts_to_str(-1), "session")

    def test_unix_ts_real(self):
        self.assertIn("UTC", bb.unix_ts_to_str(1_700_000_000))

    def test_is_root_returns_bool(self):
        self.assertIsInstance(bb.is_root(), bool)

    def test_keyring_fallback_to_peanuts(self):
        # No keyring in a test environment
        pw = bb._get_keyring_password("Chrome")
        self.assertEqual(pw, "peanuts")

    def test_app_name_chrome(self):
        self.assertEqual(bb._app_name_for_path("/home/u/.config/google-chrome"), "Chrome")

    def test_app_name_brave(self):
        self.assertEqual(bb._app_name_for_path("/home/u/.config/BraveSoftware/Brave-Browser"), "Brave")

    def test_app_name_chromium(self):
        self.assertEqual(bb._app_name_for_path("/home/u/.config/chromium"), "Chromium")

    def test_app_name_edge(self):
        self.assertEqual(bb._app_name_for_path("/home/u/.config/microsoft-edge"), "Microsoft Edge")

    def test_app_name_vivaldi(self):
        self.assertEqual(bb._app_name_for_path("/home/u/.config/vivaldi"), "Vivaldi")

    def test_app_name_opera(self):
        self.assertEqual(bb._app_name_for_path("/home/u/.config/opera"), "Opera")

    def test_get_profiles_default_only(self):
        tmp = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(tmp, "Default"))
            profiles = bb._get_profiles(tmp)
            self.assertEqual(len(profiles), 1)
            self.assertEqual(profiles[0][0], "Default")
        finally:
            shutil.rmtree(tmp)

    def test_get_profiles_multiple(self):
        tmp = tempfile.mkdtemp()
        try:
            for d in ["Default", "Profile 1", "Profile 2"]:
                os.makedirs(os.path.join(tmp, d))
            profiles = bb._get_profiles(tmp)
            labels   = [p[0] for p in profiles]
            self.assertIn("Default",   labels)
            self.assertIn("Profile 1", labels)
            self.assertIn("Profile 2", labels)
        finally:
            shutil.rmtree(tmp)


class TestFirefoxExtraction(unittest.TestCase):
    def setUp(self):
        self.orig_home = bb.HOME
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
        bb.HOME = self.tmp

    def tearDown(self):
        bb.HOME = self.orig_home
        shutil.rmtree(self.tmp)

    def test_firefox_cookies_found(self):
        # extract_all_firefox_family() resolves paths from _FIREFOX_SPECS which are
        # baked in at module load time; test _extract_moz_cookies directly instead.
        ff_dir = os.path.join(self.tmp, ".mozilla", "firefox")
        cookies = bb._extract_moz_cookies(ff_dir, "Firefox")
        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]["name"],  "ff_session")
        self.assertEqual(cookies[0]["value"], "abc123xyz")
        self.assertEqual(cookies[0]["host"],  ".mozilla.org")


if __name__ == "__main__":
    unittest.main(verbosity=2)
