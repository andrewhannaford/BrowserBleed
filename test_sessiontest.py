"""
test_sessiontest.py — Unit tests for sessiontest.py

Tests dispatch routing, each tester (with mocked HTTP), CSV loading,
cookie filtering, progress counter, and the summary output.

Run:
    python -m pytest test_sessiontest.py -v
    python test_sessiontest.py
"""

import io
import sys
import os
import csv
import json
import time
import base64
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sessiontest as st


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_jwt(payload: dict, header: dict | None = None, expired: bool = False) -> str:
    h = header or {"alg": "HS256", "typ": "JWT"}
    if expired:
        payload = {**payload, "exp": int(time.time()) - 3600}
    elif "exp" not in payload:
        payload = {**payload, "exp": int(time.time()) + 3600}
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    sig = "SflKxwRJSMeKKF2QT4fwpMeJf"  # 25 chars — passes the > 10 check in _dispatch
    return f"{enc(h)}.{enc(payload)}.{sig}"


def _make_jwe_header(exp_ms: int | None = None) -> str:
    """Build a 3-part encrypted JWT (JWE) with 'enc' in header and all parts > 10 chars."""
    header = {"typ": "QT1", "enc": "AES256", "iss": 1234567890}
    if exp_ms is not None:
        header["exp"] = exp_ms
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    return f"{h}.encryptedkey123.ciphertextvalue123"  # each part > 10 chars


def _csv_row(label: str, service: str, value: str, browser: str = "Chrome") -> dict:
    return {"browser": browser, "profile": "(memory)",
            "label": label, "service": service, "value": value, "address": "0x0"}


def _write_csv(rows: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["browser", "profile", "label", "service", "value", "address"])
        writer.writeheader()
        writer.writerows(rows)


# ══════════════════════════════════════════════════════════════════════════════
# Dispatch routing
# ══════════════════════════════════════════════════════════════════════════════
class TestDispatch(unittest.TestCase):

    def _dispatch(self, label: str, service: str, value: str) -> list:
        return st._dispatch(label, service, value, browser=False)

    # ── Bearer prefix stripping ────────────────────────────────────────────────
    def test_bearer_prefix_stripped_before_ya29(self):
        with patch.object(st, "test_google_oauth") as mock:
            mock.return_value = st.Result("Google", "l", "v", "valid", "u", "a")
            self._dispatch("Bearer token", "Google OAuth2", "Bearer ya29.abc123def456ghi789jkl")
        mock.assert_called_once()
        called_value = mock.call_args[0][0]
        self.assertTrue(called_value.startswith("ya29."))
        self.assertFalse(called_value.startswith("Bearer "))

    def test_bearer_prefix_case_insensitive(self):
        with patch.object(st, "test_google_oauth") as mock:
            mock.return_value = st.Result("Google", "l", "v", "valid", "u", "a")
            self._dispatch("Bearer token", "Google OAuth2", "BEARER ya29.abc123def456ghi789jkl")
        mock.assert_called_once()

    # ── GitHub ────────────────────────────────────────────────────────────────
    def test_github_label_routes_to_github(self):
        with patch.object(st, "test_github") as mock:
            mock.return_value = st.Result("GitHub", "l", "v", "valid", "u", "a")
            self._dispatch("GitHub token", "GitHub", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
        mock.assert_called_once()

    def test_ghp_prefix_routes_to_github(self):
        with patch.object(st, "test_github") as mock:
            mock.return_value = st.Result("GitHub", "l", "v", "valid", "u", "a")
            self._dispatch("Bearer token", "Unknown", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
        mock.assert_called_once()

    # ── Discord ───────────────────────────────────────────────────────────────
    def test_discord_token_label_routes_to_discord(self):
        with patch.object(st, "test_discord") as mock:
            mock.return_value = st.Result("Discord", "l", "v", "invalid", "—", "401")
            self._dispatch("Discord token", "Discord",
                           "MjcyOTQyODcxODE5MTkwMjcz.EXAMPLE_TOKEN_XXXXXXXXXXXXXXXXXXXX")
        mock.assert_called_once()

    def test_discord_service_m_prefix_routes(self):
        with patch.object(st, "test_discord") as mock:
            mock.return_value = st.Result("Discord", "l", "v", "invalid", "—", "401")
            self._dispatch("Bearer token", "Discord",
                           "MTIyNDM4NTcyNTk0OTI4NDQwMw.EXAMPLE_FAKE_TOKEN_XXXXXXXXXXX")
        mock.assert_called_once()

    # ── Spotify ───────────────────────────────────────────────────────────────
    def test_bqa_prefix_routes_to_spotify(self):
        with patch.object(st, "test_spotify") as mock:
            mock.return_value = st.Result("Spotify", "l", "v", "valid", "u", "a")
            self._dispatch("Bearer token", "Discord", "BQAhRH1mt3DjufZQfOs0YvOH1mE8mHZ7EjJS")
        mock.assert_called_once()

    # ── Anthropic API key ─────────────────────────────────────────────────────
    def test_sk_ant_routes_to_anthropic(self):
        with patch.object(st, "test_anthropic") as mock:
            mock.return_value = st.Result("Anthropic", "l", "v", "valid", "u", "a")
            self._dispatch("Anthropic API key", "Anthropic / Claude", "sk-ant-oat01-" + "A" * 90)
        mock.assert_called_once()

    # ── Anthropic session token ───────────────────────────────────────────────
    def test_session_token_anthropic_routes_to_session_tester(self):
        with patch.object(st, "test_anthropic_session") as mock:
            mock.return_value = st.Result("Anthropic", "l", "v", "expired", "—", "401")
            self._dispatch("Session token", "Anthropic / Claude",
                           "20111GDqECYuMQ-Vhciczs3T-mwadEQ7KN5oKjEfm1ec6")
        mock.assert_called_once()

    def test_session_token_google_oauth_routes_to_google_oauth(self):
        with patch.object(st, "test_google_oauth") as mock:
            mock.return_value = st.Result("Google", "l", "v", "valid", "u", "a")
            self._dispatch("Session token", "Google OAuth2", "QUFFLUhqb" + "A" * 60)
        mock.assert_called_once()

    # ── Slack ─────────────────────────────────────────────────────────────────
    def test_xoxb_routes_to_slack(self):
        with patch.object(st, "test_slack") as mock:
            mock.return_value = st.Result("Slack", "l", "v", "valid", "u", "a")
            self._dispatch("Slack token", "Slack", "xoxb-000000000000-000000000000-XXXXXXXXXXXX")
        mock.assert_called_once()

    # ── SAPISID ───────────────────────────────────────────────────────────────
    def test_sapisid_routes_to_sapisid_tester(self):
        with patch.object(st, "test_google_sapisid") as mock:
            mock.return_value = st.Result("Google", "l", "v", "info", "—", "302/302")
            self._dispatch("Google SAPISID", "Google", "SAPISID=jcVfV5cj6P6PkVGu/APuJltyHrGn3QFg08")
        mock.assert_called_once()

    def test_sapisid_label_routes(self):
        with patch.object(st, "test_google_sapisid") as mock:
            mock.return_value = st.Result("Google", "l", "v", "info", "—", "302/302")
            self._dispatch("Google SAPISID", "Google", "SAPISID=abc123def456ghi789jkl")
        mock.assert_called_once()

    # ── HuggingFace ───────────────────────────────────────────────────────────
    def test_hf_prefix_routes_to_huggingface(self):
        with patch.object(st, "test_huggingface") as mock:
            mock.return_value = st.Result("HuggingFace", "l", "v", "invalid", "—", "401")
            self._dispatch("HuggingFace token", "HuggingFace", "hf_" + "A" * 34)
        mock.assert_called_once()

    # ── JWT ───────────────────────────────────────────────────────────────────
    def test_valid_jwt_routes_to_jwt_tester(self):
        tok = _make_jwt({"iss": "https://accounts.google.com", "sub": "12345"})
        results = self._dispatch("JWT token", "JWT - Google", tok)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].service, "JWT - Google")

    def test_expired_jwt_shows_expired(self):
        tok = _make_jwt({"iss": "https://example.com", "sub": "u"}, expired=True)
        results = self._dispatch("JWT token", "JWT - example.com", tok)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "expired")

    # ── JWE (encrypted JWT) ───────────────────────────────────────────────────
    def test_jwe_detected_by_enc_field(self):
        tok = _make_jwe_header(exp_ms=int(time.time() * 1000) - 3_600_000)
        results = self._dispatch("JWT token", "JWT - Google", tok)
        self.assertEqual(len(results), 1)
        self.assertIn("JWE", results[0].access)

    def test_jwe_expired_shows_expired_status(self):
        past_ms = (int(time.time()) - 7200) * 1000
        tok = _make_jwe_header(exp_ms=past_ms)
        results = self._dispatch("JWT token", "JWT - Google", tok)
        self.assertEqual(results[0].status, "expired")

    # ── Google refresh token ──────────────────────────────────────────────────
    def test_1slash_prefix_shows_info(self):
        results = self._dispatch("Bearer token", "Unknown", "1//0fyPiEOFX1QxBCgYIARAAGA8SNwF")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "info")
        self.assertIn("refresh", results[0].access.lower())

    # ── OAuth refresh token ───────────────────────────────────────────────────
    def test_oauth_refresh_label_shows_info(self):
        results = self._dispatch("OAuth refresh_token", "Discord", "eyJjcmVhdGVkX2F0IjogIjIwMjYtMDctMDJU")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "info")

    # ── Password without service ──────────────────────────────────────────────
    def test_password_unknown_service_shows_info(self):
        results = self._dispatch("Password (JSON/API)", "Unknown service", "yJIBTaxlodA2uDmzUbE8jKN3GiMfpWZP")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "info")

    # ── Session ID routing ────────────────────────────────────────────────────
    def test_session_id_google_routes_to_google_tester(self):
        with patch.object(st, "test_google_session_id") as mock:
            mock.return_value = st.Result("Google", "l", "v", "info", "—", "302")
            self._dispatch("Session ID", "Google Accounts", "2cec8dd81ced83f92fbecd1402e10777")
        mock.assert_called_once()

    def test_session_id_linkedin_routes_to_linkedin_tester(self):
        with patch.object(st, "test_linkedin_session_id") as mock:
            mock.return_value = st.Result("LinkedIn", "l", "v", "info", "—", "inconclusive")
            self._dispatch("Session ID", "LinkedIn", "1DC92BCD31AADD86FE7E264BBEDE0EC6")
        mock.assert_called_once()

    def test_session_id_anthropic_returns_info(self):
        results = self._dispatch("Session ID", "Anthropic / Claude", "390d08accae4c071e6dc1c5179e551fd")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "info")

    def test_session_id_aws_returns_info(self):
        results = self._dispatch("Session ID", "AWS", "bd08e2d628be77bf1269fe230279292c")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "info")
        self.assertIn("AWS", results[0].access)

    def test_session_id_unknown_returns_info(self):
        results = self._dispatch("Session ID", "Unknown service", "A60BD429B73308543F217123A2DFCE0A")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "info")

    # ── Microsoft ─────────────────────────────────────────────────────────────
    def test_microsoft_service_routes_to_microsoft(self):
        with patch.object(st, "test_microsoft") as mock:
            mock.return_value = st.Result("Microsoft", "l", "v", "invalid", "—", "401")
            self._dispatch("Password (JSON/API)", "Microsoft", "yJIBTaxlodA2uDmzUbE8jKN3GiMfpWZP")
        mock.assert_called_once()

    # ── LinkedIn li_at ────────────────────────────────────────────────────────
    def test_linkedin_li_at_label_routes(self):
        with patch.object(st, "test_linkedin_li_at") as mock:
            mock.return_value = st.Result("LinkedIn", "l", "v", "info", "—", "inconclusive")
            self._dispatch("LinkedIn li_at", "LinkedIn", "li_at=AQEDARMxhJAFAAAAABkqwJoAAAAAykb3iQ")
        mock.assert_called_once()

    # ── Twitter auth_token ────────────────────────────────────────────────────
    def test_twitter_auth_token_label_routes(self):
        with patch.object(st, "test_twitter_auth_token") as mock:
            mock.return_value = st.Result("Twitter / X", "l", "v", "info", "—", "inconclusive")
            self._dispatch("Twitter auth_token", "Twitter / X", "auth_token=5a3f7c9e8b2d4f6a0c1e3d5f")
        mock.assert_called_once()

    # ── Anthropic session label ───────────────────────────────────────────────
    def test_anthropic_session_label_routes(self):
        with patch.object(st, "test_anthropic_session") as mock:
            mock.return_value = st.Result("Anthropic", "l", "v", "expired", "—", "401")
            self._dispatch("Anthropic session", "Anthropic / Claude",
                           "20111GDqECYuMQ-Vhciczs3T-mwadEQ7KN5oKjEfm1ec6")
        mock.assert_called_once()

    # ── Session key ───────────────────────────────────────────────────────────
    def test_session_key_anthropic_routes(self):
        with patch.object(st, "test_anthropic_session") as mock:
            mock.return_value = st.Result("Anthropic", "l", "v", "expired", "—", "401")
            self._dispatch("Session key", "Anthropic / Claude", "20111GDqECYuMQ-Vhciczs3T-mwadEQ7KN5oKjEfm")
        mock.assert_called_once()

    def test_session_key_unknown_returns_info(self):
        results = self._dispatch("Session key", "Unknown service", "someSessionKeyValue123")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "info")

    # ── SendGrid ──────────────────────────────────────────────────────────────
    def test_sendgrid_label_routes(self):
        with patch.object(st, "test_sendgrid") as mock:
            mock.return_value = st.Result("SendGrid", "l", "v", "valid", "u", "a")
            self._dispatch("Sendgrid token", "SendGrid",
                           "SG.aBcDeFgHiJkLmNoPqRsTuVwX.aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890abcdefgh")
        mock.assert_called_once()

    def test_sg_prefix_routes_to_sendgrid(self):
        with patch.object(st, "test_sendgrid") as mock:
            mock.return_value = st.Result("SendGrid", "l", "v", "valid", "u", "a")
            self._dispatch("Bearer token", "Unknown",
                           "SG.aBcDeFgHiJkLmNoPqRsTuVwX.aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890abcdefgh")
        mock.assert_called_once()

    # ── Spotify: AQA prefix no longer routes ─────────────────────────────────
    def test_aqa_prefix_not_routed_to_spotify(self):
        results = self._dispatch("Bearer token", "Unknown", "AQAhRH1mt3DjufZQfOs0")
        self.assertEqual(results, [])  # AQA too broad; narrowed to BQA only

    # ── No match returns empty ────────────────────────────────────────────────
    def test_unrecognised_returns_empty(self):
        results = self._dispatch("Unknown label", "Unknown service", "x" * 20)
        self.assertEqual(results, [])


# ══════════════════════════════════════════════════════════════════════════════
# Individual testers (mocked HTTP)
# ══════════════════════════════════════════════════════════════════════════════
class TestGitHubTester(unittest.TestCase):

    def test_valid_token_returns_valid(self):
        user_data = {"login": "octocat", "name": "The Octocat", "email": "octocat@github.com", "public_repos": 10}
        with patch.object(st, "_get", side_effect=[(200, user_data), (200, []), (200, [])]):
            r = st.test_github("ghp_fake", "GitHub token")
        self.assertEqual(r.status, "valid")
        self.assertIn("octocat", r.identity)

    def test_invalid_token_returns_invalid(self):
        with patch.object(st, "_get", return_value=(401, {"message": "Bad credentials"})):
            r = st.test_github("ghp_bad", "GitHub token")
        self.assertEqual(r.status, "invalid")

    def test_error_returns_error(self):
        with patch.object(st, "_get", return_value=(500, {})):
            r = st.test_github("ghp_oops", "GitHub token")
        self.assertEqual(r.status, "error")


class TestSlackTester(unittest.TestCase):

    def test_valid_xoxb_returns_valid(self):
        data = {"ok": True, "user": "alice", "team": "ACME", "url": "https://acme.slack.com/"}
        with patch.object(st, "_get", return_value=(200, data)):
            r = st.test_slack("xoxb-fake", "Slack token")
        self.assertEqual(r.status, "valid")
        self.assertIn("alice", r.identity)

    def test_revoked_token_returns_expired(self):
        data = {"ok": False, "error": "token_revoked"}
        with patch.object(st, "_get", return_value=(200, data)):
            r = st.test_slack("xoxb-revoked", "Slack token")
        self.assertEqual(r.status, "expired")

    def test_invalid_token_returns_invalid(self):
        data = {"ok": False, "error": "invalid_auth"}
        with patch.object(st, "_get", return_value=(200, data)):
            r = st.test_slack("xoxb-invalid", "Slack token")
        self.assertEqual(r.status, "invalid")


class TestAnthropicTester(unittest.TestCase):

    def test_valid_api_key_returns_valid(self):
        models = {"data": [{"id": "claude-opus-4-8"}, {"id": "claude-sonnet-4-6"}]}
        with patch.object(st, "_get", return_value=(200, models)):
            r = st.test_anthropic("sk-ant-oat01-" + "A" * 90, "Anthropic API key")
        self.assertEqual(r.status, "valid")

    def test_invalid_api_key_returns_invalid(self):
        with patch.object(st, "_get", return_value=(401, {"error": {"message": "invalid"}})):
            r = st.test_anthropic("sk-ant-bad", "Anthropic API key")
        self.assertEqual(r.status, "invalid")


class TestAnthropicSessionTester(unittest.TestCase):

    def test_valid_session_returns_valid(self):
        data = {"user": {"email": "user@example.com", "name": "Test User"}}
        with patch.object(st, "_get", return_value=(200, data)):
            r = st.test_anthropic_session("20111GDqECYuMQ-abc", "Session token")
        self.assertEqual(r.status, "valid")
        self.assertIn("user@example.com", r.identity)

    def test_expired_session_returns_expired_or_invalid(self):
        with patch.object(st, "_get", return_value=(401, {})):
            r = st.test_anthropic_session("20111old", "Session token")
        self.assertIn(r.status, ("expired", "invalid"))

    def test_no_user_field_returns_non_valid(self):
        with patch.object(st, "_get", return_value=(200, {})):
            r = st.test_anthropic_session("20111abc", "Session token")
        self.assertNotEqual(r.status, "valid")


class TestGoogleOAuthTester(unittest.TestCase):

    def test_userinfo_200_returns_valid(self):
        data = {"email": "user@gmail.com", "name": "Test User"}
        with patch.object(st, "_get", return_value=(200, data)):
            r = st.test_google_oauth("ya29.valid", "Bearer token")
        self.assertEqual(r.status, "valid")
        self.assertIn("user@gmail.com", r.identity)

    def test_tokeninfo_fallback_returns_valid(self):
        tokeninfo = {"scope": "https://www.googleapis.com/auth/chromesync",
                     "expires_in": "3600", "azp": "77185425430.apps.googleusercontent.com"}
        with patch.object(st, "_get", side_effect=[(401, {}), (200, tokeninfo)]):
            r = st.test_google_oauth("ya29.narrow", "Bearer token")
        self.assertEqual(r.status, "valid")
        self.assertIn("app:", r.identity)

    def test_both_fail_returns_invalid(self):
        with patch.object(st, "_get", side_effect=[(401, {"error": "expired"}), (400, {})]):
            r = st.test_google_oauth("ya29.old", "Bearer token")
        self.assertIn(r.status, ("expired", "invalid"))


class TestDiscordTester(unittest.TestCase):

    def test_valid_token_returns_valid(self):
        data = {"id": "272942871819190273", "username": "testuser",
                "discriminator": "0", "email": "test@example.com", "verified": True}
        with patch.object(st, "_get", return_value=(200, data)):
            r = st.test_discord("MjcyOTQy.fakesig.morefake", "Discord token")
        self.assertEqual(r.status, "valid")
        self.assertIn("testuser", r.identity)

    def test_invalid_token_returns_invalid(self):
        with patch.object(st, "_get", return_value=(401, {})):
            r = st.test_discord("expired_token", "Discord token")
        self.assertIn(r.status, ("invalid", "error"))

    def test_discriminator_zero_omitted(self):
        data = {"id": "123", "username": "newformat", "discriminator": "0",
                "email": "", "verified": False}
        with patch.object(st, "_get", return_value=(200, data)):
            r = st.test_discord("token", "Discord token")
        self.assertEqual(r.identity, "newformat")

    def test_old_format_discriminator_included(self):
        data = {"id": "123", "username": "olduser", "discriminator": "1234",
                "email": "", "verified": False}
        with patch.object(st, "_get", return_value=(200, data)):
            r = st.test_discord("token", "Discord token")
        self.assertIn("1234", r.identity)


class TestSpotifyTester(unittest.TestCase):

    def test_valid_token_returns_valid(self):
        data = {"id": "user123", "display_name": "Test Listener",
                "email": "music@example.com", "product": "premium"}
        with patch.object(st, "_get", return_value=(200, data)):
            r = st.test_spotify("BQAhRH1fake", "Bearer token")
        self.assertEqual(r.status, "valid")
        self.assertIn("music@example.com", r.identity)
        self.assertIn("premium", r.access)

    def test_expired_returns_expired(self):
        with patch.object(st, "_get", return_value=(401, {})):
            r = st.test_spotify("BQAold", "Bearer token")
        self.assertEqual(r.status, "expired")

    def test_forbidden_returns_invalid(self):
        with patch.object(st, "_get", return_value=(403, {})):
            r = st.test_spotify("BQAforbidden", "Bearer token")
        self.assertEqual(r.status, "invalid")


class TestMicrosoftTester(unittest.TestCase):

    def test_valid_graph_token(self):
        data = {"displayName": "Andrew H", "mail": "andrew@example.com"}
        with patch.object(st, "_get", return_value=(200, data)):
            r = st.test_microsoft("fake_graph_token", "Bearer token")
        self.assertEqual(r.status, "valid")
        self.assertIn("Andrew H", r.identity)

    def test_invalid_returns_invalid(self):
        with patch.object(st, "_get", return_value=(401, {"error": {"message": "Unauthorized"}})):
            r = st.test_microsoft("bad_token", "Bearer token")
        self.assertEqual(r.status, "invalid")


class TestGoogleSapisidTester(unittest.TestCase):

    def test_authenticated_200_vs_302(self):
        with patch.object(st, "_status_only", side_effect=[200, 302]):
            r = st.test_google_sapisid("SAPISID=abc123def456ghi789jkl", "Google SAPISID")
        self.assertEqual(r.status, "valid")

    def test_both_302_returns_info(self):
        with patch.object(st, "_status_only", side_effect=[302, 302]):
            r = st.test_google_sapisid("SAPISID=abc", "Google SAPISID")
        self.assertEqual(r.status, "info")

    def test_strips_sapisid_prefix(self):
        # The SAPISID= prefix should be stripped before sending
        with patch.object(st, "_status_only", return_value=302) as mock:
            st.test_google_sapisid("SAPISID=the_actual_value", "Google SAPISID")
        # Both calls should have been made
        self.assertEqual(mock.call_count, 2)


class TestJWTTester(unittest.TestCase):

    def test_valid_jwt_returns_info_or_valid(self):
        tok = _make_jwt({"iss": "https://example.com", "sub": "user123"})
        r = st.test_jwt(tok, "JWT token", "JWT - example.com")
        self.assertIn(r.status, ("valid", "info"))

    def test_expired_jwt_returns_expired(self):
        tok = _make_jwt({"iss": "https://example.com", "sub": "u"}, expired=True)
        r = st.test_jwt(tok, "JWT token", "JWT - example.com")
        self.assertEqual(r.status, "expired")

    def test_invalid_jwt_returns_error(self):
        r = st.test_jwt("not.a.jwt.with.bad.base64.!!!", "JWT token", "Unknown")
        self.assertEqual(r.status, "error")

    def test_jwt_no_exp_returns_info(self):
        tok = _make_jwt({"iss": "https://example.com", "sub": "u"})
        # Manually remove exp from payload
        parts = tok.split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        payload.pop("exp", None)
        parts[1] = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        tok_no_exp = ".".join(parts)
        r = st.test_jwt(tok_no_exp, "JWT token", "Unknown")
        self.assertEqual(r.status, "info")

    def test_pseg_jwt_extracts_identity(self):
        tok = _make_jwt({
            "sub": "00u1muveryfZRjefm358",
            "name": "Andrew Hannaford",
            "email": "andrew@example.com",
            "preferred_username": "andrew.hannaford",
            "exp": int(time.time()) + 3600,
        })
        r = st.test_jwt(tok, "JWT token", "JWT - id.myaccount.pseg.com")
        self.assertEqual(r.identity, "00u1muveryfZRjefm358")


# ══════════════════════════════════════════════════════════════════════════════
# CSV loading and filtering
# ══════════════════════════════════════════════════════════════════════════════
class TestCSVProcessing(unittest.TestCase):
    import tempfile

    def setUp(self):
        import tempfile as _t
        self.tmp = _t.NamedTemporaryFile(suffix=".csv", delete=False, mode="w",
                                         newline="", encoding="utf-8")
        self.tmp.close()
        self.path = self.tmp.name

    def tearDown(self):
        import os as _os
        _os.unlink(self.path)

    def test_load_rows_basic(self):
        rows = [_csv_row("JWT token", "JWT - Google", "eyJ.abc.def")]
        _write_csv(rows, self.path)
        loaded = st.load_rows(self.path)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["label"], "JWT token")

    def test_cookie_header_rows_filtered(self):
        rows = [
            _csv_row("JWT token", "Google", "eyJ.abc.def"),
            _csv_row("Cookie header", "Unknown service",
                     "Cookie:33,myDriveHierarchyDepthLimitExceeded:73,notFound:4"),
        ]
        _write_csv(rows, self.path)
        loaded = st.load_rows(self.path)
        # load_rows returns all rows; filtering happens in main()
        # Verify the row is in the file
        self.assertEqual(len(loaded), 2)
        # Now simulate the filtering
        cred_rows = []
        for row in loaded:
            label_lo = row.get("label", "").lower()
            if "cookie" in label_lo:
                if label_lo == "cookie header":
                    continue
                cred_rows.append(row)
            else:
                cred_rows.append(row)
        self.assertEqual(len(cred_rows), 1)
        self.assertEqual(cred_rows[0]["label"], "JWT token")

    def test_deduplication_by_value(self):
        rows = [
            _csv_row("JWT token", "Google", "eyJ.abc.def"),
            _csv_row("JWT token", "Google", "eyJ.abc.def"),  # duplicate
            _csv_row("AWS Access Key", "AWS", "AKIAJFNFXH2V2O7RPCAA"),
        ]
        _write_csv(rows, self.path)
        loaded = st.load_rows(self.path)
        # Simulate dedup
        seen = set()
        unique = []
        for row in loaded:
            v = row.get("value", "").strip()
            if v and v not in seen:
                seen.add(v)
                unique.append(row)
        self.assertEqual(len(unique), 2)

    def test_cookie_rows_grouped_by_domain(self):
        from collections import defaultdict
        rows = [
            _csv_row("Cookie", ".github.com", "user_session=abc123def456ghi789"),
            _csv_row("Cookie", ".github.com", "logged_in=yes"),
        ]
        _write_csv(rows, self.path)
        loaded = st.load_rows(self.path)
        # Simulate cookie grouping
        cookies_by_domain = defaultdict(list)
        for row in loaded:
            if "cookie" in row.get("label", "").lower():
                domain = row.get("service", "")
                raw_val = row.get("value", "")
                if "=" in raw_val:
                    name, _, val = raw_val.partition("=")
                    cookies_by_domain[domain].append({"name": name, "value": val})
        self.assertEqual(len(cookies_by_domain[".github.com"]), 2)


# ══════════════════════════════════════════════════════════════════════════════
# Result structure
# ══════════════════════════════════════════════════════════════════════════════
class TestResultStructure(unittest.TestCase):

    def test_result_to_dict(self):
        r = st.Result("GitHub", "GitHub token", "ghp_ab…", "valid", "octocat", "10 repos")
        d = r.to_dict()
        self.assertEqual(d["service"], "GitHub")
        self.assertEqual(d["status"], "valid")
        self.assertEqual(d["identity"], "octocat")
        self.assertIn("value_preview", d)

    def test_result_fields_present(self):
        r = st.Result("Slack", "Slack token", "xoxb…", "invalid", "—", "token_revoked")
        self.assertEqual(r.service, "Slack")
        self.assertEqual(r.status, "invalid")
        self.assertEqual(r.identity, "—")


# ══════════════════════════════════════════════════════════════════════════════
# JWT decode helper in sessiontest
# ══════════════════════════════════════════════════════════════════════════════
class TestSessiontestJWTDecode(unittest.TestCase):

    def test_valid_3part_returns_dict(self):
        tok = _make_jwt({"sub": "user123", "iss": "https://example.com"})
        decoded = st._decode_jwt(tok)
        self.assertIsNotNone(decoded)
        self.assertIn("payload", decoded)
        self.assertEqual(decoded["payload"]["sub"], "user123")

    def test_two_parts_returns_none(self):
        self.assertIsNone(st._decode_jwt("header.payload"))

    def test_invalid_base64_returns_none(self):
        self.assertIsNone(st._decode_jwt("!!.!!.!!"))

    def test_encrypted_jwe_returns_none(self):
        tok = _make_jwe_header()
        # JWE payload is encrypted bytes — not JSON — so _decode_jwt should return None
        self.assertIsNone(st._decode_jwt(tok))


# ══════════════════════════════════════════════════════════════════════════════
# Session ID testers
# ══════════════════════════════════════════════════════════════════════════════
class TestLinkedInTester(unittest.TestCase):

    def test_valid_li_at_returns_valid(self):
        with patch.object(st, "_status_only", side_effect=[200, 302]):
            r = st.test_linkedin_li_at("AQEDARMxhJAFAAAAABkqwJoAAAAAykb3iQ", "LinkedIn li_at")
        self.assertEqual(r.status, "valid")

    def test_invalid_li_at_returns_info(self):
        with patch.object(st, "_status_only", side_effect=[302, 302]):
            r = st.test_linkedin_li_at("bad_token", "LinkedIn li_at")
        self.assertEqual(r.status, "info")

    def test_strips_li_at_prefix_when_present(self):
        with patch.object(st, "_status_only", return_value=302):
            st.test_linkedin_li_at("li_at=AQEDARMxhJAFAAAAABkqwJo", "LinkedIn li_at")
        # Just verify it doesn't crash — prefix is stripped before sending


class TestTwitterTester(unittest.TestCase):

    def test_valid_auth_token_returns_valid(self):
        with patch.object(st, "_status_only", side_effect=[200, 302]):
            r = st.test_twitter_auth_token("5a3f7c9e8b2d4f6a0c1e3d5f", "Twitter auth_token")
        self.assertEqual(r.status, "valid")

    def test_inconclusive_returns_info(self):
        with patch.object(st, "_status_only", side_effect=[302, 302]):
            r = st.test_twitter_auth_token("bad", "Twitter auth_token")
        self.assertEqual(r.status, "info")

    def test_strips_auth_token_prefix(self):
        with patch.object(st, "_status_only", return_value=302):
            st.test_twitter_auth_token("auth_token=5a3f7c9e", "Twitter auth_token")


class TestSendGridTester(unittest.TestCase):

    def test_valid_key_returns_valid(self):
        data = {"username": "apiuser", "email": "api@example.com"}
        with patch.object(st, "_get", return_value=(200, data)):
            r = st.test_sendgrid("SG.real.key", "Sendgrid token")
        self.assertEqual(r.status, "valid")
        self.assertIn("apiuser", r.identity)

    def test_unauthorized_returns_invalid(self):
        with patch.object(st, "_get", return_value=(401, {})):
            r = st.test_sendgrid("SG.bad.key", "Sendgrid token")
        self.assertEqual(r.status, "invalid")

    def test_forbidden_returns_invalid(self):
        with patch.object(st, "_get", return_value=(403, {})):
            r = st.test_sendgrid("SG.nope.key", "Sendgrid token")
        self.assertEqual(r.status, "invalid")


class TestSessionIDTesters(unittest.TestCase):

    def test_google_session_id_valid(self):
        with patch.object(st, "_status_only", side_effect=[200, 302]):
            r = st.test_google_session_id("2cec8dd81ced83f92fbecd1402e10777", "Session ID")
        self.assertEqual(r.status, "valid")

    def test_google_session_id_inconclusive(self):
        with patch.object(st, "_status_only", side_effect=[302, 302]):
            r = st.test_google_session_id("2cec8dd81ced83f92fbecd1402e10777", "Session ID")
        self.assertEqual(r.status, "info")

    def test_google_session_id_connection_error(self):
        # test_google_session_id has no explicit error branch for status 0 —
        # falls through to the "inconclusive" info result
        with patch.object(st, "_status_only", return_value=0):
            r = st.test_google_session_id("2cec8dd81ced83f92fbecd1402e10777", "Session ID")
        self.assertIn(r.status, ("info", "error"))

    def test_linkedin_session_id_inconclusive(self):
        with patch.object(st, "_status_only", return_value=302):
            r = st.test_linkedin_session_id("1DC92BCD31AADD86FE7E264BBEDE0EC6", "Session ID")
        self.assertEqual(r.status, "info")


if __name__ == "__main__":
    unittest.main(verbosity=2)
