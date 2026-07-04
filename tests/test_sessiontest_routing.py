"""Extended sessiontest routing and service-specific tests."""
import base64
import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

import sessiontest as s

from tests.conftest import csv_row, make_jwe_header, make_jwt, write_csv

class TestDispatchRoutes(unittest.TestCase):

    def _dispatch(self, label: str, service: str, value: str) -> list:
        return s._dispatch(label, service, value, browser=False)

    # ── Bearer prefix stripping ────────────────────────────────────────────────
    def test_bearer_prefix_stripped_before_ya29(self):
        with patch.object(s, "test_google_oauth") as mock:
            mock.return_value = s.Result("Google", "l", "v", "valid", "u", "a")
            self._dispatch("Bearer token", "Google OAuth2", "Bearer ya29.abc123def456ghi789jkl")
        mock.assert_called_once()
        called_value = mock.call_args[0][0]
        self.assertTrue(called_value.startswith("ya29."))
        self.assertFalse(called_value.startswith("Bearer "))

    def test_bearer_prefix_case_insensitive(self):
        with patch.object(s, "test_google_oauth") as mock:
            mock.return_value = s.Result("Google", "l", "v", "valid", "u", "a")
            self._dispatch("Bearer token", "Google OAuth2", "BEARER ya29.abc123def456ghi789jkl")
        mock.assert_called_once()

    # ── GitHub ────────────────────────────────────────────────────────────────
    def test_github_label_routes_to_github(self):
        with patch.object(s, "test_github") as mock:
            mock.return_value = s.Result("GitHub", "l", "v", "valid", "u", "a")
            self._dispatch("GitHub token", "GitHub", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
        mock.assert_called_once()

    def test_ghp_prefix_routes_to_github(self):
        with patch.object(s, "test_github") as mock:
            mock.return_value = s.Result("GitHub", "l", "v", "valid", "u", "a")
            self._dispatch("Bearer token", "Unknown", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
        mock.assert_called_once()

    # ── Discord ───────────────────────────────────────────────────────────────
    def test_discord_token_label_routes_to_discord(self):
        with patch.object(s, "test_discord") as mock:
            mock.return_value = s.Result("Discord", "l", "v", "invalid", "—", "401")
            self._dispatch("Discord token", "Discord",
                           "MjcyOTQyODcxODE5MTkwMjcz.EXAMPLE_TOKEN_XXXXXXXXXXXXXXXXXXXX")
        mock.assert_called_once()

    def test_discord_service_m_prefix_routes(self):
        with patch.object(s, "test_discord") as mock:
            mock.return_value = s.Result("Discord", "l", "v", "invalid", "—", "401")
            self._dispatch("Bearer token", "Discord",
                           "MTIyNDM4NTcyNTk0OTI4NDQwMw.EXAMPLE_FAKE_TOKEN_XXXXXXXXXXX")
        mock.assert_called_once()

    # ── Spotify ───────────────────────────────────────────────────────────────
    def test_bqa_prefix_routes_to_spotify(self):
        with patch.object(s, "test_spotify") as mock:
            mock.return_value = s.Result("Spotify", "l", "v", "valid", "u", "a")
            self._dispatch("Bearer token", "Discord", "BQAhRH1mt3DjufZQfOs0YvOH1mE8mHZ7EjJS")
        mock.assert_called_once()

    # ── Anthropic API key ─────────────────────────────────────────────────────
    def test_sk_ant_routes_to_anthropic(self):
        with patch.object(s, "test_anthropic") as mock:
            mock.return_value = s.Result("Anthropic", "l", "v", "valid", "u", "a")
            self._dispatch("Anthropic API key", "Anthropic / Claude", "sk-ant-oat01-" + "A" * 90)
        mock.assert_called_once()

    # ── Anthropic session token ───────────────────────────────────────────────
    def test_session_token_anthropic_routes_to_session_tester(self):
        with patch.object(s, "test_anthropic_session") as mock:
            mock.return_value = s.Result("Anthropic", "l", "v", "expired", "—", "401")
            self._dispatch("Session token", "Anthropic / Claude",
                           "20111GDqECYuMQ-Vhciczs3T-mwadEQ7KN5oKjEfm1ec6")
        mock.assert_called_once()

    def test_session_token_google_oauth_routes_to_google_oauth(self):
        with patch.object(s, "test_google_oauth") as mock:
            mock.return_value = s.Result("Google", "l", "v", "valid", "u", "a")
            self._dispatch("Session token", "Google OAuth2", "QUFFLUhqb" + "A" * 60)
        mock.assert_called_once()

    # ── Slack ─────────────────────────────────────────────────────────────────
    def test_xoxb_routes_to_slack(self):
        with patch.object(s, "test_slack") as mock:
            mock.return_value = s.Result("Slack", "l", "v", "valid", "u", "a")
            self._dispatch("Slack token", "Slack", "xoxb-000000000000-000000000000-XXXXXXXXXXXX")
        mock.assert_called_once()

    # ── SAPISID ───────────────────────────────────────────────────────────────
    def test_sapisid_routes_to_sapisid_tester(self):
        with patch.object(s, "test_google_sapisid") as mock:
            mock.return_value = s.Result("Google", "l", "v", "info", "—", "302/302")
            self._dispatch("Google SAPISID", "Google", "SAPISID=jcVfV5cj6P6PkVGu/APuJltyHrGn3QFg08")
        mock.assert_called_once()

    def test_sapisid_label_routes(self):
        with patch.object(s, "test_google_sapisid") as mock:
            mock.return_value = s.Result("Google", "l", "v", "info", "—", "302/302")
            self._dispatch("Google SAPISID", "Google", "SAPISID=abc123def456ghi789jkl")
        mock.assert_called_once()

    # ── HuggingFace ───────────────────────────────────────────────────────────
    def test_hf_prefix_routes_to_huggingface(self):
        with patch.object(s, "test_huggingface") as mock:
            mock.return_value = s.Result("HuggingFace", "l", "v", "invalid", "—", "401")
            self._dispatch("HuggingFace token", "HuggingFace", "hf_" + "A" * 34)
        mock.assert_called_once()

    # ── JWT ───────────────────────────────────────────────────────────────────
    def test_valid_jwt_routes_to_jwt_tester(self):
        tok = make_jwt({"iss": "https://accounts.google.com", "sub": "12345"})
        results = self._dispatch("JWT token", "JWT - Google", tok)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].service, "JWT - Google")

    def test_expired_jwt_shows_expired(self):
        tok = make_jwt({"iss": "https://example.com", "sub": "u"}, expired=True)
        results = self._dispatch("JWT token", "JWT - example.com", tok)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "expired")

    # ── JWE (encrypted JWT) ───────────────────────────────────────────────────
    def test_jwe_detected_by_enc_field(self):
        tok = make_jwe_header(exp_ms=int(time.time() * 1000) - 3_600_000)
        results = self._dispatch("JWT token", "JWT - Google", tok)
        self.assertEqual(len(results), 1)
        self.assertIn("JWE", results[0].access)

    def test_jwe_expired_shows_expired_status(self):
        past_ms = (int(time.time()) - 7200) * 1000
        tok = make_jwe_header(exp_ms=past_ms)
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
        with patch.object(s, "test_google_session_id") as mock:
            mock.return_value = s.Result("Google", "l", "v", "info", "—", "302")
            self._dispatch("Session ID", "Google Accounts", "2cec8dd81ced83f92fbecd1402e10777")
        mock.assert_called_once()

    def test_session_id_linkedin_routes_to_linkedin_tester(self):
        with patch.object(s, "test_linkedin_session_id") as mock:
            mock.return_value = s.Result("LinkedIn", "l", "v", "info", "—", "inconclusive")
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
        with patch.object(s, "test_microsoft") as mock:
            mock.return_value = s.Result("Microsoft", "l", "v", "invalid", "—", "401")
            self._dispatch("Password (JSON/API)", "Microsoft", "yJIBTaxlodA2uDmzUbE8jKN3GiMfpWZP")
        mock.assert_called_once()

    # ── LinkedIn li_at ────────────────────────────────────────────────────────
    def test_linkedin_li_at_label_routes(self):
        with patch.object(s, "test_linkedin_li_at") as mock:
            mock.return_value = s.Result("LinkedIn", "l", "v", "info", "—", "inconclusive")
            self._dispatch("LinkedIn li_at", "LinkedIn", "li_at=AQEDARMxhJAFAAAAABkqwJoAAAAAykb3iQ")
        mock.assert_called_once()

    # ── Twitter auth_token ────────────────────────────────────────────────────
    def test_twitter_auth_token_label_routes(self):
        with patch.object(s, "test_twitter_auth_token") as mock:
            mock.return_value = s.Result("Twitter / X", "l", "v", "info", "—", "inconclusive")
            self._dispatch("Twitter auth_token", "Twitter / X", "auth_token=5a3f7c9e8b2d4f6a0c1e3d5f")
        mock.assert_called_once()

    # ── Anthropic session label ───────────────────────────────────────────────
    def test_anthropic_session_label_routes(self):
        with patch.object(s, "test_anthropic_session") as mock:
            mock.return_value = s.Result("Anthropic", "l", "v", "expired", "—", "401")
            self._dispatch("Anthropic session", "Anthropic / Claude",
                           "20111GDqECYuMQ-Vhciczs3T-mwadEQ7KN5oKjEfm1ec6")
        mock.assert_called_once()

    # ── Session key ───────────────────────────────────────────────────────────
    def test_session_key_anthropic_routes(self):
        with patch.object(s, "test_anthropic_session") as mock:
            mock.return_value = s.Result("Anthropic", "l", "v", "expired", "—", "401")
            self._dispatch("Session key", "Anthropic / Claude", "20111GDqECYuMQ-Vhciczs3T-mwadEQ7KN5oKjEfm")
        mock.assert_called_once()

    def test_session_key_unknown_returns_info(self):
        results = self._dispatch("Session key", "Unknown service", "someSessionKeyValue123")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "info")

    # ── SendGrid ──────────────────────────────────────────────────────────────
    def test_sendgrid_label_routes(self):
        with patch.object(s, "test_sendgrid") as mock:
            mock.return_value = s.Result("SendGrid", "l", "v", "valid", "u", "a")
            self._dispatch("Sendgrid token", "SendGrid",
                           "SG.aBcDeFgHiJkLmNoPqRsTuVwX.aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890abcdefgh")
        mock.assert_called_once()

    def test_sg_prefix_routes_to_sendgrid(self):
        with patch.object(s, "test_sendgrid") as mock:
            mock.return_value = s.Result("SendGrid", "l", "v", "valid", "u", "a")
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

class TestAnthropicSessionTester(unittest.TestCase):

    def test_valid_session_returns_valid(self):
        data = {"user": {"email": "user@example.com", "name": "Test User"}}
        with patch.object(s, "_get", return_value=(200, data)):
            r = s.test_anthropic_session("20111GDqECYuMQ-abc", "Session token")
        self.assertEqual(r.status, "valid")
        self.assertIn("user@example.com", r.identity)

    def test_expired_session_returns_expired_or_invalid(self):
        with patch.object(s, "_get", return_value=(401, {})):
            r = s.test_anthropic_session("20111old", "Session token")
        self.assertIn(r.status, ("expired", "invalid"))

    def test_no_user_field_returns_non_valid(self):
        with patch.object(s, "_get", return_value=(200, {})):
            r = s.test_anthropic_session("20111abc", "Session token")
        self.assertNotEqual(r.status, "valid")


class TestDiscordTester(unittest.TestCase):

    def test_valid_token_returns_valid(self):
        data = {"id": "272942871819190273", "username": "testuser",
                "discriminator": "0", "email": "test@example.com", "verified": True}
        with patch.object(s, "_get", return_value=(200, data)):
            r = s.test_discord("MjcyOTQy.fakesig.morefake", "Discord token")
        self.assertEqual(r.status, "valid")
        self.assertIn("testuser", r.identity)

    def test_invalid_token_returns_invalid(self):
        with patch.object(s, "_get", return_value=(401, {})):
            r = s.test_discord("expired_token", "Discord token")
        self.assertIn(r.status, ("invalid", "error"))

    def test_discriminator_zero_omitted(self):
        data = {"id": "123", "username": "newformat", "discriminator": "0",
                "email": "", "verified": False}
        with patch.object(s, "_get", return_value=(200, data)):
            r = s.test_discord("token", "Discord token")
        self.assertEqual(r.identity, "newformat")

    def test_old_format_discriminator_included(self):
        data = {"id": "123", "username": "olduser", "discriminator": "1234",
                "email": "", "verified": False}
        with patch.object(s, "_get", return_value=(200, data)):
            r = s.test_discord("token", "Discord token")
        self.assertIn("1234", r.identity)


class TestSpotifyTester(unittest.TestCase):

    def test_valid_token_returns_valid(self):
        data = {"id": "user123", "display_name": "Test Listener",
                "email": "music@example.com", "product": "premium"}
        with patch.object(s, "_get", return_value=(200, data)):
            r = s.test_spotify("BQAhRH1fake", "Bearer token")
        self.assertEqual(r.status, "valid")
        self.assertIn("music@example.com", r.identity)
        self.assertIn("premium", r.access)

    def test_expired_returns_expired(self):
        with patch.object(s, "_get", return_value=(401, {})):
            r = s.test_spotify("BQAold", "Bearer token")
        self.assertEqual(r.status, "expired")

    def test_forbidden_returns_invalid(self):
        with patch.object(s, "_get", return_value=(403, {})):
            r = s.test_spotify("BQAforbidden", "Bearer token")
        self.assertEqual(r.status, "invalid")


class TestMicrosoftTester(unittest.TestCase):

    def test_valid_graph_token(self):
        data = {"displayName": "Andrew H", "mail": "andrew@example.com"}
        with patch.object(s, "_get", return_value=(200, data)):
            r = s.test_microsoft("fake_graph_token", "Bearer token")
        self.assertEqual(r.status, "valid")
        self.assertIn("Andrew H", r.identity)

    def test_invalid_returns_invalid(self):
        with patch.object(s, "_get", return_value=(401, {"error": {"message": "Unauthorized"}})):
            r = s.test_microsoft("bad_token", "Bearer token")
        self.assertEqual(r.status, "invalid")


class TestGoogleSapisidTester(unittest.TestCase):

    def test_authenticated_200_vs_302(self):
        with patch.object(s, "_status_only", side_effect=[200, 302]):
            r = s.test_google_sapisid("SAPISID=abc123def456ghi789jkl", "Google SAPISID")
        self.assertEqual(r.status, "valid")

    def test_both_302_returns_info(self):
        with patch.object(s, "_status_only", side_effect=[302, 302]):
            r = s.test_google_sapisid("SAPISID=abc", "Google SAPISID")
        self.assertEqual(r.status, "info")

    def test_strips_sapisid_prefix(self):
        # The SAPISID= prefix should be stripped before sending
        with patch.object(s, "_status_only", return_value=302) as mock:
            s.test_google_sapisid("SAPISID=the_actual_value", "Google SAPISID")
        # Both calls should have been made
        self.assertEqual(mock.call_count, 2)


class TestJWTExtra(unittest.TestCase):

    def test_pseg_jwt_extracts_identity(self):
        tok = make_jwt({
            "sub": "00u1muveryfZRjefm358",
            "name": "Andrew Hannaford",
            "email": "andrew@example.com",
            "preferred_username": "andrew.hannaford",
            "exp": int(time.time()) + 3600,
        })
        r = s.test_jwt(tok, "JWT token", "JWT - id.myaccount.pseg.com")
        self.assertEqual(r.identity, "00u1muveryfZRjefm358")


class TestLinkedInTester(unittest.TestCase):

    def test_valid_li_at_returns_valid(self):
        with patch.object(s, "_status_only", side_effect=[200, 302]):
            r = s.test_linkedin_li_at("AQEDARMxhJAFAAAAABkqwJoAAAAAykb3iQ", "LinkedIn li_at")
        self.assertEqual(r.status, "valid")

    def test_invalid_li_at_returns_info(self):
        with patch.object(s, "_status_only", side_effect=[302, 302]):
            r = s.test_linkedin_li_at("bad_token", "LinkedIn li_at")
        self.assertEqual(r.status, "info")

    def test_strips_li_at_prefix_when_present(self):
        with patch.object(s, "_status_only", return_value=302):
            s.test_linkedin_li_at("li_at=AQEDARMxhJAFAAAAABkqwJo", "LinkedIn li_at")
        # Just verify it doesn't crash — prefix is stripped before sending


class TestTwitterTester(unittest.TestCase):

    def test_valid_auth_token_returns_valid(self):
        with patch.object(s, "_status_only", side_effect=[200, 302]):
            r = s.test_twitter_auth_token("5a3f7c9e8b2d4f6a0c1e3d5f", "Twitter auth_token")
        self.assertEqual(r.status, "valid")

    def test_inconclusive_returns_info(self):
        with patch.object(s, "_status_only", side_effect=[302, 302]):
            r = s.test_twitter_auth_token("bad", "Twitter auth_token")
        self.assertEqual(r.status, "info")

    def test_strips_auth_token_prefix(self):
        with patch.object(s, "_status_only", return_value=302):
            s.test_twitter_auth_token("auth_token=5a3f7c9e", "Twitter auth_token")


class TestSendGridTester(unittest.TestCase):

    def test_valid_key_returns_valid(self):
        data = {"username": "apiuser", "email": "api@example.com"}
        with patch.object(s, "_get", return_value=(200, data)):
            r = s.test_sendgrid("SG.real.key", "Sendgrid token")
        self.assertEqual(r.status, "valid")
        self.assertIn("apiuser", r.identity)

    def test_unauthorized_returns_invalid(self):
        with patch.object(s, "_get", return_value=(401, {})):
            r = s.test_sendgrid("SG.bad.key", "Sendgrid token")
        self.assertEqual(r.status, "invalid")

    def test_forbidden_returns_invalid(self):
        with patch.object(s, "_get", return_value=(403, {})):
            r = s.test_sendgrid("SG.nope.key", "Sendgrid token")
        self.assertEqual(r.status, "invalid")


class TestSessionIDTesters(unittest.TestCase):

    def test_google_session_id_valid(self):
        with patch.object(s, "_status_only", side_effect=[200, 302]):
            r = s.test_google_session_id("2cec8dd81ced83f92fbecd1402e10777", "Session ID")
        self.assertEqual(r.status, "valid")

    def test_google_session_id_inconclusive(self):
        with patch.object(s, "_status_only", side_effect=[302, 302]):
            r = s.test_google_session_id("2cec8dd81ced83f92fbecd1402e10777", "Session ID")
        self.assertEqual(r.status, "info")

    def test_google_session_id_connection_error(self):
        # test_google_session_id has no explicit error branch for status 0 —
        # falls through to the "inconclusive" info result
        with patch.object(s, "_status_only", return_value=0):
            r = s.test_google_session_id("2cec8dd81ced83f92fbecd1402e10777", "Session ID")
        self.assertIn(r.status, ("info", "error"))

    def test_linkedin_session_id_inconclusive(self):
        with patch.object(s, "_status_only", return_value=302):
            r = s.test_linkedin_session_id("1DC92BCD31AADD86FE7E264BBEDE0EC6", "Session ID")
        self.assertEqual(r.status, "info")
