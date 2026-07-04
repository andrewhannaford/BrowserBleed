"""Tests for sessiontest.py — credential validation tool."""
import base64
import csv
import io
import json
import os
import ssl
import sys
import tempfile
import time
import unittest
from io import StringIO
from unittest.mock import MagicMock, patch

import sessiontest as s

from tests.conftest import csv_row, http_error, make_jwe_header, make_jwt, make_urlopen_cm, write_csv

# Legacy aliases used throughout this module
_http_error = http_error
_make_urlopen_cm = make_urlopen_cm
_write_csv = write_csv

# AWS STS GetCallerIdentity response for testing
_STS_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/test-user</Arn>
    <UserId>AIDAIOSFODNN7EXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>12345678-1234-1234-1234-123456789012</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>"""

# ── 1. Colour helpers ─────────────────────────────────────────────────────────

class TestGitHub(unittest.TestCase):
    TOKEN = "ghp_" + "A" * 36

    def _mock(self, side_effects):
        return patch("sessiontest._get", side_effect=side_effects)

    def test_valid_with_name_and_email(self):
        user_data = {"login": "victim", "name": "Victim User",
                     "email": "v@company.com", "public_repos": 5}
        with self._mock([(200, user_data), (200, [{"login": "acme"}]), (200, [{"id": 1}])]):
            r = s.test_github(self.TOKEN, "GitHub Token")
        self.assertEqual(r.status, "valid")
        self.assertIn("victim", r.identity)
        self.assertIn("v@company.com", r.identity)
        self.assertIn("acme", r.access)
        self.assertIn("private repos ✓", r.access)
        self.assertIn("5 public repos", r.access)

    def test_valid_without_email(self):
        user_data = {"login": "victim", "name": None, "public_repos": 2}
        with self._mock([(200, user_data), (200, []), (200, [])]):
            r = s.test_github(self.TOKEN, "GitHub Token")
        self.assertEqual(r.status, "valid")
        self.assertNotIn("<", r.identity)  # no email bracket

    def test_valid_no_private_repos(self):
        user_data = {"login": "victim", "public_repos": 0}
        with self._mock([(200, user_data), (200, []), (200, [])]):
            r = s.test_github(self.TOKEN, "GitHub Token")
        self.assertNotIn("private repos", r.access)

    def test_orgs_capped_at_three(self):
        orgs = [{"login": f"org{i}"} for i in range(5)]
        user_data = {"login": "v", "public_repos": 0}
        with self._mock([(200, user_data), (200, orgs), (200, [])]):
            r = s.test_github(self.TOKEN, "GitHub Token")
        shown = r.access.split("orgs: ")[1] if "orgs: " in r.access else ""
        self.assertLessEqual(shown.count(","), 2)

    def test_401_returns_invalid(self):
        with self._mock([(401, {"message": "Bad credentials"})]):
            r = s.test_github(self.TOKEN, "GitHub Token")
        self.assertEqual(r.status, "invalid")
        self.assertIn("401", r.access)

    def test_500_returns_error(self):
        with self._mock([(500, {})]):
            r = s.test_github(self.TOKEN, "GitHub Token")
        self.assertEqual(r.status, "error")

    def test_value_preview_is_twelve_chars(self):
        with self._mock([(401, {})]):
            r = s.test_github(self.TOKEN, "GitHub Token")
        self.assertEqual(r.value_preview, self.TOKEN[:12] + "…")

    def test_orgs_not_a_list_handled(self):
        user_data = {"login": "victim", "public_repos": 0}
        with self._mock([(200, user_data), (200, {"error": "bad"}), (200, [])]):
            r = s.test_github(self.TOKEN, "GitHub Token")
        self.assertEqual(r.status, "valid")  # should not crash


# ── 7. Google OAuth tester ────────────────────────────────────────────────────



class TestGoogleOAuth(unittest.TestCase):
    TOKEN = "ya29.A0AbVbY9aBcDeFgHiJk"

    def test_userinfo_200_with_name(self):
        with patch("sessiontest._get", return_value=(200, {"email": "u@g.com", "name": "Alice"})):
            r = s.test_google_oauth(self.TOKEN, "Bearer Token")
        self.assertEqual(r.status, "valid")
        self.assertIn("Alice", r.identity)
        self.assertIn("u@g.com", r.identity)

    def test_userinfo_200_without_name(self):
        with patch("sessiontest._get", return_value=(200, {"email": "u@g.com"})):
            r = s.test_google_oauth(self.TOKEN, "Bearer Token")
        self.assertEqual(r.status, "valid")
        self.assertEqual(r.identity, "u@g.com")

    def test_userinfo_fails_tokeninfo_succeeds(self):
        responses = [
            (401, {"error": "invalid_token"}),
            (200, {"email": "u@g.com", "scope": "openid email", "expires_in": "3600"}),
        ]
        with patch("sessiontest._get", side_effect=responses):
            r = s.test_google_oauth(self.TOKEN, "Bearer Token")
        self.assertEqual(r.status, "valid")
        self.assertIn("scope", r.access)
        self.assertIn("expires_in", r.access)

    def test_both_fail_expired_error(self):
        responses = [
            (401, {"error_description": "Token has expired"}),
            (401, {}),
        ]
        with patch("sessiontest._get", side_effect=responses):
            r = s.test_google_oauth(self.TOKEN, "Bearer Token")
        self.assertEqual(r.status, "expired")

    def test_both_fail_invalid(self):
        responses = [
            (401, {"error": "invalid_token"}),
            (401, {}),
        ]
        with patch("sessiontest._get", side_effect=responses):
            r = s.test_google_oauth(self.TOKEN, "Bearer Token")
        self.assertEqual(r.status, "invalid")

    def test_both_fail_no_error_key(self):
        responses = [(401, {}), (401, {})]
        with patch("sessiontest._get", side_effect=responses):
            r = s.test_google_oauth(self.TOKEN, "Bearer Token")
        self.assertIn(r.status, ("invalid", "expired"))


# ── 8. Slack tester ───────────────────────────────────────────────────────────



class TestSlack(unittest.TestCase):
    TOKEN = "xoxp-111-222-333-abc"

    def test_valid(self):
        data = {"ok": True, "user": "alice", "team": "acme", "url": "https://acme.slack.com/"}
        with patch("sessiontest._get", return_value=(200, data)):
            r = s.test_slack(self.TOKEN, "Slack Token")
        self.assertEqual(r.status, "valid")
        self.assertIn("alice", r.identity)
        self.assertIn("acme", r.identity)
        self.assertEqual(r.access, "https://acme.slack.com/")

    def test_token_revoked(self):
        with patch("sessiontest._get", return_value=(200, {"ok": False, "error": "token_revoked"})):
            r = s.test_slack(self.TOKEN, "Slack Token")
        self.assertEqual(r.status, "expired")

    def test_token_expired(self):
        with patch("sessiontest._get", return_value=(200, {"ok": False, "error": "token_expired"})):
            r = s.test_slack(self.TOKEN, "Slack Token")
        self.assertEqual(r.status, "expired")

    def test_invalid_other_error(self):
        with patch("sessiontest._get", return_value=(200, {"ok": False, "error": "invalid_auth"})):
            r = s.test_slack(self.TOKEN, "Slack Token")
        self.assertEqual(r.status, "invalid")

    def test_http_error(self):
        with patch("sessiontest._get", return_value=(500, {})):
            r = s.test_slack(self.TOKEN, "Slack Token")
        self.assertEqual(r.status, "invalid")  # no "ok" key → falls through to err branch

    def test_value_preview_is_fourteen_chars(self):
        with patch("sessiontest._get", return_value=(401, {})):
            r = s.test_slack(self.TOKEN, "Slack Token")
        self.assertEqual(r.value_preview, self.TOKEN[:14] + "…")


# ── 9. Anthropic tester ───────────────────────────────────────────────────────



class TestAnthropic(unittest.TestCase):
    KEY = "sk-ant-api03-" + "A" * 40

    def test_valid_with_models(self):
        data = {"data": [{"id": "claude-3-opus"}, {"id": "claude-3-sonnet"}]}
        with patch("sessiontest._get", return_value=(200, data)):
            r = s.test_anthropic(self.KEY, "Anthropic Key")
        self.assertEqual(r.status, "valid")
        self.assertIn("claude-3-opus", r.access)

    def test_valid_no_models(self):
        with patch("sessiontest._get", return_value=(200, {"data": []})):
            r = s.test_anthropic(self.KEY, "Anthropic Key")
        self.assertEqual(r.status, "valid")

    def test_401_invalid(self):
        data = {"error": {"message": "Invalid API key", "type": "authentication_error"}}
        with patch("sessiontest._get", return_value=(401, data)):
            r = s.test_anthropic(self.KEY, "Anthropic Key")
        self.assertEqual(r.status, "invalid")
        self.assertIn("Invalid API key", r.access)

    def test_403_invalid(self):
        with patch("sessiontest._get", return_value=(403, {})):
            r = s.test_anthropic(self.KEY, "Anthropic Key")
        self.assertEqual(r.status, "invalid")

    def test_500_error(self):
        with patch("sessiontest._get", return_value=(500, {})):
            r = s.test_anthropic(self.KEY, "Anthropic Key")
        self.assertEqual(r.status, "error")

    def test_error_as_string_not_dict(self):
        with patch("sessiontest._get", return_value=(401, {"error": "unauthorized"})):
            r = s.test_anthropic(self.KEY, "Anthropic Key")
        self.assertEqual(r.status, "invalid")
        self.assertEqual(r.access, "unauthorized")


# ── 10. OpenAI tester ────────────────────────────────────────────────────────



class TestOpenAI(unittest.TestCase):
    KEY = "sk-" + "A" * 48

    def test_valid_with_models(self):
        data = {"data": [{"id": "gpt-4"}, {"id": "gpt-3.5-turbo"}]}
        with patch("sessiontest._get", return_value=(200, data)):
            r = s.test_openai(self.KEY, "OpenAI Key")
        self.assertEqual(r.status, "valid")
        self.assertIn("gpt-4", r.access)

    def test_401_invalid(self):
        data = {"error": {"message": "Incorrect API key", "type": "invalid_request_error"}}
        with patch("sessiontest._get", return_value=(401, data)):
            r = s.test_openai(self.KEY, "OpenAI Key")
        self.assertEqual(r.status, "invalid")

    def test_403_invalid(self):
        with patch("sessiontest._get", return_value=(403, {})):
            r = s.test_openai(self.KEY, "OpenAI Key")
        self.assertEqual(r.status, "invalid")

    def test_500_error(self):
        with patch("sessiontest._get", return_value=(500, {})):
            r = s.test_openai(self.KEY, "OpenAI Key")
        self.assertEqual(r.status, "error")

    def test_error_as_string(self):
        with patch("sessiontest._get", return_value=(401, {"error": "bad key"})):
            r = s.test_openai(self.KEY, "OpenAI Key")
        self.assertEqual(r.access, "bad key")

    def test_value_preview_is_fourteen_chars(self):
        with patch("sessiontest._get", return_value=(401, {})):
            r = s.test_openai(self.KEY, "OpenAI Key")
        self.assertEqual(r.value_preview, self.KEY[:14] + "…")


# ── 11. HuggingFace tester ───────────────────────────────────────────────────



class TestHuggingFace(unittest.TestCase):
    KEY = "hf_" + "A" * 33

    def test_valid_with_email_and_orgs(self):
        data = {"name": "alice", "email": "a@hf.co", "orgs": [{"name": "BigCorp"}]}
        with patch("sessiontest._get", return_value=(200, data)):
            r = s.test_huggingface(self.KEY, "HuggingFace Token")
        self.assertEqual(r.status, "valid")
        self.assertIn("alice", r.identity)
        self.assertIn("a@hf.co", r.identity)
        self.assertIn("BigCorp", r.access)

    def test_valid_without_email(self):
        data = {"name": "bob", "orgs": []}
        with patch("sessiontest._get", return_value=(200, data)):
            r = s.test_huggingface(self.KEY, "HuggingFace Token")
        self.assertEqual(r.identity, "bob")
        self.assertEqual(r.access, "no orgs")

    def test_orgs_capped_at_three(self):
        data = {"name": "alice", "orgs": [{"name": f"org{i}"} for i in range(5)]}
        with patch("sessiontest._get", return_value=(200, data)):
            r = s.test_huggingface(self.KEY, "HuggingFace Token")
        self.assertLessEqual(r.access.count(","), 2)

    def test_401_invalid(self):
        with patch("sessiontest._get", return_value=(401, {})):
            r = s.test_huggingface(self.KEY, "HuggingFace Token")
        self.assertEqual(r.status, "invalid")

    def test_500_error(self):
        with patch("sessiontest._get", return_value=(500, {})):
            r = s.test_huggingface(self.KEY, "HuggingFace Token")
        self.assertEqual(r.status, "error")


# ── 12. Stripe tester ────────────────────────────────────────────────────────



class TestStripe(unittest.TestCase):
    LIVE_KEY = "sk_live_" + "A" * 24
    TEST_KEY = "sk_test_" + "A" * 24

    def test_valid_live_with_business_name(self):
        data = {
            "id": "acct_123", "email": "owner@biz.com",
            "livemode": True,
            "business_profile": {"name": "Acme Corp"},
        }
        with patch("sessiontest._get", return_value=(200, data)):
            r = s.test_stripe(self.LIVE_KEY, "Stripe Key")
        self.assertEqual(r.status, "valid")
        self.assertIn("Acme Corp", r.identity)
        self.assertIn("LIVE", r.access)

    def test_valid_test_mode_no_business_name(self):
        data = {"id": "acct_456", "email": "dev@example.com", "livemode": False,
                "business_profile": {}}
        with patch("sessiontest._get", return_value=(200, data)):
            r = s.test_stripe(self.TEST_KEY, "Stripe Key")
        self.assertIn("test", r.access)
        self.assertEqual(r.identity, "dev@example.com")

    def test_valid_no_email_falls_back_to_id(self):
        data = {"id": "acct_789", "livemode": False, "business_profile": {}}
        with patch("sessiontest._get", return_value=(200, data)):
            r = s.test_stripe(self.TEST_KEY, "Stripe Key")
        self.assertEqual(r.identity, "acct_789")

    def test_401_invalid(self):
        data = {"error": {"message": "No such API key"}}
        with patch("sessiontest._get", return_value=(401, data)):
            r = s.test_stripe(self.LIVE_KEY, "Stripe Key")
        self.assertEqual(r.status, "invalid")
        self.assertIn("No such API key", r.access)

    def test_500_error(self):
        with patch("sessiontest._get", return_value=(500, {})):
            r = s.test_stripe(self.LIVE_KEY, "Stripe Key")
        self.assertEqual(r.status, "error")

    def test_error_as_string(self):
        with patch("sessiontest._get", return_value=(403, {"error": "forbidden"})):
            r = s.test_stripe(self.LIVE_KEY, "Stripe Key")
        self.assertEqual(r.status, "invalid")
        self.assertEqual(r.access, "forbidden")


# ── 13. npm tester ────────────────────────────────────────────────────────────



class TestNpm(unittest.TestCase):
    KEY = "npm_" + "A" * 36

    def test_valid(self):
        with patch("sessiontest._get", return_value=(200, {"username": "npmuser"})):
            r = s.test_npm(self.KEY, "npm Token")
        self.assertEqual(r.status, "valid")
        self.assertEqual(r.identity, "npmuser")
        self.assertEqual(r.access, "registry access confirmed")

    def test_401_invalid(self):
        with patch("sessiontest._get", return_value=(401, {})):
            r = s.test_npm(self.KEY, "npm Token")
        self.assertEqual(r.status, "invalid")

    def test_403_invalid(self):
        with patch("sessiontest._get", return_value=(403, {})):
            r = s.test_npm(self.KEY, "npm Token")
        self.assertEqual(r.status, "invalid")

    def test_500_error(self):
        with patch("sessiontest._get", return_value=(500, {})):
            r = s.test_npm(self.KEY, "npm Token")
        self.assertEqual(r.status, "error")

    def test_preview_is_sixteen_chars(self):
        with patch("sessiontest._get", return_value=(401, {})):
            r = s.test_npm(self.KEY, "npm Token")
        self.assertEqual(r.value_preview, self.KEY[:16] + "…")


# ── 14. JWT tester ────────────────────────────────────────────────────────────



class TestAWS(unittest.TestCase):
    KEY    = "AKIAIOSFODNN7EXAMPLE"      # AWS's official documentation example key — not a real credential
    SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    @patch("sessiontest.urllib.request.urlopen")
    def test_valid_parses_arn_and_account(self, mock_open):
        mock_open.return_value = _make_urlopen_cm(_STS_XML)
        r = s.test_aws(self.KEY, self.SECRET, "AWS Key")
        self.assertEqual(r.status, "valid")
        self.assertIn("arn:aws:iam::123456789012:user/test-user", r.identity)
        self.assertIn("123456789012", r.access)
        self.assertIn("AIDAIOSFODNN7EXAMPLE", r.access)

    @patch("sessiontest.urllib.request.urlopen")
    def test_401_returns_invalid(self, mock_open):
        mock_open.side_effect = _http_error(401)
        r = s.test_aws(self.KEY, self.SECRET, "AWS Key")
        self.assertEqual(r.status, "invalid")

    @patch("sessiontest.urllib.request.urlopen")
    def test_403_returns_invalid(self, mock_open):
        mock_open.side_effect = _http_error(403)
        r = s.test_aws(self.KEY, self.SECRET, "AWS Key")
        self.assertEqual(r.status, "invalid")

    @patch("sessiontest.urllib.request.urlopen")
    def test_500_returns_error(self, mock_open):
        mock_open.side_effect = _http_error(500)
        r = s.test_aws(self.KEY, self.SECRET, "AWS Key")
        self.assertEqual(r.status, "error")

    @patch("sessiontest.urllib.request.urlopen")
    def test_network_exception_returns_error(self, mock_open):
        mock_open.side_effect = Exception("connection refused")
        r = s.test_aws(self.KEY, self.SECRET, "AWS Key")
        self.assertEqual(r.status, "error")
        self.assertIn("connection refused", r.access)

    @patch("sessiontest.urllib.request.urlopen")
    def test_preview_is_sixteen_chars(self, mock_open):
        mock_open.return_value = _make_urlopen_cm(_STS_XML)
        r = s.test_aws(self.KEY, self.SECRET, "AWS Key")
        self.assertEqual(r.value_preview, self.KEY[:16] + "…")

    @patch("sessiontest.urllib.request.urlopen")
    def test_sigv4_auth_header_present(self, mock_open):
        mock_open.return_value = _make_urlopen_cm(_STS_XML)
        s.test_aws(self.KEY, self.SECRET, "AWS Key")
        req = mock_open.call_args[0][0]
        auth = req.get_header("Authorization")
        self.assertIn("AWS4-HMAC-SHA256", auth)
        self.assertIn(self.KEY, auth)


# ── 16. Cookie session tester ─────────────────────────────────────────────────



class TestCookieSession(unittest.TestCase):
    def test_known_domain_with_key_cookie_valid(self):
        cookies = [{"name": "_gh_sess", "value": "abc123"},
                   {"name": "user_session", "value": "xyz"}]
        def _fake_status(url, headers):
            return 200 if "Cookie" in headers else 302
        with patch("sessiontest._status_only", side_effect=_fake_status):
            results = s.test_cookie_session("github.com", cookies, browser=False)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "valid")
        self.assertEqual(results[0].identity, "authenticated")

    def test_known_domain_with_key_cookie_non_200(self):
        cookies = [{"name": "user_session", "value": "expired"}]
        with patch("sessiontest._status_only", return_value=302):
            results = s.test_cookie_session("github.com", cookies, browser=False)
        self.assertEqual(results[0].status, "invalid")

    def test_known_domain_missing_key_cookie(self):
        cookies = [{"name": "some_other_cookie", "value": "val"}]
        results = s.test_cookie_session("github.com", cookies, browser=False)
        self.assertEqual(results[0].status, "info")
        self.assertIn("user_session", results[0].access)

    def test_unknown_domain_returns_info(self):
        cookies = [{"name": "session", "value": "abc"}]
        with patch("sessiontest._status_only", return_value=200):
            results = s.test_cookie_session("unknown-app.internal", cookies, browser=False)
        self.assertEqual(results[0].status, "info")
        self.assertIn("--browser", results[0].access)

    def test_subdomain_lookup_via_strip_sub(self):
        # api.github.com should resolve to .github.com → github.com entry
        cookies = [{"name": "user_session", "value": "abc"}]
        def _fake_status(url, headers):
            return 200 if "Cookie" in headers else 302
        with patch("sessiontest._status_only", side_effect=_fake_status):
            results = s.test_cookie_session("api.github.com", cookies, browser=False)
        self.assertEqual(results[0].status, "valid")

    def test_more_than_six_cookies_shows_overflow(self):
        cookies = [{"name": f"c{i}", "value": "v"} for i in range(8)]
        with patch("sessiontest._status_only", return_value=200):
            results = s.test_cookie_session("unknown.com", cookies, browser=False)
        self.assertIn("+2 more", results[0].value_preview)

    def test_browser_true_calls_open_browser_session(self):
        cookies = [{"name": "session", "value": "abc"}]
        with patch("sessiontest._open_browser_session") as mock_browser:
            with patch("sessiontest._status_only", return_value=200):
                s.test_cookie_session("example.com", cookies, browser=True)
        mock_browser.assert_called_once_with("example.com", cookies)

    def test_browser_false_does_not_call_open_browser_session(self):
        cookies = [{"name": "session", "value": "abc"}]
        with patch("sessiontest._open_browser_session") as mock_browser:
            with patch("sessiontest._status_only", return_value=200):
                s.test_cookie_session("example.com", cookies, browser=False)
        mock_browser.assert_not_called()


# ── 17. _strip_sub ────────────────────────────────────────────────────────────




if __name__ == "__main__":
    unittest.main()
