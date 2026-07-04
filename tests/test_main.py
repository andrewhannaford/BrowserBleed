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

# ── 1. Colour helpers ─────────────────────────────────────────────────────────

class TestMain(unittest.TestCase):
    def _run(self, argv, stdin_data=""):
        with patch("sys.argv", ["sessiontest.py"] + argv), \
             patch("sys.stdout", new_callable=StringIO) as mock_out, \
             patch("time.sleep"):
            try:
                s.main()
            except SystemExit as e:
                return e.code, mock_out.getvalue()
            return 0, mock_out.getvalue()

    def test_no_csv_found_exits_1(self):
        with patch("sessiontest._find_csv", return_value=None):
            code, out = self._run([])
        self.assertEqual(code, 1)

    def test_missing_file_exits_1(self):
        code, out = self._run(["/nonexistent/path/results.csv"])
        self.assertEqual(code, 1)

    def test_empty_csv_exits_0(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
            f.write("browser,profile,label,service,value,address\n")
        try:
            code, out = self._run([path])
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)

    def test_unrecognised_creds_prints_no_testable_message(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
        try:
            _write_csv(path, [
                {"browser": "Chrome", "profile": "Default", "label": "Saved Credential",
                 "service": "example.com", "value": "user:pass", "address": "example.com"},
            ])
            code, out = self._run([path])
            self.assertEqual(code, 0)
            self.assertIn("No testable credentials", out)
        finally:
            os.unlink(path)

    def test_json_flag_outputs_valid_json(self):
        jwt = make_jwt({"sub": "user", "exp": 9999999999})
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
        try:
            _write_csv(path, [
                {"browser": "Chrome", "profile": "Default", "label": "JWT",
                 "service": "Google", "value": jwt, "address": "0x1"},
            ])
            code, out = self._run([path, "--json"])
            data = json.loads(out)
            self.assertIsInstance(data, list)
            self.assertEqual(data[0]["service"], "Google")
        finally:
            os.unlink(path)

    def test_deduplication_tests_each_value_once(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
        try:
            _write_csv(path, [
                {"browser": "Chrome", "profile": "Default", "label": "GitHub Token",
                 "service": "GitHub", "value": "ghp_" + "A" * 36, "address": "0x1"},
                {"browser": "Chrome", "profile": "Default", "label": "GitHub Token",
                 "service": "GitHub", "value": "ghp_" + "A" * 36, "address": "0x2"},  # duplicate
            ])
            call_count = []
            orig = s.test_github
            def counting_test_github(v, l):
                call_count.append(1)
                return s.Result("GitHub", l, v[:12]+"…", "valid", "u", "access")
            with patch("sessiontest.test_github", side_effect=counting_test_github):
                self._run([path])
            self.assertEqual(len(call_count), 1)
        finally:
            os.unlink(path)

    def test_cookies_grouped_by_domain(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
        try:
            _write_csv(path, [
                {"browser": "Chrome", "profile": "Default", "label": "Cookie",
                 "service": "github.com", "value": "_gh_sess=abc", "address": "github.com"},
                {"browser": "Chrome", "profile": "Default", "label": "Cookie",
                 "service": "github.com", "value": "user_session=xyz", "address": "github.com"},
            ])
            cookie_calls = []
            def mock_cookie_session(domain, cookies, *, browser):
                cookie_calls.append((domain, len(cookies)))
                return [s.Result(domain, "Cookie session", "", "info", "—", "x", {})]
            with patch("sessiontest.test_cookie_session", side_effect=mock_cookie_session):
                self._run([path])
            self.assertEqual(len(cookie_calls), 1)
            self.assertEqual(cookie_calls[0][0], "github.com")
            self.assertEqual(cookie_calls[0][1], 2)
        finally:
            os.unlink(path)

    def test_cookie_deduplication(self):
        """Same domain+name+value pair should only appear once."""
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
        try:
            _write_csv(path, [
                {"browser": "Chrome", "profile": "Default", "label": "Cookie",
                 "service": "github.com", "value": "_gh_sess=abc", "address": "github.com"},
                {"browser": "Chrome", "profile": "Default", "label": "Cookie",
                 "service": "github.com", "value": "_gh_sess=abc", "address": "github.com"},  # dup
            ])
            cookie_calls = []
            def mock_cookie_session(domain, cookies, *, browser):
                cookie_calls.append(len(cookies))
                return []
            with patch("sessiontest.test_cookie_session", side_effect=mock_cookie_session):
                self._run([path])
            self.assertEqual(cookie_calls[0], 1)
        finally:
            os.unlink(path)

    def test_aws_paired_with_secret(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
        try:
            _write_csv(path, [
                {"browser": "Chrome", "profile": "Default", "label": "AWS Key",
                 "service": "AWS", "value": "AKIAIOSFODNN7EXAMPLE", "address": "0x1"},
                {"browser": "Chrome", "profile": "Default", "label": "AWS Secret Key",
                 "service": "AWS", "value": "A" * 40, "address": "0x2"},
            ])
            aws_calls = []
            def mock_test_aws(key, secret, label):
                aws_calls.append((key, secret))
                return s.Result("AWS", label, key[:16]+"…", "valid", "arn:...", "account", {})
            with patch("sessiontest.test_aws", side_effect=mock_test_aws):
                self._run([path])
            self.assertEqual(len(aws_calls), 1)
            self.assertEqual(aws_calls[0][0], "AKIAIOSFODNN7EXAMPLE")
            self.assertEqual(aws_calls[0][1], "A" * 40)
        finally:
            os.unlink(path)

    def test_aws_without_secret_shows_info(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
        try:
            _write_csv(path, [
                {"browser": "Chrome", "profile": "Default", "label": "AWS Key",
                 "service": "AWS", "value": "AKIAIOSFODNN7EXAMPLE", "address": "0x1"},
            ])
            code, out = self._run([path, "--json"])
            data = json.loads(out)
            self.assertTrue(any(r["service"] == "AWS" and r["status"] == "info" for r in data))
        finally:
            os.unlink(path)

    def test_no_verify_ssl_disables_cert_check(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
            f.write("browser,profile,label,service,value,address\n")
        try:
            original_ctx = s._ssl_ctx
            self._run([path, "--no-verify-ssl"])
            self.assertFalse(s._ssl_ctx.check_hostname)
            self.assertEqual(s._ssl_ctx.verify_mode, ssl.CERT_NONE)
        finally:
            os.unlink(path)
            # Restore
            s._ssl_ctx = original_ctx

    def test_timeout_flag_sets_global(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
            f.write("browser,profile,label,service,value,address\n")
        try:
            original = s._timeout
            self._run([path, "--timeout", "42"])
            self.assertEqual(s._timeout, 42)
        finally:
            os.unlink(path)
            s._timeout = original

    def test_empty_domain_cookie_skipped(self):
        """Cookies with no domain should be silently skipped."""
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
        try:
            _write_csv(path, [
                {"browser": "Chrome", "profile": "Default", "label": "Cookie",
                 "service": "", "value": "session=abc", "address": ""},
            ])
            cookie_calls = []
            def mock_cookie_session(domain, cookies, *, browser):
                cookie_calls.append(domain)
                return []
            with patch("sessiontest.test_cookie_session", side_effect=mock_cookie_session):
                self._run([path])
            self.assertEqual(cookie_calls, [])
        finally:
            os.unlink(path)

    def test_cookie_value_without_equals_handled(self):
        """Cookie value with no '=' still parses without crash."""
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
        try:
            _write_csv(path, [
                {"browser": "Chrome", "profile": "Default", "label": "Cookie",
                 "service": "example.com", "value": "noequalssign", "address": "example.com"},
            ])
            with patch("sessiontest.test_cookie_session", return_value=[]):
                code, _ = self._run([path])
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)


# ── 24. Display helpers ───────────────────────────────────────────────────────



class TestDispatch(unittest.TestCase):
    def _run(self, label, service, value):
        with patch("sessiontest.test_github",       return_value=MagicMock(spec=s.Result)) as g, \
             patch("sessiontest.test_google_oauth", return_value=MagicMock(spec=s.Result)) as go, \
             patch("sessiontest.test_slack",        return_value=MagicMock(spec=s.Result)) as sl, \
             patch("sessiontest.test_anthropic",    return_value=MagicMock(spec=s.Result)) as an, \
             patch("sessiontest.test_openai",       return_value=MagicMock(spec=s.Result)) as oi, \
             patch("sessiontest.test_huggingface",  return_value=MagicMock(spec=s.Result)) as hf, \
             patch("sessiontest.test_stripe",       return_value=MagicMock(spec=s.Result)) as st, \
             patch("sessiontest.test_npm",          return_value=MagicMock(spec=s.Result)) as np, \
             patch("sessiontest.test_jwt",          return_value=MagicMock(spec=s.Result)) as jw:
            results = s._dispatch(label, service, value, browser=False)
            return results, g, go, sl, an, oi, hf, st, np, jw

    # GitHub prefixes
    def test_dispatch_ghp(self):
        _, g, *_ = self._run("Token", "", "ghp_" + "A" * 36)
        g.assert_called_once()

    def test_dispatch_gho(self):
        _, g, *_ = self._run("Token", "", "gho_" + "A" * 36)
        g.assert_called_once()

    def test_dispatch_ghs(self):
        _, g, *_ = self._run("Token", "", "ghs_" + "A" * 36)
        g.assert_called_once()

    def test_dispatch_ghr(self):
        _, g, *_ = self._run("Token", "", "ghr_" + "A" * 36)
        g.assert_called_once()

    def test_dispatch_ghu(self):
        _, g, *_ = self._run("Token", "", "ghu_" + "A" * 36)
        g.assert_called_once()

    def test_dispatch_github_label(self):
        _, g, *_ = self._run("GitHub Token", "", "sometoken")
        g.assert_called_once()

    # Google OAuth
    def test_dispatch_google_oauth(self):
        _, _, go, *_ = self._run("Bearer Token", "", "ya29.A0AbVbY9aBcDeFgHiJk")
        go.assert_called_once()

    # Slack prefixes
    def test_dispatch_xoxp(self):
        _, _, _, sl, *_ = self._run("Token", "", "xoxp-111-222-333-abc")
        sl.assert_called_once()

    def test_dispatch_xoxb(self):
        _, _, _, sl, *_ = self._run("Token", "", "xoxb-111-222-333-abc")
        sl.assert_called_once()

    def test_dispatch_xoxa(self):
        _, _, _, sl, *_ = self._run("Token", "", "xoxa-111-222-333-abc")
        sl.assert_called_once()

    def test_dispatch_xoxs(self):
        _, _, _, sl, *_ = self._run("Token", "", "xoxs-111-222-333-abc")
        sl.assert_called_once()

    def test_dispatch_xoxe(self):
        _, _, _, sl, *_ = self._run("Token", "", "xoxe-111-222-333-abc")
        sl.assert_called_once()

    # Anthropic
    def test_dispatch_anthropic(self):
        _, _, _, _, an, *_ = self._run("Token", "", "sk-ant-api03-" + "A" * 40)
        an.assert_called_once()

    # OpenAI (sk- but not sk-ant-)
    def test_dispatch_openai(self):
        _, _, _, _, _, oi, *_ = self._run("Token", "", "sk-" + "A" * 48)
        oi.assert_called_once()

    def test_sk_ant_not_dispatched_to_openai(self):
        _, _, _, _, an, oi, *_ = self._run("Token", "", "sk-ant-api03-" + "A" * 40)
        oi.assert_not_called()

    # HuggingFace
    def test_dispatch_huggingface(self):
        _, _, _, _, _, _, hf, *_ = self._run("Token", "", "hf_" + "A" * 33)
        hf.assert_called_once()

    # Stripe
    def test_dispatch_stripe_live(self):
        _, _, _, _, _, _, _, st, *_ = self._run("Token", "", "sk_live_" + "A" * 24)
        st.assert_called_once()

    def test_dispatch_stripe_test(self):
        _, _, _, _, _, _, _, st, *_ = self._run("Token", "", "sk_test_" + "A" * 24)
        st.assert_called_once()

    def test_dispatch_stripe_rk_live(self):
        _, _, _, _, _, _, _, st, *_ = self._run("Token", "", "rk_live_" + "A" * 24)
        st.assert_called_once()

    # npm
    def test_dispatch_npm_label(self):
        _, _, _, _, _, _, _, _, np, *_ = self._run("npm Token", "", "some-uuid-token-here")
        np.assert_called_once()

    # JWT — three base64url parts, each >10 chars
    def test_dispatch_jwt(self):
        jwt = make_jwt({"sub": "u", "exp": 9999999999})
        _, _, _, _, _, _, _, _, _, jw = self._run("JWT", "Google", jwt)
        jw.assert_called_once()

    def test_jwt_not_dispatched_if_parts_too_short(self):
        _, _, _, _, _, _, _, _, _, jw = self._run("JWT", "", "short.parts.here")
        jw.assert_not_called()

    # Bearer with service hints
    def test_dispatch_bearer_github_service(self):
        _, g, *_ = self._run("Bearer Token", "GitHub", "some_opaque_token")
        g.assert_called_once()

    def test_dispatch_bearer_google_service(self):
        _, _, go, *_ = self._run("Bearer Token", "Google", "some_opaque_token")
        go.assert_called_once()

    def test_dispatch_bearer_slack_service(self):
        _, _, _, sl, *_ = self._run("Bearer Token", "Slack", "some_opaque_token")
        sl.assert_called_once()

    def test_dispatch_bearer_unknown_service_returns_empty(self):
        results, *_ = self._run("Bearer Token", "Unknown", "some_opaque_token")
        self.assertEqual(results, [])

    # Unrecognised
    def test_unrecognised_returns_empty(self):
        results, *_ = self._run("Saved Credential", "", "user:password123")
        self.assertEqual(results, [])


# ── 21. _find_csv ─────────────────────────────────────────────────────────────




if __name__ == "__main__":
    unittest.main()
