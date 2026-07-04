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

class TestColour(unittest.TestCase):
    def test_no_tty_returns_plain(self):
        # In test context stdout is not a tty — colours should be stripped
        self.assertEqual(s._colour("32", "hello"), "hello")

    def test_tty_wraps_with_ansi(self):
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            result = s._colour("32", "hello")
        self.assertIn("\033[32m", result)
        self.assertIn("hello", result)
        self.assertIn("\033[0m", result)

    def test_colour_lambdas_exist(self):
        # Verify all colour lambdas are callable and return strings
        for fn in (s.green, s.red, s.yellow, s.cyan, s.bold, s.dim):
            self.assertIsInstance(fn("x"), str)


# ── 2. Base64 padding ─────────────────────────────────────────────────────────



class TestB64Pad(unittest.TestCase):
    def test_no_padding_needed(self):
        self.assertEqual(s._b64pad("abcd"), "abcd")

    def test_one_pad(self):
        self.assertEqual(s._b64pad("abc"), "abc=")

    def test_two_pads(self):
        self.assertEqual(s._b64pad("ab"), "ab==")

    def test_three_pads(self):
        self.assertEqual(s._b64pad("a"), "a===")

    def test_empty_string(self):
        self.assertEqual(s._b64pad(""), "")


# ── 3. JWT decode ─────────────────────────────────────────────────────────────



class TestDisplayHelpers(unittest.TestCase):
    def test_status_str_valid(self):
        self.assertIn("valid", s._status_str("valid"))

    def test_status_str_expired(self):
        self.assertIn("expired", s._status_str("expired"))

    def test_status_str_invalid(self):
        self.assertIn("invalid", s._status_str("invalid"))

    def test_status_str_error(self):
        self.assertIn("error", s._status_str("error"))

    def test_status_str_info(self):
        self.assertIn("info", s._status_str("info"))

    def test_status_str_unknown_returns_info(self):
        result = s._status_str("something_unknown")
        self.assertIn("info", result)

    def test_print_progress_no_crash(self):
        r = s.Result("GitHub", "JWT", "tok…", "valid", "alice", "5 repos")
        out = io.StringIO()
        with patch("sys.stdout", out):
            s._print_progress(1, 10, r)
        self.assertIn("GitHub", out.getvalue())

    def test_print_table_no_crash(self):
        results = [
            s.Result("GitHub", "Bearer Token", "ghp_XXXX…", "valid", "alice", "5 repos"),
            s.Result("Slack",  "Slack Token",  "xoxp-XX…",  "expired", "—", "token_expired"),
        ]
        out = io.StringIO()
        with patch("sys.stdout", out):
            s._print_table(results)
        output = out.getvalue()
        self.assertIn("GitHub", output)
        self.assertIn("Slack",  output)

    def test_print_table_valid_shows_access(self):
        results = [s.Result("GitHub", "Token", "tok…", "valid", "alice", "5 repos, 2 orgs")]
        out = io.StringIO()
        with patch("sys.stdout", out):
            s._print_table(results)
        self.assertIn("5 repos, 2 orgs", out.getvalue())

    def test_print_table_non_valid_skips_access_line(self):
        results = [s.Result("GitHub", "Token", "tok…", "invalid", "—", "token rejected")]
        out = io.StringIO()
        with patch("sys.stdout", out):
            s._print_table(results)
        # access line printed only for valid/info — for invalid it should not appear
        self.assertNotIn("token rejected", out.getvalue())




if __name__ == "__main__":
    unittest.main()
