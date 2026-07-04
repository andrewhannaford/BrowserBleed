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

class TestGet(unittest.TestCase):
    def _cm(self, status, body):
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=cm)
        cm.__exit__  = MagicMock(return_value=False)
        cm.status    = status
        cm.read      = MagicMock(return_value=body)
        return cm

    @patch("sessiontest.urllib.request.urlopen")
    def test_200_json_response(self, mock_open):
        mock_open.return_value = self._cm(200, b'{"login":"user"}')
        code, data = s._get("https://x", {})
        self.assertEqual(code, 200)
        self.assertEqual(data["login"], "user")

    @patch("sessiontest.urllib.request.urlopen")
    def test_200_non_json_returns_empty_dict(self, mock_open):
        mock_open.return_value = self._cm(200, b"<html>not json</html>")
        code, data = s._get("https://x", {})
        self.assertEqual(code, 200)
        self.assertEqual(data, {})

    @patch("sessiontest.urllib.request.urlopen")
    def test_http_error_with_json_body(self, mock_open):
        mock_open.side_effect = _http_error(401, b'{"error":"invalid_token"}')
        code, data = s._get("https://x", {})
        self.assertEqual(code, 401)
        self.assertEqual(data["error"], "invalid_token")

    @patch("sessiontest.urllib.request.urlopen")
    def test_http_error_without_json_body(self, mock_open):
        mock_open.side_effect = _http_error(403, b"Forbidden")
        code, data = s._get("https://x", {})
        self.assertEqual(code, 403)
        self.assertEqual(data, {})

    @patch("sessiontest.urllib.request.urlopen")
    def test_network_error_returns_zero(self, mock_open):
        mock_open.side_effect = Exception("timeout")
        code, data = s._get("https://x", {})
        self.assertEqual(code, 0)
        self.assertIn("_error", data)

    @patch("sessiontest.urllib.request.urlopen")
    def test_post_method_passed_through(self, mock_open):
        mock_open.return_value = self._cm(200, b"{}")
        s._get("https://x", {}, body=b"data", method="POST")
        req = mock_open.call_args[0][0]
        self.assertEqual(req.get_method(), "POST")


# ── 6. GitHub tester ──────────────────────────────────────────────────────────




if __name__ == "__main__":
    unittest.main()
