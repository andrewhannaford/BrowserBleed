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

class TestResult(unittest.TestCase):
    def _make(self, **kwargs):
        defaults = dict(service="GitHub", label="Bearer Token",
                        value_preview="ghp_XXXX…", status="valid",
                        identity="user", access="read")
        defaults.update(kwargs)
        return s.Result(**defaults)

    def test_to_dict_has_all_keys(self):
        r = self._make()
        d = r.to_dict()
        self.assertSetEqual(set(d.keys()),
            {"service", "label", "value_preview", "status", "identity", "access"})

    def test_to_dict_values_match(self):
        r = self._make(service="Slack", status="expired", identity="alice")
        d = r.to_dict()
        self.assertEqual(d["service"], "Slack")
        self.assertEqual(d["status"], "expired")
        self.assertEqual(d["identity"], "alice")

    def test_raw_defaults_to_empty_dict(self):
        r = s.Result("svc", "lbl", "val", "valid", "id", "access")
        self.assertEqual(r.raw, {})

    def test_raw_stored_when_provided(self):
        r = s.Result("svc", "lbl", "val", "valid", "id", "access", {"key": "val"})
        self.assertEqual(r.raw["key"], "val")


# ── 5. HTTP helper (_get) ─────────────────────────────────────────────────────




if __name__ == "__main__":
    unittest.main()
