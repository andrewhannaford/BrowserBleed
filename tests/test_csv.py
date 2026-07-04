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

class TestFindCSV(unittest.TestCase):
    def test_finds_file_in_cwd(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bb_results.csv")
            open(path, "w").close()
            with patch("os.path.exists", side_effect=lambda p: p == path or os.path.exists(p)):
                # Patch candidates list directly
                with patch("sessiontest.os.path.exists", return_value=True):
                    result = s._find_csv()
                    self.assertIsNotNone(result)

    def test_returns_none_when_not_found(self):
        with patch("sessiontest.os.path.exists", return_value=False):
            self.assertIsNone(s._find_csv())


# ── 22. load_rows ─────────────────────────────────────────────────────────────



class TestLoadRows(unittest.TestCase):
    def _write_csv(self, rows, path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["browser","profile","label","service","value","address"])
            writer.writeheader()
            writer.writerows(rows)

    def test_loads_all_rows(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
        try:
            self._write_csv([
                {"browser": "Chrome", "profile": "Default", "label": "JWT",
                 "service": "Google", "value": "tok", "address": "0x1"},
                {"browser": "Chrome", "profile": "Default", "label": "Cookie",
                 "service": "github.com", "value": "sess=abc", "address": "github.com"},
            ], path)
            rows = s.load_rows(path)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["label"], "JWT")
            self.assertEqual(rows[1]["label"], "Cookie")
        finally:
            os.unlink(path)

    def test_empty_csv_returns_empty_list(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, newline="") as f:
            path = f.name
            f.write("browser,profile,label,service,value,address\n")
        try:
            rows = s.load_rows(path)
            self.assertEqual(rows, [])
        finally:
            os.unlink(path)


# ── 23. main() ───────────────────────────────────────────────────────────────

def _write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["browser","profile","label","service","value","address"])
        w.writeheader()
        w.writerows(rows)





if __name__ == "__main__":
    unittest.main()
