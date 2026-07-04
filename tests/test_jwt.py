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

class TestDecodeJWT(unittest.TestCase):
    def test_valid_jwt_returns_header_and_payload(self):
        jwt = make_jwt({"sub": "user123", "exp": 9999999999})
        result = s._decode_jwt(jwt)
        self.assertIsNotNone(result)
        self.assertEqual(result["payload"]["sub"], "user123")
        self.assertIn("alg", result["header"])

    def test_two_part_token_returns_none(self):
        self.assertIsNone(s._decode_jwt("abc.def"))

    def test_four_part_token_returns_none(self):
        self.assertIsNone(s._decode_jwt("a.b.c.d"))

    def test_invalid_base64_returns_none(self):
        self.assertIsNone(s._decode_jwt("!!!.!!!.!!!"))

    def test_non_json_payload_returns_none(self):
        # valid base64 but not JSON
        garbage = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
        self.assertIsNone(s._decode_jwt(f"eyJhbGciOiJSUzI1NiJ9.{garbage}.sig"))

    def test_empty_string_returns_none(self):
        self.assertIsNone(s._decode_jwt(""))


# ── 4. Result class ───────────────────────────────────────────────────────────



class TestJWT(unittest.TestCase):
    def test_not_expired_shows_valid(self):
        jwt = make_jwt({"sub": "user123", "exp": int(time.time()) + 3600,
                         "iss": "https://accounts.google.com"})
        r = s.test_jwt(jwt, "JWT", "Google")
        self.assertEqual(r.status, "valid")
        self.assertIn("valid for", r.access)
        self.assertIn("iss=", r.access)

    def test_expired_shows_expired(self):
        jwt = make_jwt({"sub": "user123", "exp": int(time.time()) - 7200})
        r = s.test_jwt(jwt, "JWT", "")
        self.assertEqual(r.status, "expired")
        self.assertIn("expired", r.access)

    def test_no_expiry_is_info(self):
        jwt = make_jwt({"sub": "user123"})
        r = s.test_jwt(jwt, "JWT", "")
        self.assertEqual(r.status, "info")
        self.assertIn("no expiry", r.access)

    def test_identity_from_email(self):
        jwt = make_jwt({"email": "victim@corp.com", "exp": 9999999999})
        r = s.test_jwt(jwt, "JWT", "")
        self.assertIn("victim@corp.com", r.identity)

    def test_identity_from_sub_when_no_email(self):
        jwt = make_jwt({"sub": "uid-12345", "exp": 9999999999})
        r = s.test_jwt(jwt, "JWT", "")
        self.assertIn("uid-12345", r.identity)

    def test_identity_from_preferred_username(self):
        jwt = make_jwt({"preferred_username": "alice", "exp": 9999999999})
        r = s.test_jwt(jwt, "JWT", "")
        self.assertIn("alice", r.identity)

    def test_identity_from_unique_name(self):
        jwt = make_jwt({"unique_name": "bob@corp.com", "exp": 9999999999})
        r = s.test_jwt(jwt, "JWT", "")
        self.assertIn("bob@corp.com", r.identity)

    def test_identity_from_upn(self):
        jwt = make_jwt({"upn": "carol@corp.com", "exp": 9999999999})
        r = s.test_jwt(jwt, "JWT", "")
        self.assertIn("carol@corp.com", r.identity)

    def test_no_identity_fields_returns_dash(self):
        jwt = make_jwt({"exp": 9999999999})
        r = s.test_jwt(jwt, "JWT", "")
        self.assertEqual(r.identity, "—")

    def test_aud_as_list_uses_first(self):
        jwt = make_jwt({"aud": ["aud1", "aud2"], "exp": 9999999999})
        r = s.test_jwt(jwt, "JWT", "")
        self.assertIn("aud=aud1", r.access)

    def test_service_from_iss_when_no_service_arg(self):
        jwt = make_jwt({"iss": "https://auth.example.com", "exp": 9999999999})
        r = s.test_jwt(jwt, "JWT", "")
        self.assertEqual(r.service, "https://auth.example.com")

    def test_service_arg_takes_precedence_over_iss(self):
        jwt = make_jwt({"iss": "https://auth.example.com", "exp": 9999999999})
        r = s.test_jwt(jwt, "JWT", "Google")
        self.assertEqual(r.service, "Google")

    def test_short_preview_not_truncated(self):
        short = "a.b.c"  # too short to be a JWT — will fail decode
        r = s.test_jwt(short, "JWT", "")
        # Falls back to error result with no truncation
        self.assertEqual(r.status, "error")

    def test_undecoded_jwt_returns_error(self):
        r = s.test_jwt("not.a.jwt", "JWT", "")
        self.assertEqual(r.status, "error")
        self.assertEqual(r.access, "could not decode")


# ── 15. AWS tester ───────────────────────────────────────────────────────────

_STS_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/test-user</Arn>
    <Account>123456789012</Account>
    <UserId>AIDAIOSFODNN7EXAMPLE</UserId>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>"""





if __name__ == "__main__":
    unittest.main()
