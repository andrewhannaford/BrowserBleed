"""Shared helpers for the BrowserBleed test suite."""
import base64
import csv
import io
import json
import os
import sys
import time
import urllib.error
from unittest.mock import MagicMock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def make_jwt(payload: dict, header: dict | None = None, *, expired: bool = False) -> str:
    h = header or {"alg": "RS256", "typ": "JWT"}
    payload = dict(payload)
    if expired:
        payload["exp"] = int(time.time()) - 3600

    def enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{enc(h)}.{enc(payload)}.fakesignatureXXXXXXXXXXXXXX"


def make_jwe_header(exp_ms: int | None = None) -> str:
    header = {"typ": "QT1", "enc": "AES256", "iss": 1234567890}
    if exp_ms is not None:
        header["exp"] = exp_ms
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    return f"{h}.encryptedkey123.ciphertextvalue123"


def make_urlopen_cm(read_bytes: bytes):
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    cm.read = MagicMock(return_value=read_bytes)
    return cm


def http_error(code: int, body: bytes = b"") -> urllib.error.HTTPError:
    fp = io.BytesIO(body)
    fp.read = lambda: body
    return urllib.error.HTTPError("http://x", code, "err", {}, fp)


def csv_row(label: str, service: str, value: str, browser: str = "Chrome") -> dict:
    return {
        "browser": browser,
        "profile": "(memory)",
        "label": label,
        "service": service,
        "value": value,
        "address": "0x0",
    }


def write_csv(rows: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["browser", "profile", "label", "service", "value", "address"]
        )
        writer.writeheader()
        writer.writerows(rows)
