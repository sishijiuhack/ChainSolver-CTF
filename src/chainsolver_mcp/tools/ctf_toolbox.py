"""General CTF helper tools exposed via MCP."""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any


_HASH_PATTERNS: dict[str, re.Pattern[str]] = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha512": re.compile(r"^[a-fA-F0-9]{128}$"),
}


def jwt_decode(token: str) -> dict[str, Any]:
    """Decode JWT without signature verification for CTF analysis."""

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT: expected three segments")

    header = _b64url_json_decode(parts[0])
    payload = _b64url_json_decode(parts[1])

    return {
        "header": header,
        "payload": payload,
        "signature": parts[2],
        "verified": False,
    }


def hash_identify(hash_string: str) -> dict[str, Any]:
    """Identify likely hash algorithms based on canonical hex lengths."""

    candidates = [name for name, pattern in _HASH_PATTERNS.items() if pattern.match(hash_string)]
    return {
        "hash": hash_string,
        "candidates": candidates or ["unknown"],
        "confidence": "low" if len(candidates) != 1 else "medium",
    }


def decode_string(encoded_string: str, encoding_type: str = "base64") -> dict[str, str]:
    """Decode common CTF encodings."""

    encoding_type = encoding_type.lower()

    if encoding_type == "base64":
        decoded = base64.b64decode(encoded_string).decode("utf-8", errors="replace")
    elif encoding_type == "hex":
        decoded = bytes.fromhex(encoded_string).decode("utf-8", errors="replace")
    elif encoding_type == "url":
        from urllib.parse import unquote

        decoded = unquote(encoded_string)
    else:
        raise ValueError(f"Unsupported encoding_type: {encoding_type}")

    return {
        "input": encoded_string,
        "encoding": encoding_type,
        "decoded": decoded,
    }


def _b64url_json_decode(segment: str) -> dict[str, Any]:
    padded = segment + "=" * ((4 - len(segment) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
        return json.loads(raw)
    except (binascii.Error, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JWT segment") from exc
