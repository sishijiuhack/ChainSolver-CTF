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


def jwt_forge(payload: dict[str, Any], secret: str, algorithm: str = "HS256") -> dict[str, Any]:
    """Forge a JWT token with a given payload and secret.

    Args:
        payload: Claims dict to encode.
        secret: HMAC secret or 'none' for alg:none attack.
        algorithm: JWT algorithm (HS256, HS512, none).
    """
    import hashlib
    import hmac
    import time

    header = {"alg": algorithm, "typ": "JWT"}
    header_enc = _b64url_encode(json.dumps(header, separators=(",", ":")))
    payload.setdefault("iat", int(time.time()))
    payload_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")))
    signing_input = f"{header_enc}.{payload_enc}"

    if algorithm.lower() == "none":
        token = f"{signing_input}."
    elif algorithm == "HS256":
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        token = f"{signing_input}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    elif algorithm == "HS512":
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha512).digest()
        token = f"{signing_input}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    else:
        return {"error": f"Unsupported algorithm: {algorithm}"}

    return {"token": token, "header": header, "payload": payload}


def hash_identify(hash_string: str) -> dict[str, Any]:
    """Identify likely hash algorithms based on canonical hex lengths."""

    candidates = [name for name, pattern in _HASH_PATTERNS.items() if pattern.match(hash_string)]
    return {
        "hash": hash_string,
        "candidates": candidates or ["unknown"],
        "confidence": "low" if len(candidates) != 1 else "medium",
    }


def hash_crack(hash_string: str, wordlist: list[str] | None = None) -> dict[str, Any]:
    """Attempt to crack a hash against a wordlist (or built-in common passwords).

    Args:
        hash_string: Hex hash to crack.
        wordlist: List of candidate plaintexts. Defaults to a small built-in list.
    """
    import hashlib

    candidates = wordlist or _DEFAULT_WORDLIST
    hash_len = len(hash_string)
    algos: dict[int, list[str]] = {
        32: ["md5"],
        40: ["sha1"],
        64: ["sha256"],
        128: ["sha512"],
    }
    target_algos = algos.get(hash_len, ["md5", "sha1", "sha256", "sha512"])

    for word in candidates:
        for algo in target_algos:
            h = hashlib.new(algo, word.encode()).hexdigest()
            if h == hash_string.lower():
                return {"cracked": True, "plaintext": word, "algorithm": algo}

    return {"cracked": False, "tried": len(candidates), "algorithms": target_algos}


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


def xor_bruteforce(ciphertext_hex: str, key_length: int | None = None) -> dict[str, Any]:
    """Brute-force single or multi-byte XOR cipher.

    Args:
        ciphertext_hex: Hex-encoded ciphertext.
        key_length: Key length to try. If None, tries 1-4 bytes.
    """
    try:
        ct = bytes.fromhex(ciphertext_hex)
    except ValueError:
        return {"error": "Invalid hex input"}

    lengths = [key_length] if key_length else list(range(1, 5))
    results: list[dict[str, Any]] = []

    for klen in lengths:
        best_key, best_score, best_plain = _xor_crack(ct, klen)
        results.append({
            "key_length": klen,
            "key_hex": best_key.hex(),
            "key_ascii": best_key.decode("latin-1"),
            "plaintext": best_plain,
            "score": best_score,
        })

    results.sort(key=lambda x: x["score"], reverse=True)
    return {"results": results, "best": results[0] if results else None}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_WORDLIST = [
    "password", "123456", "admin", "root", "letmein", "qwerty",
    "abc123", "monkey", "master", "dragon", "pass", "test",
    "secret", "flag", "ctf", "hacker", "1234", "12345678",
]

_ENGLISH_FREQ = {c: f for c, f in zip(
    "etaoinshrdlcumwfgypbvkjxqz",
    [12.7, 9.1, 8.2, 7.5, 7.0, 6.3, 6.1, 6.0, 5.9, 4.3,
     4.0, 2.8, 2.4, 2.4, 2.4, 2.2, 2.0, 1.9, 1.5, 1.0,
     0.8, 0.2, 0.2, 0.2, 0.1, 0.1],
)}


def _score_english(text: bytes) -> float:
    return sum(_ENGLISH_FREQ.get(chr(b).lower(), 0) for b in text if 32 <= b < 127)


def _xor_crack(ct: bytes, key_len: int) -> tuple[bytes, float, str]:
    key = bytearray()
    for i in range(key_len):
        chunk = bytes(ct[j] for j in range(i, len(ct), key_len))
        best_byte = max(range(256), key=lambda k: _score_english(bytes(b ^ k for b in chunk)))
        key.append(best_byte)
    plain = bytes(ct[i] ^ key[i % key_len] for i in range(len(ct)))
    score = _score_english(plain)
    return bytes(key), score, plain.decode("latin-1")


def _b64url_encode(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()


def _b64url_json_decode(segment: str) -> dict[str, Any]:
    padded = segment + "=" * ((4 - len(segment) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
        return json.loads(raw)
    except (binascii.Error, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JWT segment") from exc
