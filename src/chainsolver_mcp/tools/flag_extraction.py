"""Flag extraction utilities for CTF workflows."""

from __future__ import annotations

import re

DEFAULT_FLAG_PATTERNS = [
    r"flag\{[^}]+\}",
    r"ctf\{[^}]+\}",
    r"FLAG\{[^}]+\}",
]


def extract_flags(text: str, pattern: str | None = None) -> dict[str, list[str]]:
    """Extract candidate flags from input text."""

    patterns = [pattern] if pattern else DEFAULT_FLAG_PATTERNS
    results: list[str] = []

    for item in patterns:
        results.extend(re.findall(item, text))

    deduped = list(dict.fromkeys(results))
    return {"matches": deduped}


def submit_flag(flag: str, challenge_url: str, challenge_id: str | None = None, api_key: str | None = None) -> dict:
    """Submit a flag to a CTF platform.

    Args:
        flag: The flag string to submit.
        challenge_url: Full URL of the submission endpoint.
        challenge_id: Optional challenge identifier.
        api_key: Optional API key for authenticated platforms.
    """
    import json as _json
    import urllib.error
    import urllib.request

    payload: dict = {"flag": flag}
    if challenge_id:
        payload["challenge_id"] = challenge_id

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(
        challenge_url,
        data=_json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                data = _json.loads(body)
            except _json.JSONDecodeError:
                data = {"raw": body}
            return {"submitted": True, "flag": flag, "response": data}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return {"submitted": False, "flag": flag, "error": f"HTTP {exc.code}", "detail": detail}
    except Exception as exc:
        return {"submitted": False, "flag": flag, "error": str(exc)}
