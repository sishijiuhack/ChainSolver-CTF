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
    return {
        "matches": deduped,
    }
