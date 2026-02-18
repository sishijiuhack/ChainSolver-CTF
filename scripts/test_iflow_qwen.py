"""Simple connectivity test for iFlow platform qwen3-235b model.

Usage:
  IFLOW_API_KEY=... python scripts/test_iflow_qwen.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API_URL = os.getenv("IFLOW_API_URL", "https://api.iflow.cn/v1/chat/completions")
MODEL = os.getenv("IFLOW_MODEL", "qwen3-235b")


def main() -> int:
    api_key = os.getenv("IFLOW_API_KEY")
    if not api_key:
        print("ERROR: IFLOW_API_KEY is required")
        return 2

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You are a concise assistant."},
            {"role": "user", "content": "Reply with exactly: IFlow Qwen test OK"},
        ],
        "temperature": 0,
    }

    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        print(f"HTTP_ERROR: {exc.code}")
        print(detail)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"REQUEST_FAILED: {exc}")
        return 1

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print("INVALID_JSON_RESPONSE")
        print(body)
        return 1

    message = (
        data.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )

    print("MODEL:", MODEL)
    print("REPLY:", message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
