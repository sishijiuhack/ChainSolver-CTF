"""Connectivity test for iFlow qwen3-235b (OpenAI-compatible API).

Usage:
  IFLOW_API_KEY=... python scripts/test_iflow_qwen.py

Optional env:
  IFLOW_API_URL           Explicit endpoint, e.g. https://platform.iflow.cn/v1/chat/completions
  IFLOW_MODEL             Defaults to qwen3-235b
  IFLOW_TIMEOUT_S         Defaults to 30
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

DEFAULT_ENDPOINTS = [
    # 平台侧地址（优先）
    "https://platform.iflow.cn/v1/chat/completions",
    # 兼容部分网关部署
    "https://platform.iflow.cn/api/openai/v1/chat/completions",
]
MODEL = os.getenv("IFLOW_MODEL", "qwen3-235b")
TIMEOUT_S = float(os.getenv("IFLOW_TIMEOUT_S", "30"))


def _build_payload() -> dict[str, Any]:
    return {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You are a concise assistant."},
            {"role": "user", "content": "Reply with exactly: IFlow Qwen test OK"},
        ],
        "temperature": 0,
    }


def _looks_like_html(body: str) -> bool:
    text = body.lstrip().lower()
    return text.startswith("<!doctype html") or text.startswith("<html")


def _try_request(api_url: str, api_key: str, payload: dict[str, Any]) -> tuple[bool, str]:
    req = urllib.request.Request(
        api_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return False, f"HTTP_ERROR({api_url}): {exc.code}\n{detail}"
    except Exception as exc:  # noqa: BLE001
        return False, f"REQUEST_FAILED({api_url}): {exc}"

    if _looks_like_html(body):
        return (
            False,
            "HTML_RESPONSE_DETECTED\n"
            f"endpoint={api_url}\n"
            "你当前命中了网页站点而不是 OpenAI API 端点。\n"
            "请改用 IFLOW_API_URL=https://platform.iflow.cn/v1/chat/completions",
        )

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        snippet = body[:500]
        return False, f"INVALID_JSON_RESPONSE({api_url})\n{snippet}"

    message = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    if not message:
        return False, f"UNEXPECTED_RESPONSE_SCHEMA({api_url})\n{json.dumps(data, ensure_ascii=False)[:800]}"

    return True, f"MODEL: {MODEL}\nENDPOINT: {api_url}\nREPLY: {message}"


def main() -> int:
    api_key = os.getenv("IFLOW_API_KEY")
    if not api_key:
        print("ERROR: IFLOW_API_KEY is required")
        return 2

    payload = _build_payload()
    configured = os.getenv("IFLOW_API_URL")
    endpoints = [configured] if configured else DEFAULT_ENDPOINTS

    errors: list[str] = []
    for endpoint in endpoints:
        ok, result = _try_request(endpoint, api_key, payload)
        if ok:
            print(result)
            return 0
        errors.append(result)

    print("ALL_ENDPOINTS_FAILED")
    for idx, err in enumerate(errors, 1):
        print(f"--- failure #{idx} ---")
        print(err)
    return 1


if __name__ == "__main__":
    sys.exit(main())
