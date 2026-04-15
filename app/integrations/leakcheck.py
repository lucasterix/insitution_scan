"""LeakCheck.io client — public API for e-mail breach lookup.

The public API at /api/public is rate-limited but returns rich data per
request: total matches, leaked field types, and the list of sources with
dates. Exactly what we need for the e-mail harvest check.

Endpoint:
    GET https://leakcheck.io/api/public?key=KEY&check=<value>&type=email

Gated on LEAKCHECK_API_KEY. Returns None when the key is empty or the call
fails so callers can skip gracefully.
"""
from __future__ import annotations

import time

import httpx

from app.config import get_settings

USER_AGENT = "MVZ-SelfScan/1.0"
BASE_URL = "https://leakcheck.io/api/public"


def is_enabled() -> bool:
    return bool(get_settings().leakcheck_api_key)


def check_email(email: str) -> dict | None:
    """Return the raw LeakCheck response for an e-mail, or None on failure.

    Shape: {success: bool, found: int, fields: [...], sources: [{name, date}]}
    """
    key = get_settings().leakcheck_api_key
    if not key:
        return None
    try:
        r = httpx.get(
            BASE_URL,
            params={"key": key, "check": email, "type": "email"},
            headers={"User-Agent": USER_AGENT},
            timeout=12.0,
        )
        r.raise_for_status()
        data = r.json()
    except (httpx.HTTPError, ValueError):
        return None
    if not data.get("success"):
        return None
    return data


def rate_limit_sleep() -> None:
    """Public API is generous but not unlimited — pace ourselves."""
    time.sleep(1.1)
