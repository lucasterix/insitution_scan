"""Have I Been Pwned client — domain + account breach checks.

⚠️ HIBP has NO free API tier since 2019. Both `breachedaccount` and
`breacheddomain` endpoints require a paid subscription (approx. $3.95/month
for "Pwned 1" → breached account; Pwned 2+ for domain search).

Gated on HIBP_API_KEY. Free public `breaches` (catalog browsing) works without
a key but is not useful for targeted checks.
"""
from __future__ import annotations

import time

import httpx

from app.config import get_settings

USER_AGENT = "MVZ-SelfScan/1.0"
BASE_URL = "https://haveibeenpwned.com/api/v3"


def is_enabled() -> bool:
    return bool(get_settings().hibp_api_key)


def _headers() -> dict:
    return {
        "User-Agent": USER_AGENT,
        "hibp-api-key": get_settings().hibp_api_key,
    }


def breached_account(email: str) -> list[dict] | None:
    if not is_enabled():
        return None
    try:
        r = httpx.get(
            f"{BASE_URL}/breachedaccount/{email}",
            params={"truncateResponse": "false"},
            headers=_headers(),
            timeout=12.0,
        )
        if r.status_code == 404:
            return []  # clean — no breaches
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def breached_domain(domain: str) -> dict | None:
    """Domain-wide breach check. Requires Pwned 2 subscription."""
    if not is_enabled():
        return None
    try:
        r = httpx.get(
            f"{BASE_URL}/breacheddomain/{domain}",
            headers=_headers(),
            timeout=20.0,
        )
        if r.status_code == 404:
            return {}
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def rate_limit_sleep() -> None:
    """HIBP rate limits individual-account lookups to ~1/1.5s."""
    time.sleep(1.6)
