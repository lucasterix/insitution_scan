"""Hunter.io client — find e-mail patterns for a company domain.

Gated on HUNTER_API_KEY. Free tier: 25 queries/month.
Docs: https://hunter.io/api-documentation/v2
"""
from __future__ import annotations

import httpx

from app.config import get_settings

USER_AGENT = "MVZ-SelfScan/1.0"
BASE_URL = "https://api.hunter.io/v2"


def is_enabled() -> bool:
    return bool(get_settings().hunter_api_key)


def domain_search(domain: str, limit: int = 10) -> dict | None:
    key = get_settings().hunter_api_key
    if not key:
        return None
    try:
        r = httpx.get(
            f"{BASE_URL}/domain-search",
            params={"domain": domain, "limit": limit, "api_key": key},
            headers={"User-Agent": USER_AGENT},
            timeout=15.0,
        )
        r.raise_for_status()
        return r.json().get("data")
    except (httpx.HTTPError, ValueError):
        return None
