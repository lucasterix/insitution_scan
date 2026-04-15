"""SecurityTrails client — DNS history + subdomains.

Gated on SECURITYTRAILS_API_KEY. Free tier: 50 queries/month.
Docs: https://docs.securitytrails.com/reference
"""
from __future__ import annotations

import httpx

from app.config import get_settings

USER_AGENT = "MVZ-SelfScan/1.0"
BASE_URL = "https://api.securitytrails.com/v1"


def is_enabled() -> bool:
    return bool(get_settings().securitytrails_api_key)


def _headers() -> dict:
    return {
        "User-Agent": USER_AGENT,
        "APIKEY": get_settings().securitytrails_api_key,
        "Accept": "application/json",
    }


def history_dns(domain: str, record_type: str = "a") -> dict | None:
    """Fetch historical DNS records (a, aaaa, mx, ns, soa, txt)."""
    if not is_enabled():
        return None
    try:
        r = httpx.get(
            f"{BASE_URL}/history/{domain}/dns/{record_type}",
            headers=_headers(),
            timeout=15.0,
        )
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def subdomains(domain: str) -> list[str] | None:
    if not is_enabled():
        return None
    try:
        r = httpx.get(
            f"{BASE_URL}/domain/{domain}/subdomains",
            params={"children_only": "false", "include_inactive": "true"},
            headers=_headers(),
            timeout=15.0,
        )
        r.raise_for_status()
        data = r.json()
        return [f"{s}.{domain}" for s in (data.get("subdomains") or [])]
    except (httpx.HTTPError, ValueError):
        return None
