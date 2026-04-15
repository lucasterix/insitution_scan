"""AlienVault OTX client — threat-intel pulses for a domain or IP.

Gated on OTX_API_KEY. Free with registration.
"""
from __future__ import annotations

import httpx

from app.config import get_settings

USER_AGENT = "MVZ-SelfScan/1.0"
BASE_URL = "https://otx.alienvault.com/api/v1"


def is_enabled() -> bool:
    return bool(get_settings().otx_api_key)


def _headers() -> dict:
    return {"User-Agent": USER_AGENT, "X-OTX-API-KEY": get_settings().otx_api_key}


def domain_pulses(domain: str) -> dict | None:
    if not is_enabled():
        return None
    try:
        r = httpx.get(
            f"{BASE_URL}/indicators/domain/{domain}/general",
            headers=_headers(),
            timeout=12.0,
        )
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def ip_pulses(ip: str) -> dict | None:
    if not is_enabled():
        return None
    try:
        r = httpx.get(
            f"{BASE_URL}/indicators/IPv4/{ip}/general",
            headers=_headers(),
            timeout=12.0,
        )
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None
