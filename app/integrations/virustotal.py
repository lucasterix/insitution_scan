"""VirusTotal v3 API client — domain reputation lookup.

Gated on VIRUSTOTAL_API_KEY. Free public tier: 4 req/min, 500/day.
Docs: https://docs.virustotal.com/reference/overview
"""
from __future__ import annotations

import httpx

from app.config import get_settings

USER_AGENT = "MVZ-SelfScan/1.0"
BASE_URL = "https://www.virustotal.com/api/v3"


def is_enabled() -> bool:
    return bool(get_settings().virustotal_api_key)


def _headers() -> dict:
    return {
        "User-Agent": USER_AGENT,
        "x-apikey": get_settings().virustotal_api_key,
        "Accept": "application/json",
    }


def domain_report(domain: str) -> dict | None:
    if not is_enabled():
        return None
    try:
        r = httpx.get(
            f"{BASE_URL}/domains/{domain}",
            headers=_headers(),
            timeout=15.0,
        )
        if r.status_code == 404:
            return {"not_found": True}
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def ip_report(ip: str) -> dict | None:
    if not is_enabled():
        return None
    try:
        r = httpx.get(
            f"{BASE_URL}/ip_addresses/{ip}",
            headers=_headers(),
            timeout=15.0,
        )
        if r.status_code == 404:
            return {"not_found": True}
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None
