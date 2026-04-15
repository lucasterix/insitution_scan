"""AbuseIPDB client — reputation lookup for an IP.

Returns abuse confidence (0–100) and recent report count. Gated on
ABUSEIPDB_API_KEY. Free tier: 1000 checks/day.
"""
from __future__ import annotations

import httpx

from app.config import get_settings

USER_AGENT = "MVZ-SelfScan/1.0"
BASE_URL = "https://api.abuseipdb.com/api/v2"


def is_enabled() -> bool:
    return bool(get_settings().abuseipdb_api_key)


def check_ip(ip: str, max_age_days: int = 90) -> dict | None:
    key = get_settings().abuseipdb_api_key
    if not key:
        return None
    try:
        r = httpx.get(
            f"{BASE_URL}/check",
            params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": "false"},
            headers={
                "User-Agent": USER_AGENT,
                "Key": key,
                "Accept": "application/json",
            },
            timeout=12.0,
        )
        r.raise_for_status()
        return r.json().get("data")
    except (httpx.HTTPError, ValueError):
        return None
