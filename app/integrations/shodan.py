"""Shodan client — passive lookup of an IP's exposed ports/services.

Uses Shodan's `/shodan/host/{ip}` endpoint which returns cached, pre-scanned
data about an IP. This is strictly passive — we don't send any packets to the
target — which keeps us comfortably inside white-hat territory.

Gated on SHODAN_API_KEY. If the key is empty, every call returns None.
"""
from __future__ import annotations

import httpx

from app.config import get_settings

USER_AGENT = "MVZ-SelfScan/1.0"
BASE_URL = "https://api.shodan.io"


def is_enabled() -> bool:
    return bool(get_settings().shodan_api_key)


def host_lookup(ip: str) -> dict | None:
    """Return the Shodan host record for `ip`, or None."""
    key = get_settings().shodan_api_key
    if not key:
        return None
    try:
        r = httpx.get(
            f"{BASE_URL}/shodan/host/{ip}",
            params={"key": key, "minify": "false"},
            timeout=15.0,
            headers={"User-Agent": USER_AGENT},
        )
        if r.status_code == 404:
            return {"ip": ip, "ports": [], "data": [], "note": "no_shodan_data"}
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None
