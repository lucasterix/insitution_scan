"""Shared SPA-catch-all baseline defense.

Modern sites (React/Vue/Next SPAs, WP themes with catch-all fallbacks) return
the same HTML body for any path the router doesn't know. Every path scanner
therefore needs to:

1. Probe `/` and a guaranteed-nonexistent path up front.
2. Compare each probed body against those baselines — if identical (stripped),
   the response is a catch-all and must be ignored.

This module centralizes that logic so every scanner uses the same hardened
baseline set.
"""
from __future__ import annotations

import hashlib

import httpx

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
BASELINE_TIMEOUT = 5.0


def _body_hash(body: str) -> str:
    return hashlib.sha1(body.strip().encode("utf-8", errors="ignore")).hexdigest()


def fetch_baselines(domain: str) -> set[str]:
    """Return a set of SHA1 hashes for responses that represent a catch-all.

    Fetches `/` and a nonsense path; both bodies are hashed and returned.
    """
    baselines: set[str] = set()
    probe_paths = (
        "/",
        f"/__mvzscan_404_probe_{hashlib.md5(domain.encode()).hexdigest()[:12]}__",
    )
    try:
        with httpx.Client(
            timeout=BASELINE_TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            for path in probe_paths:
                try:
                    r = client.get(f"https://{domain}{path}")
                    if r.status_code == 200:
                        baselines.add(_body_hash(r.text[:8192]))
                except httpx.HTTPError:
                    continue
    except Exception:  # noqa: BLE001
        pass
    baselines.discard(_body_hash(""))
    return baselines


def is_catchall(body: str, baselines: set[str]) -> bool:
    if not baselines:
        return False
    return _body_hash(body[:8192]) in baselines
