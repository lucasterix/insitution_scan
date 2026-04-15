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
BODY_CAP = 8192  # bytes of HTML head that get fingerprinted


def _body_hash(body: str) -> str:
    """Hash a normalized prefix of the body.

    Truncates to BODY_CAP so probes and baselines always operate on the same
    window regardless of how much the caller passed in.
    """
    capped = body[:BODY_CAP].strip()
    return hashlib.sha1(capped.encode("utf-8", errors="ignore")).hexdigest()


def fetch_baselines(domain: str) -> tuple[set[str], set[int]]:
    """Return (body-hash set, body-length set) that represent catch-all pages.

    Fetches `/` and two nonsense paths, hashes BODY_CAP bytes of each and also
    stores the exact body length. SPAs that serve the same HTML to every route
    will match on either the hash or the length baseline.
    """
    hashes: set[str] = set()
    lengths: set[int] = set()
    probe_paths = (
        "/",
        f"/__mvzscan_404_probe_{hashlib.md5(domain.encode()).hexdigest()[:12]}__",
        f"/__mvzscan_random_{hashlib.md5((domain + 'x').encode()).hexdigest()[:12]}__",
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
                        hashes.add(_body_hash(r.text))
                        lengths.add(len(r.text))
                except httpx.HTTPError:
                    continue
    except Exception:  # noqa: BLE001
        pass
    hashes.discard(_body_hash(""))
    lengths.discard(0)
    return hashes, lengths


def is_catchall(body: str, baselines: tuple[set[str], set[int]] | set[str]) -> bool:
    # Back-compat: accept the old set-only shape.
    if isinstance(baselines, set):
        hashes = baselines
        lengths: set[int] = set()
    else:
        hashes, lengths = baselines

    if not hashes and not lengths:
        return False

    if _body_hash(body) in hashes:
        return True

    # Length-based fallback: SPAs that ship a tiny route-specific title/meta
    # patch still return a body within a handful of bytes of the baseline.
    body_len = len(body)
    for b_len in lengths:
        if abs(body_len - b_len) <= 50:
            return True
    return False
