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


def _capped_len(body: str) -> int:
    """Measure the body in the same window the hash operates on.

    Callers all over the scanner pass already-truncated bodies (r.text[:4096],
    r.text[:8192], r.text[:16384]). If the baseline stored the FULL length
    and the probe passed a truncated length, the length comparison could
    never match and the catch-all defense silently broke for every SPA.
    Normalising to the BODY_CAP window on both sides fixes that regardless
    of how much the caller passed in.
    """
    return len(body[:BODY_CAP])


def fetch_baselines(domain: str) -> tuple[set[str], set[int]]:
    """Return (body-hash set, body-length set) that represent catch-all pages.

    Fetches `/` and two nonsense paths, hashes BODY_CAP bytes of each and also
    stores the body length capped to BODY_CAP. SPAs that serve the same HTML
    to every route will match on either the hash or the length baseline.
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
                        lengths.add(_capped_len(r.text))
                except httpx.HTTPError:
                    continue
    except Exception:  # noqa: BLE001
        pass
    hashes.discard(_body_hash(""))
    lengths.discard(0)
    return hashes, lengths


def detect_blanket_4xx(domain: str) -> set[int]:
    """Detect if the server returns the same 4xx status for ALL unknown paths.

    Many WAFs (Cloudflare, Sucuri, ModSecurity, SiteGround Security) and
    reverse-proxies return a blanket 403/401 for anything they don't
    recognise. Any scanner that treats those status codes as 'path exists'
    then misinterprets the WAF behavior as dozens of real findings
    (phpMyAdmin exposed, Konnektor exposed, ...).

    Two guaranteed-nonexistent probe paths — if BOTH return the same 4xx,
    the server has a blanket response for that code. Callers should then
    drop all hits matching that status.
    """
    probe_a = f"/__mvzscan_probe_{hashlib.md5(domain.encode()).hexdigest()[:10]}__"
    probe_b = f"/__mvzscan_probe_{hashlib.md5((domain + 'x').encode()).hexdigest()[:10]}__"
    status_a: int | None = None
    status_b: int | None = None
    try:
        with httpx.Client(
            timeout=BASELINE_TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            try:
                status_a = client.get(f"https://{domain}{probe_a}").status_code
            except httpx.HTTPError:
                pass
            try:
                status_b = client.get(f"https://{domain}{probe_b}").status_code
            except httpx.HTTPError:
                pass
    except Exception:  # noqa: BLE001
        return set()
    blanket: set[int] = set()
    if status_a in (401, 403) and status_a == status_b:
        blanket.add(status_a)
    return blanket


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

    # Length-based fallback, measured in the same BODY_CAP window the
    # baseline was stored in so truncated callers still match.
    body_len = _capped_len(body)
    for b_len in lengths:
        if abs(body_len - b_len) <= 50:
            return True
    return False
