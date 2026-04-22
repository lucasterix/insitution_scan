"""Open redirect probe.

Tests common redirect parameter names (url=, next=, redirect=, goto=, returnTo=,
continue=, forward=, dest=, destination=, redir=) by injecting an external URL.

If the server responds with a 30x redirect to the external URL, it's an open
redirect — attackers use those to bypass domain-trust in phishing campaigns.

For MVZs this is a HIGH risk because patients trust the practice URL and click
redirects without suspicion.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from urllib.parse import urlencode

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
CANARY_URL = "https://evil-redirect-probe.invalid/pwned"

PARAM_NAMES = (
    "url", "next", "redirect", "redirect_to", "redirect_uri",
    "goto", "return", "returnTo", "return_to", "continue",
    "forward", "dest", "destination", "redir", "target",
    "return_url", "callback", "checkout_url", "login_url",
)

BASE_PATHS = ("/", "/login", "/logout", "/redirect")


def _probe(domain: str, base_path: str, param: str) -> dict | None:
    url = f"https://{domain}{base_path}?{urlencode({param: CANARY_URL})}"
    try:
        with httpx.Client(
            timeout=5.0, follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            r = client.get(url)
    except httpx.HTTPError:
        return None
    if r.status_code not in (301, 302, 303, 307, 308):
        return None
    location = r.headers.get("location", "")
    # Only flag a REAL open redirect: the Location header's HOST must be the
    # evil canary host, i.e. the server actually sends the user OFF-SITE.
    # If the evil URL only appears as a query-string on the SAME host (e.g.
    # canonical www→www with ?goto=... preserved), that's NOT a redirect
    # vulnerability — the user stays on the customer's domain. Every SPA
    # and CMS preserves query strings on canonical redirects.
    from urllib.parse import urlparse
    try:
        loc_host = urlparse(location).netloc.lower()
    except Exception:  # noqa: BLE001
        loc_host = ""
    if "evil-redirect-probe.invalid" in loc_host:
        return {"path": base_path, "param": param, "status": r.status_code, "location": location[:200]}
    return None


def check_open_redirect(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Open-Redirect-Probe", 67)

    seen_paths: set[str] = set()
    hits: list[dict] = []

    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = [
            ex.submit(_probe, domain, bp, p)
            for bp in BASE_PATHS for p in PARAM_NAMES
        ]
        for fut in as_completed(futures):
            hit = fut.result()
            if hit and hit["path"] not in seen_paths:
                hits.append(hit)
                seen_paths.add(hit["path"])

    if not hits:
        return

    result.metadata["open_redirects"] = hits

    result.add(Finding(
        id="deep.open_redirect",
        title=f"Open Redirect auf {len(hits)} Pfad(en)",
        description=(
            "Der Server leitet bei bestimmten URL-Parametern ohne Validierung auf "
            "externe Domains um. Angreifer nutzen das in Phishing-Mails:\n"
            f"  https://{domain}{hits[0]['path']}?{hits[0]['param']}=https://evil.com\n\n"
            "Da der Link mit der vertrauenswürdigen Praxis-Domain beginnt, klicken "
            "Patienten und Mitarbeitende bedenkenlos — und landen auf einer Fake-Login-Seite."
        ),
        # Open-redirect is a phishing enabler, not direct compromise. Victim has to
        # click an attacker-crafted link starting with the trusted domain.
        severity=Severity.MEDIUM,
        category="Deep Scan",
        evidence={"hits": hits},
        recommendation=(
            "Redirect-Ziel gegen eine Allowlist validieren oder nur relative Pfade zulassen. "
            "Niemals die Query-Parameter ungeprüft in den Location-Header übernehmen."
        ),
    ))
