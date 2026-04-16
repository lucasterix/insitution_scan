"""Open redirect probe.

Tests common redirect parameter names (url=, next=, redirect=, goto=, returnTo=,
continue=, forward=, dest=, destination=, redir=) by injecting an external URL.

If the server responds with a 30x redirect to the external URL, it's an open
redirect — attackers use those to bypass domain-trust in phishing campaigns.

For MVZs this is a HIGH risk because patients trust the practice URL and click
redirects without suspicion.
"""
from __future__ import annotations

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


def check_open_redirect(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Open-Redirect-Probe", 67)

    hits: list[dict] = []

    with httpx.Client(
        timeout=5.0,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        for base_path in BASE_PATHS:
            for param in PARAM_NAMES:
                url = f"https://{domain}{base_path}?{urlencode({param: CANARY_URL})}"
                try:
                    r = client.get(url)
                except httpx.HTTPError:
                    continue

                if r.status_code not in (301, 302, 303, 307, 308):
                    continue

                location = r.headers.get("location", "")
                if CANARY_URL in location or "evil-redirect-probe" in location:
                    hits.append({
                        "path": base_path,
                        "param": param,
                        "status": r.status_code,
                        "location": location[:200],
                    })
                    break  # One hit per base_path is enough

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
        severity=Severity.HIGH,
        category="Deep Scan",
        evidence={"hits": hits},
        recommendation=(
            "Redirect-Ziel gegen eine Allowlist validieren oder nur relative Pfade zulassen. "
            "Niemals die Query-Parameter ungeprüft in den Location-Header übernehmen."
        ),
    ))
