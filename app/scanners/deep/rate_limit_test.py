"""Rate limit test on discovered API endpoints.

Sends 15 rapid-fire requests to each discovered API endpoint and checks
whether the server responds with 429 Too Many Requests. Missing rate
limiting on sensitive endpoints (auth, patient, medical) is a HIGH finding
because it enables brute-force and credential-stuffing attacks.
"""
from __future__ import annotations

import time
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
BURST_SIZE = 15
BURST_TIMEOUT = 3.0

SENSITIVE_KEYWORDS = ("login", "auth", "token", "password", "user", "patient", "admin")


def _collect_endpoints(result: ScanResult) -> list[str]:
    endpoints: set[str] = set()
    js = result.metadata.get("js_analysis") or {}
    for ep in js.get("api_endpoints_found") or []:
        endpoints.add(ep)
    openapi = result.metadata.get("openapi") or {}
    for ep_info in openapi.get("endpoints") or []:
        path = ep_info.get("path", "")
        if path:
            endpoints.add(path)
    # Also test login paths
    cms = result.metadata.get("cms") or {}
    if cms.get("signals", {}).get("wordpress"):
        endpoints.add("/wp-login.php")
    for p in ("/login", "/api/login", "/api/auth", "/api/token"):
        endpoints.add(p)
    return sorted(endpoints)[:10]


def check_rate_limits(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Rate-Limit-Test", 77)

    endpoints = _collect_endpoints(result)
    if not endpoints:
        return

    no_limit: list[dict] = []
    has_limit: list[dict] = []

    with httpx.Client(
        timeout=BURST_TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        for ep in endpoints:
            url = f"https://{domain}{ep}"
            statuses: list[int] = []
            try:
                for _ in range(BURST_SIZE):
                    r = client.get(url)
                    statuses.append(r.status_code)
            except httpx.HTTPError:
                continue

            got_429 = 429 in statuses
            is_sensitive = any(kw in ep.lower() for kw in SENSITIVE_KEYWORDS)

            entry = {"endpoint": ep, "statuses": statuses, "rate_limited": got_429, "sensitive": is_sensitive}

            if got_429:
                has_limit.append(entry)
            else:
                no_limit.append(entry)

    result.metadata["rate_limit_test"] = {
        "tested": len(endpoints),
        "no_limit": len(no_limit),
        "has_limit": len(has_limit),
    }

    sensitive_no_limit = [e for e in no_limit if e["sensitive"]]
    if sensitive_no_limit:
        result.add(Finding(
            id="deep.rate_limit_missing_sensitive",
            title=f"{len(sensitive_no_limit)} sensible Endpoint(s) ohne Rate-Limiting",
            description=(
                f"{BURST_SIZE} Requests in Folge auf auth-/login-/patient-Endpunkte — "
                "keiner hat mit HTTP 429 (Too Many Requests) geantwortet. Ohne Rate-Limiting "
                "kann ein Angreifer unbegrenzt Brute-Force- und Credential-Stuffing-Angriffe fahren."
            ),
            severity=Severity.HIGH,
            category="Deep Scan",
            evidence={"endpoints": sensitive_no_limit[:5]},
            recommendation=(
                "Rate-Limiting auf allen Auth-Endpunkten erzwingen (z.B. 5 Versuche/Minute). "
                "nginx: `limit_req_zone`, Cloudflare: Rate Limiting Rules, WAF: entsprechende Policy."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (Zugriffskontrolle)",
        ))
