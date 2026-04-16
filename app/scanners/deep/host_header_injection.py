"""Host header injection test.

Sends a request with a crafted Host header. If the server reflects the
injected Host in the response body (e.g., in a password-reset link or a
self-referencing URL), an attacker can:

1. Poison password-reset e-mails (Host: evil.com → reset link points to evil.com).
2. Exploit web-cache poisoning if a CDN caches the response keyed on URL only.
3. Trigger SSRF in backend services that trust the Host header.

The test sends two probes:
- Host: evil-hostheader-probe.invalid
- X-Forwarded-Host: evil-hostheader-probe.invalid (for reverse-proxy setups)
"""
from __future__ import annotations

from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
CANARY_HOST = "evil-hostheader-probe.invalid"


def check_host_header(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Host-Header-Injection", 63)

    issues: list[dict] = []

    try:
        with httpx.Client(
            timeout=6.0,
            follow_redirects=False,
            verify=False,
        ) as client:
            # Probe 1: Overridden Host header.
            try:
                r = client.get(
                    f"https://{domain}/",
                    headers={"User-Agent": USER_AGENT, "Host": CANARY_HOST},
                )
                if r.status_code in (200, 301, 302, 303) and CANARY_HOST in r.text[:8192]:
                    issues.append({"vector": "Host header", "reflected_in": "body"})
                loc = r.headers.get("location", "")
                if CANARY_HOST in loc:
                    issues.append({"vector": "Host header", "reflected_in": "Location header"})
            except httpx.HTTPError:
                pass

            # Probe 2: X-Forwarded-Host (common behind reverse proxies).
            try:
                r = client.get(
                    f"https://{domain}/",
                    headers={
                        "User-Agent": USER_AGENT,
                        "Host": domain,
                        "X-Forwarded-Host": CANARY_HOST,
                    },
                )
                if r.status_code in (200, 301, 302, 303) and CANARY_HOST in r.text[:8192]:
                    issues.append({"vector": "X-Forwarded-Host", "reflected_in": "body"})
                loc = r.headers.get("location", "")
                if CANARY_HOST in loc:
                    issues.append({"vector": "X-Forwarded-Host", "reflected_in": "Location header"})
            except httpx.HTTPError:
                pass
    except httpx.HTTPError:
        return

    if not issues:
        return

    result.metadata["host_header_injection"] = issues

    # Reflection in Location header is the most dangerous (password-reset poisoning).
    in_location = any(i["reflected_in"] == "Location header" for i in issues)

    result.add(Finding(
        id="deep.host_header_injection",
        title=f"Host-Header-Injection: Server reflektiert manipulierten Host ({len(issues)} Vektor(en))",
        description=(
            "Der Server übernimmt den vom Client gesendeten Host-Header (oder X-Forwarded-Host) "
            "ungeprüft in die Response. Das ermöglicht:\n"
            "1. Password-Reset-Poisoning: Angreifer setzt Host: evil.com, opfert erhält Reset-Mail "
            "mit Link zu evil.com.\n"
            "2. Web-Cache-Poisoning: CDN cacht die vergiftete Response und liefert sie an alle Besucher.\n"
            "3. SSRF: Backend-Services die Host vertrauen senden Requests an den Angreifer-Host."
            + ("\n\n⚠️ Reflection im Location-Header — Password-Reset-Poisoning direkt möglich!" if in_location else "")
        ),
        severity=Severity.HIGH if in_location else Severity.MEDIUM,
        category="Deep Scan",
        evidence={"issues": issues},
        recommendation=(
            "Host-Header im Webserver hart auf die eigene Domain setzen (nginx: `server_name` "
            "strict, Apache: `UseCanonicalName On`). X-Forwarded-Host nur von vertrauenswürdigen "
            "Reverse-Proxies akzeptieren."
        ),
    ))
