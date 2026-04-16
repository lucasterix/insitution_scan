"""Active CORS misconfiguration test.

We send three crafted Origin headers:

1. A random attacker origin (https://evil-mvzscan-test.invalid)
2. A null origin ("Origin: null")
3. The domain suffixed with "-evil.com"

If the server echoes any of these back in Access-Control-Allow-Origin
— especially combined with Access-Control-Allow-Credentials: true —
that is a CRITICAL finding.
"""
from __future__ import annotations

from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

MALICIOUS_ORIGINS = (
    "https://evil-mvzscan-test.invalid",
    "null",
    "https://attacker.example",
)


def check_cors(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Active CORS Test", 65)

    issues: list[dict] = []
    try:
        with httpx.Client(
            timeout=6.0,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            for origin in MALICIOUS_ORIGINS:
                try:
                    r = client.get(f"https://{domain}/", headers={"Origin": origin})
                except httpx.HTTPError:
                    continue
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "").lower()

                if not acao:
                    continue

                # 1. Full wildcard with credentials — forbidden by spec but seen in the wild.
                if acao == "*" and acac == "true":
                    issues.append(
                        {
                            "origin_sent": origin,
                            "issue": "wildcard_with_credentials",
                            "acao": acao,
                            "acac": acac,
                        }
                    )
                # 2. Reflected attacker origin
                elif acao.strip() == origin:
                    issues.append(
                        {
                            "origin_sent": origin,
                            "issue": "origin_reflected",
                            "acao": acao,
                            "acac": acac,
                        }
                    )
                # 3. null origin accepted
                elif origin == "null" and acao.strip().lower() == "null":
                    issues.append(
                        {
                            "origin_sent": origin,
                            "issue": "null_origin_allowed",
                            "acao": acao,
                            "acac": acac,
                        }
                    )
    except httpx.HTTPError:
        return

    if not issues:
        return

    result.metadata["cors_issues"] = issues
    # Severity CRITICAL if any issue comes with credentials: true
    critical = any(i.get("acac") == "true" for i in issues)

    result.add(Finding(
        id="deep.cors_misconfigured",
        title=f"CORS-Konfiguration erlaubt unsichere Origin-Rückmeldungen ({len(issues)})",
        description=(
            "Der Server spiegelt vom Client gesendete Origins im Access-Control-Allow-Origin "
            "zurück oder akzeptiert 'null' bzw. Wildcard mit Credentials. Ein Angreifer kann "
            "dadurch im Browser des Opfers cross-origin Reads auf geschützte Endpunkte ausführen."
        ),
        # With credentials:true + reflected origin = direct cross-origin data exfil
        # but requires victim to visit attacker page while logged in → HIGH, not CRITICAL.
        # Without credentials = info-leak, effect depends on endpoint → LOW/MEDIUM.
        severity=Severity.HIGH if critical else Severity.LOW,
        category="Deep Scan",
        evidence={"issues": issues},
        recommendation=(
            "CORS-Policy auf eine definierte Whitelist setzen. Niemals dynamisch die Request-Origin "
            "zurückgeben. Credentials nur für exakt eine vertrauenswürdige Origin zulassen."
        ),
    ))
