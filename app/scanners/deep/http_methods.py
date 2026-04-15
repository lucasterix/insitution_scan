"""HTTP methods probe — checks whether the server accepts dangerous verbs.

TRACE can enable Cross-Site Tracing (XST), PUT/DELETE without auth = catastrophic,
OPTIONS tells us which methods are advertised.
"""
from __future__ import annotations

from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

DANGEROUS_METHODS: list[tuple[str, Severity, str]] = [
    ("TRACE", Severity.MEDIUM, "TRACE aktiv — Cross-Site Tracing (XST) möglich"),
    ("PUT", Severity.HIGH, "PUT akzeptiert — ermöglicht Datei-Upload ohne Auth"),
    ("DELETE", Severity.HIGH, "DELETE akzeptiert — Löschoperationen ohne Auth"),
    ("PATCH", Severity.MEDIUM, "PATCH akzeptiert ohne Auth"),
    ("CONNECT", Severity.HIGH, "CONNECT akzeptiert — Server kann als Proxy missbraucht werden"),
]


def check_http_methods(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("HTTP Methods Probe", 62)

    # Pull OPTIONS first to see what the server claims.
    allowed: list[str] = []
    try:
        with httpx.Client(
            timeout=8.0,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            opt = client.request("OPTIONS", f"https://{domain}/")
            allow = opt.headers.get("allow", "")
            if allow:
                allowed = [m.strip().upper() for m in allow.split(",")]
            result.metadata["http_methods_allowed"] = allowed

            # Probe each dangerous method.
            for method, sev, label in DANGEROUS_METHODS:
                try:
                    r = client.request(method, f"https://{domain}/")
                except httpx.HTTPError:
                    continue
                # 200 on TRACE with the request echoed back is the classic XST indicator.
                if method == "TRACE":
                    if r.status_code == 200 and "trace" in (r.text or "").lower()[:200]:
                        result.add(Finding(
                            id="deep.http_trace_enabled",
                            title=label,
                            description="TRACE mit HTTP 200 beantwortet. Kombiniert mit XSS ermöglicht das Cross-Site Tracing.",
                            severity=sev,
                            category="Deep Scan",
                            evidence={"status": r.status_code},
                            recommendation="TRACE am Webserver deaktivieren (nginx: unterbinden mit `if ($request_method = TRACE)`).",
                        ))
                    continue

                # For PUT/DELETE/PATCH/CONNECT: 200/201/204 without auth = finding.
                if r.status_code in (200, 201, 204):
                    result.add(Finding(
                        id=f"deep.http_{method.lower()}_accepted",
                        title=label,
                        description=f"Server akzeptierte {method} auf / ohne Auth (HTTP {r.status_code}).",
                        severity=sev,
                        category="Deep Scan",
                        evidence={"method": method, "status": r.status_code},
                        recommendation=f"Am Webserver nur zugelassene Methoden whitelisten und {method} explizit verbieten.",
                    ))
    except httpx.HTTPError:
        return
