"""HTTP methods probe — checks whether the server accepts dangerous verbs.

TRACE can enable Cross-Site Tracing (XST), PUT/DELETE without auth = catastrophic,
OPTIONS tells us which methods are advertised.
"""
from __future__ import annotations

from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity
from app.scanners._baseline import fetch_baselines, is_catchall

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

    # SPA defense: fetch the homepage catch-all fingerprint up front. Next.js
    # and similar SPAs return HTTP 200 with the same HTML for any method
    # (PUT/DELETE/PATCH get the homepage too) — a 200 alone proves nothing.
    baselines = fetch_baselines(domain)

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

                # For PUT/DELETE/PATCH/CONNECT: 200/201/204 with EVIDENCE of
                # actual acceptance = finding. Evidence = any of:
                #   - 201 Created (real resource creation)
                #   - 204 No Content (real deletion, no body)
                #   - 200 response that differs from the homepage catch-all
                #     AND does not look like HTML (an API'd return JSON/text).
                # This eliminates the Next.js / React SPA / CMS-catch-all FP
                # that was flagging 11 of 30 practice sites falsely.
                if r.status_code not in (200, 201, 204):
                    continue
                if r.status_code == 200:
                    ct = (r.headers.get("content-type") or "").lower()
                    body = r.text or ""
                    # HTML responses on PUT/DELETE/PATCH/CONNECT are almost
                    # always false positives: Next.js, WordPress themes,
                    # Typo3, Joomla, static-SPA builds all return HTML for
                    # every verb without actually writing anything. A real
                    # write endpoint responds with JSON (REST), XML (SOAP),
                    # or empty (204). We skip HTML 200 entirely — the risk
                    # of missing a truly broken method-accepting server is
                    # much smaller than the risk of shipping FPs to every
                    # practice website.
                    if "html" in ct:
                        continue
                    # JSON/plaintext 200: still do the baseline compare in
                    # case the server renders its homepage as JSON (rare).
                    if is_catchall(body, baselines):
                        continue
                result.add(Finding(
                    id=f"deep.http_{method.lower()}_accepted",
                    title=label,
                    description=(
                        f"Server antwortete auf {method} auf / mit HTTP {r.status_code}. "
                        f"Content-Type: {r.headers.get('content-type', 'unbekannt')}. "
                        "Manuell verifizieren, ob die Methode tatsächlich Schreibzugriff "
                        "hat — eine 200 allein kann auch eine SPA-Route sein."
                    ),
                    severity=sev,
                    category="Deep Scan",
                    evidence={
                        "method": method,
                        "status": r.status_code,
                        "content_type": r.headers.get("content-type", ""),
                    },
                    recommendation=(
                        f"Am Webserver nur zugelassene Methoden whitelisten und {method} "
                        "explizit verbieten. Bei SPAs ggf. nur statistisch relevant — "
                        "prüfen ob tatsächlich eine Änderung am Ressourcen-Zustand erfolgt."
                    ),
                ))
    except httpx.HTTPError:
        return
