"""Unauthenticated API endpoint probing.

Takes API endpoints discovered by:
- js_secrets.py (JS-extracted /api/* paths)
- openapi_parser.py (Swagger/OpenAPI spec endpoints)
- healthcare.py (sensitive health paths)

And sends a GET (+ POST for mutation-like paths) without authentication.
If the server returns 200 with JSON data, it's a broken-auth finding.
"""
from __future__ import annotations

from typing import Callable

import httpx

from app.scanners._baseline import fetch_baselines, is_catchall
from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
TIMEOUT = 5.0

SENSITIVE_KEYWORDS = ("patient", "user", "account", "medical", "health",
                      "appointment", "termin", "befund", "rezept", "diagnos",
                      "auth", "admin", "token", "password", "credential")


def _collect_endpoints(result: ScanResult) -> list[str]:
    """Collect API endpoints from all step-1 sources."""
    eps: set[str] = set()

    js = result.metadata.get("js_analysis") or {}
    for ep in js.get("api_endpoints_found") or []:
        eps.add(ep)

    openapi = result.metadata.get("openapi") or {}
    for ep_info in openapi.get("endpoints") or []:
        path = ep_info.get("path", "")
        if path:
            eps.add(path)

    health = result.metadata.get("health_paths") or []
    for h in health:
        p = h.get("path", "")
        if p.startswith("/api"):
            eps.add(p)

    return sorted(eps)


def check_api_auth(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Step-2: API-Auth-Test", 97)

    endpoints = _collect_endpoints(result)
    if not endpoints:
        return

    baselines = fetch_baselines(domain)
    open_endpoints: list[dict] = []

    with httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    ) as client:
        for ep in endpoints[:30]:
            url = f"https://{domain}{ep}"
            try:
                r = client.get(url)
            except httpx.HTTPError:
                continue

            if r.status_code not in (200, 201):
                continue
            ct = r.headers.get("content-type", "").lower()
            if "json" not in ct:
                continue
            body = r.text[:4096]
            if is_catchall(body, baselines):
                continue

            try:
                data = r.json()
            except ValueError:
                continue

            has_data = False
            if isinstance(data, list) and len(data) > 0:
                has_data = True
            elif isinstance(data, dict) and len(data) > 2:
                has_data = True

            if not has_data:
                continue

            is_sensitive = any(kw in ep.lower() for kw in SENSITIVE_KEYWORDS)

            open_endpoints.append({
                "path": ep,
                "status": r.status_code,
                "data_type": "array" if isinstance(data, list) else "object",
                "data_keys": list(data[0].keys())[:10] if isinstance(data, list) and data and isinstance(data[0], dict) else list(data.keys())[:10] if isinstance(data, dict) else [],
                "sensitive": is_sensitive,
            })

    if not open_endpoints:
        return

    result.metadata["api_auth_test"] = open_endpoints

    sensitive_open = [e for e in open_endpoints if e["sensitive"]]
    generic_open = [e for e in open_endpoints if not e["sensitive"]]

    if sensitive_open:
        result.add(Finding(
            id="step2.api_unauth_sensitive",
            title=f"{len(sensitive_open)} sensible API-Endpoint(s) ohne Auth erreichbar",
            description=(
                "Die folgenden API-Endpunkte geben ohne Authentifizierung JSON-Daten "
                "mit sensiblen Inhalten zurück (Schlüsselwörter: patient, medical, auth, admin, ...). "
                "Das ist eine der schwerwiegendsten Schwachstellen: IDOR / Broken Access Control "
                "ermöglicht Angreifern den Zugriff auf Patientendaten."
            ),
            severity=Severity.CRITICAL,
            category="Step-2 Analyse",
            evidence={"endpoints": sensitive_open[:10]},
            recommendation="Sofort Auth-Middleware für alle API-Endpunkte erzwingen. JWT/Session-Check vor jeder Response.",
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 3 (Zugriffskontrolle) + DSGVO Art. 32",
        ))

    if generic_open:
        result.add(Finding(
            id="step2.api_unauth_generic",
            title=f"{len(generic_open)} API-Endpoint(s) geben Daten ohne Auth zurück",
            description=(
                "Die folgenden API-Endpunkte antworten mit JSON-Daten ohne Authentifizierung. "
                "Auch wenn die Daten nicht direkt sensibel erscheinen, offenbaren sie die "
                "interne API-Struktur und können als Sprungbrett für weitere Angriffe dienen."
            ),
            severity=Severity.MEDIUM,
            category="Step-2 Analyse",
            evidence={"endpoints": generic_open[:10]},
            recommendation="API-Endpunkte prüfen — nur bewusst öffentliche Daten ohne Auth ausliefern.",
        ))
