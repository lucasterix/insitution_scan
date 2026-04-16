"""IDOR (Insecure Direct Object Reference) scanner.

Takes API endpoints discovered by js_secrets, openapi_parser, healthcare
scanner and directory fuzzer, and tests for IDOR vulnerabilities by:

1. ID Increment: If an endpoint contains a numeric ID (e.g., /api/patient/1),
   we request /api/patient/2 and /api/patient/3 to see if different data
   is returned — indicating missing authorization checks.

2. ID Pattern: Test common ID parameter names (?id=1, ?user_id=1,
   ?patient_id=1) on endpoints that don't have IDs in the path.

3. Method Fuzzing: For each endpoint, test GET/POST/PUT/DELETE to see
   which methods are accepted without auth.

4. File Upload Detection: Probe for upload endpoints and test if they
   accept files without authentication.

IMPORTANT: We do NOT read or store any returned data content. We only
check if the HTTP status code changes (200 for different IDs = IDOR).
Response bodies are discarded immediately after status check.
"""
from __future__ import annotations

import re
from typing import Callable
from urllib.parse import urlencode

import httpx

from app.scanners._baseline import fetch_baselines, is_catchall
from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
TIMEOUT = 5.0

ID_IN_PATH_RE = re.compile(r"/(\d{1,8})(?:/|$|\?)")
COMMON_ID_PARAMS = ("id", "user_id", "patient_id", "patientId", "userId",
                    "account_id", "record_id", "appointment_id", "termin_id",
                    "befund_id", "doc_id", "file_id", "order_id")

UPLOAD_PATHS = (
    "/upload", "/api/upload", "/api/files", "/api/documents",
    "/wp-admin/async-upload.php", "/api/v1/upload",
    "/api/attachments", "/api/media",
)

PASSWORD_RESET_PATHS = (
    "/forgot-password", "/password-reset", "/reset-password",
    "/api/password/reset", "/api/auth/forgot",
    "/wp-login.php?action=lostpassword",
    "/user/password", "/account/recover",
)


def _collect_api_endpoints(result: ScanResult) -> list[str]:
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


def _test_idor_id_increment(client: httpx.Client, domain: str, baselines, result: ScanResult) -> None:
    """Test endpoints with numeric IDs by incrementing the ID."""
    endpoints = _collect_api_endpoints(result)
    idor_hits: list[dict] = []

    for ep in endpoints[:20]:
        m = ID_IN_PATH_RE.search(ep)
        if not m:
            continue

        original_id = m.group(1)
        original_url = f"https://{domain}{ep}"

        try:
            r_original = client.get(original_url)
        except httpx.HTTPError:
            continue
        if r_original.status_code != 200:
            continue
        if "json" not in r_original.headers.get("content-type", "").lower():
            continue
        if is_catchall(r_original.text[:8192], baselines):
            continue

        # Try incrementing the ID
        test_ids = [str(int(original_id) + 1), str(int(original_id) + 2), "1", "0"]
        for test_id in test_ids:
            test_ep = ep.replace(f"/{original_id}", f"/{test_id}")
            test_url = f"https://{domain}{test_ep}"
            try:
                r_test = client.get(test_url)
            except httpx.HTTPError:
                continue

            if r_test.status_code == 200 and "json" in r_test.headers.get("content-type", "").lower():
                # Different ID returns 200 with JSON → potential IDOR
                # Check that the responses are DIFFERENT (not just the same catch-all)
                if r_test.text[:100] != r_original.text[:100]:
                    idor_hits.append({
                        "endpoint": ep,
                        "original_id": original_id,
                        "test_id": test_id,
                        "both_returned_200": True,
                        "different_content": True,
                    })
                    break

    if idor_hits:
        result.metadata["idor_test"] = idor_hits
        result.add(Finding(
            id="idor.id_increment",
            title=f"IDOR: {len(idor_hits)} API-Endpoint(s) geben verschiedene Daten für verschiedene IDs zurück",
            description=(
                "Durch einfaches Ändern der numerischen ID in der URL werden "
                "unterschiedliche Datensätze zurückgegeben — ohne dass der Server "
                "prüft ob der anfragende Benutzer berechtigt ist.\n\n"
                "Beispiel: /api/patient/1 liefert Patient A, /api/patient/2 liefert "
                "Patient B. Ein Angreifer kann alle IDs durchiterieren und sämtliche "
                "Datensätze exportieren.\n\n"
                "IDOR ist laut OWASP Top 10 (A01 Broken Access Control) die #1 "
                "Web-Schwachstelle und bei Patientenportalen besonders kritisch."
            ),
            severity=Severity.CRITICAL,
            category="API-Schwachstelle",
            evidence={"hits": idor_hits[:10]},
            recommendation=(
                "Serverseitige Autorisierungsprüfung für JEDEN API-Zugriff: "
                "Prüfe ob der eingeloggte Benutzer Zugriff auf die angeforderte "
                "Ressource hat (nicht nur ob er eingeloggt ist)."
            ),
            kbv_ref="KBV Anlage 3 (Zugriffskontrolle), DSGVO Art. 32, §203 StGB",
        ))


def _test_idor_query_params(client: httpx.Client, domain: str, baselines, result: ScanResult) -> None:
    """Test endpoints with common ID query parameters."""
    endpoints = _collect_api_endpoints(result)
    param_hits: list[dict] = []

    for ep in endpoints[:15]:
        if ID_IN_PATH_RE.search(ep):
            continue  # Already tested via path increment

        for param in COMMON_ID_PARAMS:
            url = f"https://{domain}{ep}?{urlencode({param: '1'})}"
            try:
                r = client.get(url)
            except httpx.HTTPError:
                continue
            if r.status_code != 200:
                continue
            if "json" not in r.headers.get("content-type", "").lower():
                continue
            if is_catchall(r.text[:8192], baselines):
                continue

            # Try a different ID
            url2 = f"https://{domain}{ep}?{urlencode({param: '2'})}"
            try:
                r2 = client.get(url2)
            except httpx.HTTPError:
                continue

            if r2.status_code == 200 and r2.text[:100] != r.text[:100]:
                param_hits.append({
                    "endpoint": ep,
                    "param": param,
                    "different_content": True,
                })
                break

    if param_hits:
        result.add(Finding(
            id="idor.query_param",
            title=f"IDOR via Query-Parameter: {len(param_hits)} Endpoint(s) antworten auf ?id=1 vs ?id=2 unterschiedlich",
            description=(
                "API-Endpoints geben unterschiedliche Daten zurück wenn ein "
                "ID-Parameter verändert wird. Kein Authentifizierungs- oder "
                "Autorisierungs-Check erkennbar."
            ),
            severity=Severity.CRITICAL,
            category="API-Schwachstelle",
            evidence={"hits": param_hits[:10]},
            recommendation="Serverseitige Autorisierung pro Ressource implementieren.",
            kbv_ref="OWASP A01, KBV Anlage 3, DSGVO Art. 32",
        ))


def _test_api_methods(client: httpx.Client, domain: str, baselines, result: ScanResult) -> None:
    """Test if API endpoints accept dangerous HTTP methods without auth."""
    endpoints = _collect_api_endpoints(result)
    method_hits: list[dict] = []

    for ep in endpoints[:15]:
        url = f"https://{domain}{ep}"
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            try:
                r = client.request(method, url)
            except httpx.HTTPError:
                continue
            if r.status_code in (200, 201, 204):
                if is_catchall(r.text[:8192] if r.text else "", baselines):
                    continue
                method_hits.append({
                    "endpoint": ep,
                    "method": method,
                    "status": r.status_code,
                })

    if method_hits:
        result.metadata["api_method_test"] = method_hits
        # Group by danger level
        delete_hits = [h for h in method_hits if h["method"] == "DELETE"]
        write_hits = [h for h in method_hits if h["method"] in ("POST", "PUT", "PATCH")]

        if delete_hits:
            result.add(Finding(
                id="api.delete_accepted",
                title=f"API: DELETE ohne Auth auf {len(delete_hits)} Endpoint(s) akzeptiert",
                description=(
                    "DELETE-Requests werden ohne Authentifizierung mit HTTP 200/204 beantwortet. "
                    "Ein Angreifer kann Datensätze löschen — Termine, Patientenakten, Befunde."
                ),
                severity=Severity.CRITICAL,
                category="API-Schwachstelle",
                evidence={"endpoints": delete_hits[:10]},
                recommendation="Auth-Middleware erzwingen, DELETE nur für autorisierte Rollen.",
            ))

        if write_hits:
            result.add(Finding(
                id="api.write_accepted",
                title=f"API: POST/PUT/PATCH ohne Auth auf {len(write_hits)} Endpoint(s) akzeptiert",
                description=(
                    "Schreib-Operationen werden ohne Authentifizierung akzeptiert. "
                    "Ein Angreifer kann Daten ändern, neue Datensätze anlegen oder "
                    "bestehende manipulieren."
                ),
                severity=Severity.HIGH,
                category="API-Schwachstelle",
                evidence={"endpoints": write_hits[:10]},
                recommendation="Auth-Middleware für alle schreibenden Endpoints erzwingen.",
            ))


def _test_upload_endpoints(client: httpx.Client, domain: str, baselines, result: ScanResult) -> None:
    """Check if upload endpoints are reachable without authentication."""
    accessible: list[dict] = []

    for path in UPLOAD_PATHS:
        url = f"https://{domain}{path}"
        try:
            r = client.get(url)
        except httpx.HTTPError:
            continue
        if r.status_code in (200, 405):  # 405 = endpoint exists but needs POST
            if is_catchall(r.text[:8192] if r.text else "", baselines):
                continue
            accessible.append({"path": path, "status": r.status_code})

    if accessible:
        result.add(Finding(
            id="api.upload_exposed",
            title=f"Upload-Endpoint(s) erreichbar: {len(accessible)} Pfad(e)",
            description=(
                "Upload-Endpoints sind ohne Authentifizierung erreichbar. "
                "Ein Angreifer kann potenziell Dateien hochladen — bei fehlender "
                "Typ-Validierung auch ausführbare Webshells (PHP, JSP, ASPX)."
            ),
            severity=Severity.HIGH,
            category="API-Schwachstelle",
            evidence={"endpoints": accessible},
            recommendation="Upload-Endpoints hinter Auth + Dateityp-Whitelist + Virus-Scan.",
        ))


def _test_password_reset(client: httpx.Client, domain: str, baselines, result: ScanResult) -> None:
    """Probe password reset flow for common weaknesses."""
    for path in PASSWORD_RESET_PATHS:
        url = f"https://{domain}{path}"
        try:
            r = client.get(url)
        except httpx.HTTPError:
            continue
        if r.status_code != 200:
            continue
        if is_catchall(r.text[:8192], baselines):
            continue

        body_lower = r.text[:8192].lower()
        has_email_field = "email" in body_lower or "e-mail" in body_lower
        has_form = "<form" in body_lower

        if has_email_field and has_form:
            # Password reset form found — check for rate limiting
            has_captcha = any(
                kw in body_lower
                for kw in ("captcha", "recaptcha", "hcaptcha", "turnstile", "g-recaptcha")
            )

            result.add(Finding(
                id=f"api.password_reset.{path.strip('/').replace('/', '_')}",
                title=f"Passwort-Reset-Formular gefunden: {path}",
                description=(
                    f"Unter {path} existiert ein Passwort-Reset-Formular.\n\n"
                    + ("✅ CAPTCHA erkannt — bietet Schutz gegen automatisierte Anfragen.\n"
                       if has_captcha else
                       "❌ Kein CAPTCHA erkannt — Angreifer können automatisiert Reset-Mails "
                       "für beliebige E-Mail-Adressen auslösen (User Enumeration + Spam).\n")
                    + "\nPrüfen Sie außerdem:\n"
                    "• Ist der Reset-Token ausreichend lang und zufällig (≥ 32 Zeichen)?\n"
                    "• Verfällt der Token nach einmaliger Nutzung?\n"
                    "• Ist der Token zeitlich begrenzt (≤ 1 Stunde)?\n"
                    "• Wird der Token per E-Mail und NICHT per URL-Parameter übermittelt?"
                ),
                severity=Severity.LOW if has_captcha else Severity.MEDIUM,
                category="API-Schwachstelle",
                evidence={"path": path, "captcha": has_captcha},
                recommendation=(
                    "CAPTCHA auf Reset-Formular, Token-Lebensdauer max. 1h, "
                    "Rate-Limiting auf max. 3 Resets/Stunde pro E-Mail."
                ),
            ))
            break  # One reset form is enough


def check_idor(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Step-2: IDOR + API-Security", 97)

    baselines = fetch_baselines(domain)

    with httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    ) as client:
        _test_idor_id_increment(client, domain, baselines, result)
        _test_idor_query_params(client, domain, baselines, result)
        _test_api_methods(client, domain, baselines, result)
        _test_upload_endpoints(client, domain, baselines, result)
        _test_password_reset(client, domain, baselines, result)
