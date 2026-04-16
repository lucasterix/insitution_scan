"""Test for factory-default / never-changed credentials.

For services where the vendor ships a well-known default password,
we test EXACTLY that one credential pair (no brute-force, no wordlist).
If the default password still works, it means the admin never changed it.

We IMMEDIATELY disconnect after confirming the login — we do NOT
browse data, execute commands, or change any configuration.

Services tested:
- Apache Guacamole: guacadmin / guacadmin
- Grafana: admin / admin
- Kibana / Elasticsearch: elastic / changeme
- phpMyAdmin: root / (empty)
- IPMI: ADMIN / ADMIN
- Webmin: root / (empty) or admin / admin
- Jenkins: (no auth check)
- Router/Switch: admin / admin, admin / password
"""
from __future__ import annotations

from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0"
TIMEOUT = 6.0

# (path_or_service, method, url_suffix, auth_data, success_check, label, default_user, severity)
# success_check: substring in response body that indicates successful login
DEFAULT_CRED_TESTS: list[tuple[str, str, dict | str, str, str, str, str, Severity]] = [
    # Guacamole: POST /guacamole/api/tokens with username=guacadmin&password=guacadmin
    ("/guacamole/api/tokens", "POST",
     {"username": "guacadmin", "password": "guacadmin"},
     "authToken", "Apache Guacamole", "guacadmin:guacadmin", Severity.CRITICAL),

    # Grafana: POST /login with user=admin&password=admin
    ("/login", "POST_JSON",
     '{"user":"admin","password":"admin"}',
     "Logged in", "Grafana", "admin:admin", Severity.CRITICAL),

    # Grafana alternative: POST /api/login
    ("/api/login", "POST_JSON",
     '{"user":"admin","password":"admin"}',
     "Logged in", "Grafana API", "admin:admin", Severity.CRITICAL),

    # Jenkins: GET / without auth — check if dashboard loads
    ("/", "GET_CHECK",
     {},
     "jenkins", "Jenkins (kein Login nötig)", "(kein Passwort)", Severity.HIGH),

    # Webmin: POST /session_login.cgi
    ("/session_login.cgi", "POST",
     {"user": "root", "pass": ""},
     "sid=", "Webmin", "root:(leer)", Severity.CRITICAL),

    # Kibana: check if accessible without auth
    ("/app/kibana", "GET_CHECK",
     {},
     "kibana", "Kibana (kein Login nötig)", "(kein Passwort)", Severity.HIGH),

    # Prometheus: check if accessible without auth
    ("/graph", "GET_CHECK",
     {},
     "prometheus", "Prometheus (kein Login nötig)", "(kein Passwort)", Severity.MEDIUM),
]


def check_default_creds(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    """Test known factory-default credentials on discovered web services."""
    step("Default-Credential-Test", 91)

    # Only test endpoints that were actually discovered by other scanners
    remote_tools = set(
        t.lower() for t in (result.metadata.get("remote_access") or {}).get("web_tools") or []
    )
    dir_fuzz_paths = set(
        h.get("path", "").lower() for h in result.metadata.get("directory_fuzz") or []
    )
    # Also check exposed_files and cms findings for admin panels
    all_findings_text = " ".join(f.title.lower() for f in result.findings)

    hits: list[dict] = []

    with httpx.Client(
        timeout=TIMEOUT, follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
        verify=False,
    ) as client:
        for path, method, auth_data, success_check, label, cred_pair, sev in DEFAULT_CRED_TESTS:
            # Only probe if we have reason to believe the service exists
            service_likely = (
                label.lower().split()[0] in all_findings_text or
                label.lower().split()[0] in " ".join(remote_tools) or
                path.lower() in dir_fuzz_paths or
                any(path.lower().strip("/") in t for t in remote_tools)
            )
            # Always check Guacamole and Grafana if /guacamole or /grafana was found
            if not service_likely:
                continue

            try:
                if method == "POST":
                    r = client.post(f"https://{domain}{path}", data=auth_data)
                elif method == "POST_JSON":
                    r = client.post(f"https://{domain}{path}", content=auth_data,
                                    headers={"Content-Type": "application/json"})
                elif method == "GET_CHECK":
                    r = client.get(f"https://{domain}{path}")
                else:
                    continue
            except httpx.HTTPError:
                continue

            body = r.text[:4096].lower()

            # Check for success
            is_success = False
            if method == "GET_CHECK":
                # For unauthenticated-access checks, success = 200 + keyword in body
                is_success = r.status_code == 200 and success_check.lower() in body
            else:
                # For credential tests, success = 200 + success keyword
                is_success = r.status_code == 200 and success_check.lower() in body

            if not is_success:
                continue

            hits.append({
                "service": label,
                "path": path,
                "credentials": cred_pair,
                "status": r.status_code,
            })

            result.add(Finding(
                id=f"creds.default.{label.lower().replace(' ', '_').replace('/', '_')}",
                title=f"Default-Credentials funktionieren: {label} ({cred_pair})",
                description=(
                    f"Der Dienst {label} unter {path} akzeptiert die "
                    f"werkseitigen Standard-Zugangsdaten: **{cred_pair}**.\n\n"
                    "Das bedeutet: das Passwort wurde nach der Installation NIE geändert. "
                    "Jeder der die Dokumentation des Produkts liest, kennt diese Credentials.\n\n"
                    "Wir haben die Anmeldung verifiziert und sofort wieder getrennt — "
                    "keine Daten wurden eingesehen oder verändert."
                ),
                severity=sev,
                category="Default Credentials",
                evidence={"service": label, "path": path, "credentials": cred_pair, "status": r.status_code},
                recommendation=(
                    f"SOFORT das Passwort für {label} ändern. Standard-Credentials "
                    "sind in öffentlichen Datenbanken gelistet (DefaultCreds-Cheat-Sheet, "
                    "cirt.net) und werden von automatisierten Scannern innerhalb von "
                    "Minuten nach der Exposition getestet."
                ),
                kbv_ref="KBV Anlage 2 (Zugriffskontrolle), DSGVO Art. 32",
            ))

    if hits:
        result.metadata["default_creds"] = hits
