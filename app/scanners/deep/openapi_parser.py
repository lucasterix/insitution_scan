"""Swagger / OpenAPI spec parser.

If a publicly accessible Swagger-UI or OpenAPI spec is found, we pull the
spec JSON and enumerate every endpoint + HTTP method. This is like publishing
the Postman collection for every attacker to import.
"""
from __future__ import annotations

from typing import Callable
from urllib.parse import urljoin

import httpx

from app.scanners._baseline import fetch_baselines, is_catchall
from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

SPEC_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v1/openapi.json",
    "/v2/swagger.json",
    "/api/v1/openapi.json",
    "/docs/openapi.json",
    "/.well-known/openapi.json",
)


def _try_fetch_spec(client: httpx.Client, domain: str, baselines) -> tuple[str, dict] | None:
    for path in SPEC_PATHS:
        try:
            r = client.get(f"https://{domain}{path}")
        except httpx.HTTPError:
            continue
        if r.status_code != 200:
            continue
        ct = r.headers.get("content-type", "").lower()
        if "json" not in ct and "yaml" not in ct:
            continue
        body = r.text[:32768]
        if is_catchall(body, baselines):
            continue
        try:
            data = r.json()
        except ValueError:
            continue
        # Validate it looks like OpenAPI / Swagger
        if data.get("openapi") or data.get("swagger") or data.get("paths"):
            return path, data
    return None


def check_openapi(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("OpenAPI / Swagger Parser", 60)

    baselines = fetch_baselines(domain)

    with httpx.Client(
        timeout=8.0,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        found = _try_fetch_spec(client, domain, baselines)

    if not found:
        return

    path, spec = found
    version = spec.get("openapi") or spec.get("swagger") or "unknown"
    info = spec.get("info") or {}
    title = info.get("title", "")
    api_version = info.get("version", "")
    paths = spec.get("paths") or {}

    endpoints: list[dict] = []
    for ep_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "options"):
            if method in methods:
                op = methods[method]
                summary = ""
                if isinstance(op, dict):
                    summary = op.get("summary", "") or op.get("description", "")[:100]
                endpoints.append({
                    "method": method.upper(),
                    "path": ep_path,
                    "summary": summary[:100],
                })

    auth_sensitive = any(
        any(kw in ep["path"].lower() for kw in ("user", "patient", "auth", "admin", "login", "token", "password"))
        for ep in endpoints
    )

    result.metadata["openapi"] = {
        "spec_path": path,
        "openapi_version": version,
        "title": title,
        "api_version": api_version,
        "endpoints_count": len(endpoints),
        "endpoints": endpoints[:50],
    }

    sev = Severity.HIGH if auth_sensitive else Severity.MEDIUM

    result.add(Finding(
        id="deep.openapi_exposed",
        title=f"OpenAPI/Swagger-Spec öffentlich: {len(endpoints)} Endpoints ({title or 'untitled'})",
        description=(
            f"Unter {path} ist die vollständige API-Spezifikation (v{version}) ohne Auth abrufbar. "
            f"Sie definiert {len(endpoints)} Endpoints"
            + (f" — darunter auth-/user-/patient-sensible Pfade." if auth_sensitive
               else ".") +
            "\n\nEin Angreifer kann diese Spec in Postman/Burp importieren und jeden Endpoint "
            "systematisch auf Input-Validation-Fehler, Auth-Bypasses und IDOR testen."
        ),
        severity=sev,
        category="Deep Scan",
        evidence={
            "spec_path": path,
            "version": version,
            "endpoints_sample": endpoints[:20],
        },
        recommendation=(
            "API-Spec nur hinter Auth ausliefern oder in der Produktion komplett abschalten. "
            "FastAPI: `docs_url=None, redoc_url=None, openapi_url=None` in Production."
        ),
    ))
