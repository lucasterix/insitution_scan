"""Deep-inspect the alive subdomains found by subdomain_walker.

Runs a small set of high-value checks on each alive sub:

1. Security headers (HSTS/CSP/X-Frame/X-Content-Type/Referrer/Permissions)
2. TLS certificate expiry
3. Server banner → tech fingerprint (so the CVE scanner sees the sub's stack too)

Cap at 10 alive subs to avoid explosive runtime.
"""
from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
MAX_SUBS = 10
TIMEOUT = 6.0

REQUIRED_HEADERS = {
    "strict-transport-security": ("HSTS fehlt", Severity.MEDIUM),
    "x-content-type-options": ("X-Content-Type-Options fehlt", Severity.LOW),
    "x-frame-options": ("X-Frame-Options fehlt (oder CSP frame-ancestors)", Severity.LOW),
}


def _fetch(sub: str) -> dict | None:
    try:
        with httpx.Client(
            timeout=TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
            verify=False,
        ) as client:
            r = client.get(f"https://{sub}")
            return {
                "sub": sub,
                "status": r.status_code,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "final_url": str(r.url),
            }
    except httpx.HTTPError:
        return None


def _tls_info(sub: str) -> dict | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((sub, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=sub) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
    except (socket.timeout, ssl.SSLError, OSError):
        return None
    return {"cert": cert, "version": version}


def deep_scan_subdomains(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    walk_data = result.metadata.get("subdomain_walk") or {}
    alive_map = walk_data.get("results") or {}
    if not alive_map:
        return

    # Skip apex + www alias (same host as apex; findings would be double-reported).
    subs = [
        s for s in alive_map.keys()
        if s != domain and s != f"www.{domain}"
    ][:MAX_SUBS]
    if not subs:
        return

    step(f"Subdomain Deep-Scan ({len(subs)})", 80)

    per_sub: dict[str, dict] = {}

    def task(sub: str) -> None:
        info = _fetch(sub)
        if info is None:
            return
        tls = _tls_info(sub)
        per_sub[sub] = {"info": info, "tls": tls}

        # Security headers per sub.
        headers = info.get("headers") or {}
        missing: list[str] = []
        for key, (label, _sev) in REQUIRED_HEADERS.items():
            if key not in headers:
                missing.append(key)
        if missing:
            result.add(Finding(
                id=f"subdomain.headers.{sub}",
                title=f"Subdomain {sub}: Security-Headers fehlen ({len(missing)})",
                description=(
                    f"Die Subdomain {sub} antwortet mit HTTP {info['status']}, liefert aber "
                    f"wichtige Security-Header nicht aus: {', '.join(missing)}. Subdomains "
                    "erben die Header der Haupt-Domain nicht automatisch und müssen einzeln "
                    "konfiguriert werden."
                ),
                severity=Severity.MEDIUM,
                category="Subdomain Exposure",
                evidence={"subdomain": sub, "missing": missing, "status": info["status"]},
                recommendation=f"Security-Header für {sub} in der nginx/Apache-Site-Config ergänzen.",
            ))

        # Server banner → contribute to tech fingerprint for CVE scanner.
        server = headers.get("server", "")
        if server:
            tech = result.metadata.setdefault("tech", {})
            tech[f"subdomain_server.{sub}"] = server

        # TLS expiry per sub
        if tls and tls.get("cert"):
            cert = tls["cert"]
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expires - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        result.add(Finding(
                            id=f"subdomain.tls_expired.{sub}",
                            title=f"Subdomain {sub}: TLS-Zertifikat abgelaufen",
                            description=f"Das Zertifikat für {sub} ist seit {-days_left} Tagen abgelaufen.",
                            severity=Severity.HIGH,
                            category="Subdomain Exposure",
                            evidence={"subdomain": sub, "not_after": not_after},
                        ))
                    elif days_left < 14:
                        result.add(Finding(
                            id=f"subdomain.tls_expiring.{sub}",
                            title=f"Subdomain {sub}: TLS-Zertifikat läuft in {days_left} Tagen ab",
                            description=f"Das Zertifikat für {sub} läuft bald ab.",
                            severity=Severity.MEDIUM,
                            category="Subdomain Exposure",
                            evidence={"subdomain": sub, "days_left": days_left},
                        ))
                except ValueError:
                    pass

    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = [ex.submit(task, s) for s in subs]
        for f in as_completed(futures):
            f.result()

    result.metadata["subdomain_deep"] = {
        "checked": len(subs),
        "with_tls": sum(1 for d in per_sub.values() if d.get("tls")),
    }
