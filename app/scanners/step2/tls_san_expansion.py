"""TLS SAN expansion — discover hidden domains from certificate SANs.

The TLS certificate's Subject Alternative Names often list domains/subdomains
that the operator didn't expose in DNS or HTML. The step-1 TLS check already
captured the cert; here we extract SANs and flag any that are NOT already in
our subdomain list — those are "hidden" attack surface.
"""
from __future__ import annotations

import re
import socket
import ssl
from typing import Callable

from app.scanners.base import Finding, ScanResult, Severity


def _get_sans(domain: str) -> list[str]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except (socket.timeout, ssl.SSLError, OSError):
        return []
    sans: list[str] = []
    for typ, val in cert.get("subjectAltName") or []:
        if typ == "DNS":
            name = val.lower().strip()
            if name and not name.startswith("*"):
                sans.append(name)
    return sans


def check_tls_san_expansion(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Step-2: TLS SAN Expansion", 97)

    sans = _get_sans(domain)
    if not sans:
        return

    known_subs = set(result.metadata.get("subdomains") or [])
    known_subs.add(domain)
    walk_results = (result.metadata.get("subdomain_walk") or {}).get("results") or {}
    known_subs.update(walk_results.keys())

    new_domains = sorted(set(sans) - known_subs)
    if not new_domains:
        return

    result.metadata["tls_san_expansion"] = {
        "total_sans": len(sans),
        "new_domains": new_domains,
    }

    result.add(Finding(
        id="step2.tls_san_new_domains",
        title=f"TLS-Zertifikat enthält {len(new_domains)} bisher unbekannte Domain(s)",
        description=(
            "Das TLS-Zertifikat listet Domains in den Subject Alternative Names, die "
            "weder in unserer Subdomain-Enumeration noch im DNS aufgetaucht sind. "
            "Diese Domains teilen sich die gleiche TLS-Infrastruktur und könnten auf "
            "vergessene oder interne Dienste hinweisen."
        ),
        severity=Severity.MEDIUM,
        category="Step-2 Analyse",
        evidence={"new_domains": new_domains[:30], "all_sans": sans[:50]},
        recommendation="Jede dieser Domains manuell prüfen — sind sie alle gewollt öffentlich? Laufen sie noch?",
    ))
