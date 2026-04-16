"""DNS rebinding check — flag domains resolving to private IPs.

If a subdomain resolves to a private/internal IP (10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16), it's either:
- An internal service accidentally published in public DNS (HIGH).
- A DNS rebinding vector that can be exploited to reach internal services
  from a victim's browser (CRITICAL in enterprise/healthcare context).
"""
from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import dns.exception
import dns.resolver

from app.scanners.base import Finding, ScanResult, Severity

PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETWORKS)


def _resolve_a(hostname: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(hostname, "A", lifetime=3.0)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def check_dns_rebinding(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Step-2: DNS-Rebinding-Check", 97)

    hostnames = set()
    hostnames.add(domain)
    hostnames.update(result.metadata.get("subdomains") or [])
    hostnames.update((result.metadata.get("subdomain_walk") or {}).get("results", {}).keys())
    san_expansion = result.metadata.get("tls_san_expansion") or {}
    hostnames.update(san_expansion.get("new_domains") or [])

    if not hostnames:
        return

    private_hits: list[dict] = []

    def task(hostname: str) -> None:
        ips = _resolve_a(hostname)
        for ip in ips:
            if _is_private(ip):
                private_hits.append({"hostname": hostname, "ip": ip})

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(task, h) for h in list(hostnames)[:100]]
        for f in as_completed(futures):
            f.result()

    if not private_hits:
        return

    result.metadata["dns_rebinding"] = private_hits

    result.add(Finding(
        id="step2.dns_rebinding",
        title=f"{len(private_hits)} Hostname(s) lösen zu privaten IP-Adressen auf",
        description=(
            "Die folgenden öffentlich auflösbaren Hostnamen zeigen auf private/interne "
            "IP-Adressen. Das ist ein Sicherheitsrisiko:\n"
            "1. Interner Dienst versehentlich in öffentlichem DNS publiziert.\n"
            "2. DNS-Rebinding-Angriff: Ein Angreifer nutzt die Domain, um den "
            "Browser des Opfers zum Zugriff auf interne Ressourcen zu verleiten.\n"
            "3. Informationsleck: Angreifer kennt die interne Netzstruktur."
        ),
        severity=Severity.HIGH,
        category="Step-2 Analyse",
        evidence={"hits": private_hits[:20]},
        recommendation="DNS-Records bereinigen: private IPs aus öffentlichem DNS entfernen.",
    ))
