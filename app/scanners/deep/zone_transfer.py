"""DNS zone transfer (AXFR) probe.

A misconfigured authoritative nameserver that answers AXFR queries hands out
the entire zone — every subdomain, every A/AAAA/MX record, every TXT.
This is almost always blocked, but when it isn't, it is a CRITICAL finding.
"""
from __future__ import annotations

from typing import Callable

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from app.scanners.base import Finding, ScanResult, Severity


def _get_nameservers(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=4.0)
        return [str(r).rstrip(".") for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def _try_axfr(ns: str, domain: str) -> int | None:
    """Return number of records on success, None on refused/failure."""
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, lifetime=8.0))
        return len(zone.nodes)
    except Exception:  # noqa: BLE001 — any failure = AXFR refused
        return None


def check_zone_transfer(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("DNS Zone Transfer (AXFR)", 56)

    nameservers = _get_nameservers(domain)
    if not nameservers:
        return

    hits: list[dict] = []
    for ns in nameservers:
        count = _try_axfr(ns, domain)
        if count is not None:
            hits.append({"nameserver": ns, "records": count})

    result.metadata["axfr"] = {
        "nameservers_tried": nameservers,
        "transfer_allowed": hits,
    }

    if hits:
        result.add(Finding(
            id="deep.axfr_allowed",
            title=f"AXFR Zone Transfer erlaubt auf {len(hits)} Nameserver(n)",
            description=(
                "Mindestens ein autoritativer Nameserver liefert die komplette Zone "
                "per AXFR aus. Damit sind alle Subdomains, IPs und internen Record-Typen "
                "öffentlich lesbar. Das ist de facto ein kompletter Infrastruktur-Leak."
            ),
            severity=Severity.CRITICAL,
            category="Deep Scan",
            evidence={"hits": hits},
            recommendation=(
                "Beim DNS-Provider AXFR auf IP-Whitelist beschränken oder vollständig abschalten. "
                "Nur Secondary-NS sollten AXFR-Berechtigung haben."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 3 (DNS-Härtung)",
        ))
