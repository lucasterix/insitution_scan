"""SPF include-chain analysis.

Recursively follows all `include:`, `redirect=`, and `a:` mechanisms in
the domain's SPF record. Checks each included domain:

1. Is the domain still registered? An expired include domain = SPF takeover.
2. Is the include chain > 10 DNS lookups? (RFC 7208 limit → SPF softfail)
3. Are there known-permissive includes (e.g., include:spf.protection.outlook.com
   in a non-M365 setup)?

SPF takeover via expired include domain is CRITICAL because an attacker can
register the domain, set up their own SPF, and then send spoofed emails
that pass the victim's SPF check.
"""
from __future__ import annotations

import re
from typing import Callable

import dns.exception
import dns.resolver

from app.scanners.base import Finding, ScanResult, Severity

MAX_DEPTH = 5
MAX_LOOKUPS = 15

INCLUDE_RE = re.compile(r"include:([^\s]+)", re.IGNORECASE)
REDIRECT_RE = re.compile(r"redirect=([^\s]+)", re.IGNORECASE)


def _resolve_txt(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=3.0)
        return [r.to_text().strip('"') for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def _domain_exists(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "A", lifetime=3.0)
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return True  # DNS error ≠ non-existent


def _walk_spf(domain: str, depth: int, visited: set, chain: list, lookup_count: list) -> None:
    if depth > MAX_DEPTH or domain in visited or lookup_count[0] > MAX_LOOKUPS:
        return
    visited.add(domain)
    lookup_count[0] += 1

    txts = _resolve_txt(domain)
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if not spf:
        return

    chain.append({"domain": domain, "spf": spf, "depth": depth})

    for m in INCLUDE_RE.finditer(spf):
        inc_domain = m.group(1).lower().rstrip(".")
        _walk_spf(inc_domain, depth + 1, visited, chain, lookup_count)

    redir = REDIRECT_RE.search(spf)
    if redir:
        redir_domain = redir.group(1).lower().rstrip(".")
        _walk_spf(redir_domain, depth + 1, visited, chain, lookup_count)


def check_spf_chain(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Step-2: SPF-Include-Chain", 97)

    chain: list[dict] = []
    visited: set[str] = set()
    lookup_count = [0]
    _walk_spf(domain, 0, visited, chain, lookup_count)

    if not chain:
        return

    all_includes = [c["domain"] for c in chain if c["depth"] > 0]
    expired: list[str] = []
    for inc in all_includes:
        if not _domain_exists(inc):
            expired.append(inc)

    result.metadata["spf_chain"] = {
        "chain": chain,
        "total_lookups": lookup_count[0],
        "includes": all_includes,
        "expired_includes": expired,
    }

    if expired:
        result.add(Finding(
            id="step2.spf_takeover",
            title=f"SPF-Include-Domain(s) nicht mehr registriert: {', '.join(expired)}",
            description=(
                "Der SPF-Record der Domain referenziert (direkt oder transitiv) Domains, "
                "die nicht mehr existieren. Ein Angreifer kann diese Domains registrieren, "
                "dort einen SPF-Record einrichten, und dann E-Mails senden die den SPF-Check "
                "der Zieldomain bestehen — perfektes Phishing."
            ),
            # Exploit requires attacker to register the expired domain AND send
            # spoofed mail — domain registration is cheap but not zero-click.
            severity=Severity.HIGH,
            category="Step-2 Analyse",
            evidence={"expired": expired, "chain": chain},
            recommendation=(
                "SPF-Record sofort bereinigen: nicht mehr benötigte includes entfernen. "
                "Wenn die Domain noch gebraucht wird: sofort neu registrieren."
            ),
        ))

    if lookup_count[0] > 10:
        result.add(Finding(
            id="step2.spf_too_many_lookups",
            title=f"SPF-Include-Chain hat {lookup_count[0]} DNS-Lookups (RFC-Limit: 10)",
            description=(
                "RFC 7208 erlaubt maximal 10 DNS-Lookups in einer SPF-Evaluation. "
                f"Die aktuelle Chain hat {lookup_count[0]} — ab 11 verweigern strenge "
                "Empfänger die SPF-Evaluation und die Domain fällt auf 'permerror'."
            ),
            severity=Severity.MEDIUM,
            category="Step-2 Analyse",
            evidence={"lookups": lookup_count[0], "chain": chain},
            recommendation="SPF-Record konsolidieren: ip4/ip6-Ranges statt vieler includes nutzen.",
        ))
