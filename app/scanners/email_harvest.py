"""Passively harvest e-mail addresses from a domain's public pages.

MVZ websites almost always expose at least one e-mail address in the
impressum/contact page (GDPR requirement). Finding these passively is a
useful OSINT step because those addresses are prime phishing targets.

When HIBP is configured (paid), we also run each harvested address through
the breached-account endpoint.
"""
from __future__ import annotations

import re
from typing import Callable

import httpx

from app.integrations import hibp
from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CANDIDATE_PATHS = (
    "/",
    "/impressum",
    "/impressum/",
    "/kontakt",
    "/kontakt/",
    "/datenschutz",
    "/datenschutz/",
    "/legal",
    "/imprint",
)


def _fetch(client: httpx.Client, url: str) -> str:
    try:
        r = client.get(url)
        if r.status_code == 200 and "text/html" in r.headers.get("content-type", "").lower():
            return r.text[:200_000]
    except httpx.HTTPError:
        pass
    return ""


def harvest_and_check(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("E-Mail-Harvest + HIBP", 96)

    found: set[str] = set()
    with httpx.Client(
        timeout=8.0,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        for path in CANDIDATE_PATHS:
            text = _fetch(client, f"https://{domain}{path}")
            if not text:
                continue
            for m in EMAIL_RE.findall(text):
                addr = m.lower().strip(".")
                # Filter out obvious garbage (image hashes, typos, etc.)
                if addr.endswith((".png", ".jpg", ".gif", ".webp", ".svg")):
                    continue
                # Only keep addresses ending in the target domain or a direct subdomain
                local, _, dom = addr.partition("@")
                if dom.endswith(domain):
                    found.add(addr)

    if not found:
        return

    result.metadata["harvested_emails"] = sorted(found)

    result.add(Finding(
        id="osint.emails_harvested",
        title=f"{len(found)} E-Mail-Adresse(n) öffentlich auffindbar",
        description=(
            "Die folgenden E-Mail-Adressen wurden auf öffentlich erreichbaren Seiten "
            "(Impressum/Kontakt/Datenschutz) gefunden. Diese Adressen sind bevorzugte "
            "Ziele für Phishing und Credential-Stuffing."
        ),
        severity=Severity.INFO,
        category="OSINT",
        evidence={"emails": sorted(found)},
        recommendation=(
            "Nutze pro sensibler Rolle eigene Mailaccounts mit MFA, aktiviere DMARC mit "
            "p=quarantine oder p=reject, und schule Mitarbeitende gezielt auf Phishing-Szenarien."
        ),
    ))

    # If HIBP is enabled, check each address.
    if hibp.is_enabled():
        any_breached = False
        breaches_per_email: dict[str, list[str]] = {}
        for email in sorted(found):
            breaches = hibp.breached_account(email)
            hibp.rate_limit_sleep()
            if breaches is None:
                continue
            if breaches:
                any_breached = True
                breaches_per_email[email] = [b.get("Name", "") for b in breaches]

        if breaches_per_email:
            result.metadata["hibp_breaches"] = breaches_per_email
            total = sum(len(v) for v in breaches_per_email.values())
            result.add(Finding(
                id="osint.hibp_breached_accounts",
                title=f"{len(breaches_per_email)} E-Mail-Adresse(n) in {total} Daten-Leaks gefunden",
                description=(
                    "Have I Been Pwned verzeichnet bekannte Daten-Leaks, in denen diese "
                    "öffentlich auffindbaren E-Mail-Adressen vorkommen. Passwörter aus "
                    "solchen Leaks werden für Credential-Stuffing-Angriffe gegen "
                    "MVZ-Konten missbraucht."
                ),
                severity=Severity.HIGH,
                category="Credential Leak",
                evidence=breaches_per_email,
                recommendation=(
                    "Betroffene Konten: Passwörter sofort ändern, MFA erzwingen, in "
                    "Exchange/M365 auf ungewöhnliche Anmeldungen und Forwarding-Regeln prüfen."
                ),
                kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (Credentials)",
            ))
        elif any_breached is False and breaches_per_email == {}:
            result.add(Finding(
                id="osint.hibp_no_breaches",
                title="Keine Leaks für die gefundenen E-Mail-Adressen bekannt",
                description="HIBP hat zu keiner der öffentlich gefundenen Adressen Einträge.",
                severity=Severity.INFO,
                category="Credential Leak",
            ))
