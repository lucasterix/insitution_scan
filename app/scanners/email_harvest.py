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

from app.integrations import leakcheck
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
    step("E-Mail-Harvest + Leak-Check", 96)

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

    # If LeakCheck is enabled, check each address.
    if not leakcheck.is_enabled():
        return

    breaches_per_email: dict[str, dict] = {}
    clean_count = 0

    for email in sorted(found):
        data = leakcheck.check_email(email)
        leakcheck.rate_limit_sleep()
        if data is None:
            continue
        found_count = int(data.get("found", 0) or 0)
        if found_count > 0:
            breaches_per_email[email] = {
                "count": found_count,
                "fields": data.get("fields") or [],
                "sources": [
                    {"name": s.get("name"), "date": s.get("date")}
                    for s in (data.get("sources") or [])[:30]
                ],
            }
        else:
            clean_count += 1

    if breaches_per_email:
        result.metadata["leakcheck_breaches"] = breaches_per_email
        total = sum(v["count"] for v in breaches_per_email.values())

        # Highest severity is CRITICAL if any breach leaked passwords *and* personal data.
        worst_fields = set()
        for v in breaches_per_email.values():
            for f in v.get("fields") or []:
                worst_fields.add(f.lower())
        has_password = "password" in worst_fields
        has_pii = any(f in worst_fields for f in ("ssn", "dob", "address", "phone", "first_name", "last_name"))

        if has_password and has_pii:
            sev = Severity.CRITICAL
        elif has_password:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM

        result.add(Finding(
            id="osint.leakcheck_breached_accounts",
            title=f"{len(breaches_per_email)} E-Mail-Adresse(n) in {total} Daten-Leaks gefunden",
            description=(
                "LeakCheck.io verzeichnet bekannte Daten-Leaks, in denen diese öffentlich "
                "auffindbaren E-Mail-Adressen vorkommen. Passwörter und Stammdaten aus "
                "solchen Leaks werden für Credential-Stuffing- und Phishing-Angriffe "
                "gegen MVZ-Konten missbraucht."
                f"\n\nBetroffene Datenkategorien: {', '.join(sorted(worst_fields)) or 'unklar'}."
            ),
            severity=sev,
            category="Credential Leak",
            evidence=breaches_per_email,
            recommendation=(
                "Betroffene Konten: Passwörter sofort ändern, MFA erzwingen, in "
                "Exchange/M365 auf ungewöhnliche Anmeldungen und Forwarding-Regeln prüfen. "
                "Mitarbeitende über Risiko von wiederverwendeten Passwörtern schulen."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (Credentials)",
        ))
    elif clean_count > 0:
        result.add(Finding(
            id="osint.leakcheck_no_breaches",
            title="Keine Leaks für die gefundenen E-Mail-Adressen bekannt",
            description="LeakCheck hat zu keiner der öffentlich gefundenen Adressen Einträge.",
            severity=Severity.INFO,
            category="Credential Leak",
        ))
