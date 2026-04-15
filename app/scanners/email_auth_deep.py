"""Deeper e-mail security checks: DKIM selector brute, MTA-STS, TLS-RPT.

This runs *after* the basic SPF/DMARC check. It does three things:

1. Brute-force common DKIM selectors to confirm DKIM is actually configured.
   Public API servers don't announce which selectors are in use, so we try a
   curated list of defaults used by M365/Google Workspace/Mailchimp/etc.
2. Check MTA-STS policy: both DNS record and HTTPS policy file.
3. Check TLS-RPT record for e-mail transport failure reporting.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import dns.exception
import dns.resolver
import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

# Commonly used DKIM selectors — if any returns a TXT, we know DKIM is configured.
DKIM_SELECTORS = (
    "default", "mail", "dkim",
    "google", "selector1", "selector2",  # M365
    "k1", "k2", "k3",                      # Mailchimp / SendGrid
    "mandrill", "mxvault",
    "smtpapi",                              # SendGrid
    "scph1118",                             # Campaign Monitor
    "s1", "s2",                             # generic numeric
    "everlytickey1", "everlytickey2",
    "dkim1", "dkim2",
    "m1", "m2",
)


def _resolve_txt(name: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    resolver.timeout = 3.0
    try:
        answers = resolver.resolve(name, "TXT", raise_on_no_answer=False)
        return [r.to_text().strip('"') for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def _probe_selector(domain: str, selector: str) -> tuple[str, list[str]]:
    name = f"{selector}._domainkey.{domain}"
    return selector, _resolve_txt(name)


def _check_dkim(domain: str, result: ScanResult) -> None:
    hits: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_probe_selector, domain, s) for s in DKIM_SELECTORS]
        for f in as_completed(futures):
            selector, txt = f.result()
            matching = [t for t in txt if "p=" in t.lower() or "v=dkim" in t.lower()]
            if matching:
                hits[selector] = matching

    result.metadata.setdefault("email_auth", {})["dkim_selectors_found"] = list(hits.keys())

    if not hits:
        result.add(Finding(
            id="email.dkim_missing",
            title="Kein DKIM-Eintrag gefunden (getestete Selektoren)",
            description=(
                "Unter den 18 gängigsten DKIM-Selektoren wurde kein Eintrag gefunden. "
                "Entweder nutzt der Absender einen seltenen Selektor, oder DKIM ist gar "
                "nicht aktiv — ohne DKIM wirkt DMARC nicht zuverlässig."
            ),
            severity=Severity.HIGH,
            category="E-Mail",
            recommendation=(
                "DKIM in M365/Google Workspace/dem Mail-Provider aktivieren, "
                "Signatur-Validierung in einer Testmail prüfen."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (E-Mail-Sicherheit)",
        ))


def _check_mta_sts(domain: str, result: ScanResult) -> None:
    txt = _resolve_txt(f"_mta-sts.{domain}")
    has_record = any(t.lower().startswith("v=stsv1") for t in txt)

    policy_present = False
    policy_body = ""
    if has_record:
        try:
            with httpx.Client(timeout=6.0, headers={"User-Agent": USER_AGENT}, verify=True) as client:
                r = client.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
                if r.status_code == 200 and "version" in r.text.lower():
                    policy_present = True
                    policy_body = r.text[:2000]
        except httpx.HTTPError:
            pass

    result.metadata.setdefault("email_auth", {})["mta_sts"] = {
        "dns_record": has_record,
        "policy_file": policy_present,
    }

    if not has_record:
        result.add(Finding(
            id="email.mta_sts_missing",
            title="MTA-STS nicht konfiguriert",
            description=(
                "MTA-STS zwingt sendende Mailserver zu TLS — ohne diesen Standard "
                "können E-Mails im Transit weiterhin unverschlüsselt ankommen (STARTTLS-Downgrade)."
            ),
            severity=Severity.MEDIUM,
            category="E-Mail",
            recommendation=(
                "DNS-TXT _mta-sts.{domain} mit v=STSv1 + id=... setzen und unter "
                "https://mta-sts.{domain}/.well-known/mta-sts.txt eine Policy-Datei hinterlegen."
            ),
        ))
    elif has_record and not policy_present:
        result.add(Finding(
            id="email.mta_sts_policy_missing",
            title="MTA-STS DNS-Eintrag vorhanden, Policy-Datei fehlt",
            description=(
                "Der _mta-sts TXT-Record verweist auf eine Policy, die HTTP(S)-Datei ist aber nicht erreichbar."
            ),
            severity=Severity.MEDIUM,
            category="E-Mail",
            recommendation="Policy-Datei unter https://mta-sts.<domain>/.well-known/mta-sts.txt hinterlegen.",
        ))


def _check_tls_rpt(domain: str, result: ScanResult) -> None:
    txt = _resolve_txt(f"_smtp._tls.{domain}")
    has_record = any(t.lower().startswith("v=tlsrptv1") for t in txt)
    result.metadata.setdefault("email_auth", {})["tls_rpt"] = has_record
    if not has_record:
        result.add(Finding(
            id="email.tls_rpt_missing",
            title="TLS-RPT nicht konfiguriert",
            description=(
                "TLS-RPT liefert Reports über fehlgeschlagene TLS-Verbindungen beim "
                "E-Mail-Transport — ohne diesen Record merkt niemand, wenn ein Angreifer "
                "TLS-Downgrade versucht."
            ),
            severity=Severity.LOW,
            category="E-Mail",
            recommendation='TXT-Record _smtp._tls.<domain> mit z.B. "v=TLSRPTv1; rua=mailto:tls-rpt@<domain>" setzen.',
        ))


def check_email_deep(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("E-Mail Deep (DKIM/MTA-STS/TLS-RPT)", 30)
    _check_dkim(domain, result)
    _check_mta_sts(domain, result)
    _check_tls_rpt(domain, result)
