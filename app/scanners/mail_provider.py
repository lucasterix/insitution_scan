"""Detect the mail provider behind a domain.

Healthcare IT departments need to know *where* their mail physically lives
because the provider dictates which security features are available:

- Microsoft 365 (Exchange Online): MX `*.mail.protection.outlook.com`
- Google Workspace: MX `aspmx.l.google.com` + alternatives
- KIM-Providers (gematik-trusted)
- Self-hosted Exchange / Postfix / Kerio

For each provider we report what features are likely/required (DKIM default
selector, MFA support, etc.) and emit warnings when the config contradicts
expected state.
"""
from __future__ import annotations

from typing import Callable

import dns.exception
import dns.resolver

from app.scanners.base import Finding, ScanResult, Severity


def _resolve(name: str, rtype: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    resolver.timeout = 3.0
    try:
        answers = resolver.resolve(name, rtype, raise_on_no_answer=False)
        return [r.to_text() for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


# Each entry: (provider_key, provider_label, list of MX substring indicators, list of TXT substring indicators)
PROVIDERS: list[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = [
    ("m365", "Microsoft 365 / Exchange Online",
     ("mail.protection.outlook.com",),
     ("ms=ms", "v=spf1 include:spf.protection.outlook.com")),
    ("google", "Google Workspace",
     ("aspmx.l.google.com", "aspmx2.googlemail.com", "aspmx3.googlemail.com"),
     ("google-site-verification", "v=spf1 include:_spf.google.com")),
    ("one_com", "one.com",
     ("mx.one.com",), ()),
    ("ionos", "IONOS / 1&1",
     ("mx00.ionos", "mx01.ionos", "mx00.1and1", "mx00.kundenserver"),
     ()),
    ("strato", "STRATO",
     ("mx.strato", "mx0.strato"),
     ()),
    ("hetzner", "Hetzner Mailserver",
     ("mailgate.hetzner.com", "mail.your-server.de"),
     ()),
    ("gmx", "GMX / Mail.de",
     ("gmx.net",),
     ()),
    ("web_de", "WEB.DE",
     ("mx-ha.web.de",),
     ()),
    ("proton", "Proton Mail",
     ("mail.protonmail.ch", "mailsec.protonmail.ch"),
     ("protonmail-verification",)),
    ("fastmail", "Fastmail",
     ("messagingengine.com",),
     ()),
    ("mailbox_org", "mailbox.org",
     ("mailbox.org",),
     ()),
    ("posteo", "Posteo",
     ("posteo.de",),
     ()),
    ("cgm_kim", "CGM KIM-Provider",
     ("kim.compugroup",),
     ()),
    ("arvato_kim", "Arvato / akquinet KIM",
     ("akquinet.kim", "arvato-systems.kim"),
     ()),
    ("medatixx_kim", "medatixx KIM",
     ("medatixx.kim",),
     ()),
    ("telekom_kim", "Telekom Healthcare KIM",
     ("telekom-healthcare.com", "t-systems.kim"),
     ()),
]


def check_mail_provider(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Mail-Provider-Detection", 28)

    mx_records = _resolve(domain, "MX")
    txt_records = _resolve(domain, "TXT")

    mx_joined = " ".join(mx_records).lower()
    txt_joined = " ".join(txt_records).lower()

    detected: list[dict] = []
    for key, label, mx_tags, txt_tags in PROVIDERS:
        if any(tag in mx_joined for tag in mx_tags) or any(tag in txt_joined for tag in txt_tags):
            detected.append({"key": key, "label": label})

    # Microsoft-specific DNS hints: autodiscover + msoid + lyncdiscover CNAMEs
    autodiscover_cname = _resolve(f"autodiscover.{domain}", "CNAME")
    if autodiscover_cname and any("outlook.com" in r.lower() for r in autodiscover_cname):
        if not any(d["key"] == "m365" for d in detected):
            detected.append({"key": "m365", "label": "Microsoft 365 / Exchange Online"})

    if not detected:
        return

    result.metadata["mail_provider"] = detected

    provider_labels = ", ".join(sorted({d["label"] for d in detected}))
    result.add(Finding(
        id="mail.provider_detected",
        title=f"Mail-Provider: {provider_labels}",
        description=(
            f"Die Domain nutzt {provider_labels}. Das wirkt sich direkt auf die "
            "verfügbaren E-Mail-Sicherheitsfeatures aus (DKIM-Selektoren, MFA, "
            "Anti-Phishing, Conditional Access)."
        ),
        severity=Severity.INFO,
        category="E-Mail",
        evidence={"detected": detected, "mx": mx_records[:10], "txt_snippet": txt_joined[:500]},
    ))

    # Provider-specific expectations.
    detected_keys = {d["key"] for d in detected}

    if "m365" in detected_keys:
        # M365 standard DKIM selectors are selector1/selector2. The generic DKIM brute
        # run by email_auth_deep already tries these, so we just emit an info finding
        # with actionable advice.
        result.add(Finding(
            id="mail.m365_hardening_advice",
            title="Microsoft 365 erkannt — dedizierte Härtung empfohlen",
            description=(
                "Stellen Sie sicher: DKIM auf selector1 + selector2 aktiv, DMARC p=reject, "
                "Conditional Access mit MFA für alle Mailboxen, Audit-Log aktiv, "
                "Anti-Phish-Policies mit Impersonation Protection, Forwarding nur explizit, "
                "Litigation-Hold für Pflichtaufbewahrung."
            ),
            severity=Severity.INFO,
            category="E-Mail",
            recommendation="https://learn.microsoft.com/microsoft-365/security/office-365-security/",
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (E-Mail-Sicherheit)",
        ))

    if "google" in detected_keys:
        result.add(Finding(
            id="mail.google_hardening_advice",
            title="Google Workspace erkannt — dedizierte Härtung empfohlen",
            description=(
                "Stellen Sie sicher: DKIM-Schlüssel 2048 bit aktiv, DMARC p=reject, "
                "2-Schritt-Verifizierung erzwingen, Kontext-bewusster Zugriff, "
                "S/MIME für ausgehende Mails an sensible Adressaten, Zero-Day-Anhangs-"
                "Schutz in Advanced Protection."
            ),
            severity=Severity.INFO,
            category="E-Mail",
        ))

    if any(k in detected_keys for k in ("cgm_kim", "arvato_kim", "medatixx_kim", "telekom_kim")):
        result.add(Finding(
            id="mail.kim_provider_detected",
            title="KIM-Provider erkannt",
            description=(
                "Es wurden Hinweise auf einen gematik-zertifizierten KIM-Provider gefunden. "
                "Das ist ein positives Signal für die TI-Anbindung."
            ),
            severity=Severity.INFO,
            category="Healthcare",
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 4 & 5 (TI)",
        ))
