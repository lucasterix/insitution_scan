"""OSINT & Reconnaissance scanner (white-hat, passive checks only)."""
from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Callable

import dns.resolver
import httpx
import tldextract

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS fehlt",
        "Strict-Transport-Security erzwingt HTTPS beim Browser — Schutz vor Downgrade-Angriffen.",
        Severity.MEDIUM,
    ),
    "content-security-policy": (
        "Content-Security-Policy fehlt",
        "CSP reduziert XSS-Risiken erheblich.",
        Severity.MEDIUM,
    ),
    "x-frame-options": (
        "X-Frame-Options fehlt",
        "Schutz vor Clickjacking (bzw. CSP frame-ancestors).",
        Severity.LOW,
    ),
    "x-content-type-options": (
        "X-Content-Type-Options fehlt",
        "Verhindert MIME-Type Sniffing.",
        Severity.LOW,
    ),
    "referrer-policy": (
        "Referrer-Policy fehlt",
        "Kontrolliert welche Referrer-Informationen beim Navigieren gesendet werden.",
        Severity.INFO,
    ),
    "permissions-policy": (
        "Permissions-Policy fehlt",
        "Regelt welche Browser-Features die Seite nutzen darf.",
        Severity.INFO,
    ),
}


def _normalize_domain(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/", 1)[0]
    return value


def _resolve_records(domain: str, rtype: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 5.0
    try:
        answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
        return [r.to_text().strip('"') for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def check_dns(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("DNS Records", 10)
    a = _resolve_records(domain, "A")
    aaaa = _resolve_records(domain, "AAAA")
    mx = _resolve_records(domain, "MX")
    ns = _resolve_records(domain, "NS")
    caa = _resolve_records(domain, "CAA")

    result.metadata["dns"] = {"A": a, "AAAA": aaaa, "MX": mx, "NS": ns, "CAA": caa}

    if not a and not aaaa:
        result.add(Finding(
            id="dns.no_records",
            title="Keine A/AAAA Records gefunden",
            description=f"Für {domain} konnten keine A- oder AAAA-Records aufgelöst werden.",
            severity=Severity.HIGH,
            category="DNS",
            evidence={"domain": domain},
        ))
    if not caa:
        result.add(Finding(
            id="dns.caa_missing",
            title="CAA Record fehlt",
            description="CAA Records schränken ein, welche Zertifizierungsstellen Zertifikate ausstellen dürfen.",
            severity=Severity.LOW,
            category="DNS",
            recommendation='Setze einen CAA Record, z.B. "0 issue \\"letsencrypt.org\\"".',
        ))


def check_email_auth(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("E-Mail Authentifizierung (SPF/DKIM/DMARC)", 25)
    txt = _resolve_records(domain, "TXT")
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    dmarc_records = _resolve_records(f"_dmarc.{domain}", "TXT")
    dmarc = next((t for t in dmarc_records if t.lower().startswith("v=dmarc1")), None)

    result.metadata["email_auth"] = {"spf": spf, "dmarc": dmarc}

    if not spf:
        result.add(Finding(
            id="email.spf_missing",
            title="SPF Record fehlt",
            description="Ohne SPF können Angreifer leichter E-Mails im Namen der Domain fälschen.",
            severity=Severity.HIGH,
            category="E-Mail",
            recommendation="Setze einen SPF-TXT-Record mit allen legitimen Absende-Servern.",
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (E-Mail-Sicherheit)",
        ))
    elif spf.endswith("+all") or " +all" in spf:
        result.add(Finding(
            id="email.spf_too_permissive",
            title="SPF Record zu permissiv (+all)",
            description="+all erlaubt jedem Server, E-Mails für diese Domain zu senden.",
            severity=Severity.CRITICAL,
            category="E-Mail",
            evidence={"spf": spf},
            recommendation="Ersetze +all durch -all oder ~all.",
        ))

    if not dmarc:
        result.add(Finding(
            id="email.dmarc_missing",
            title="DMARC Record fehlt",
            description="DMARC ist Voraussetzung für wirksamen Phishing-Schutz.",
            severity=Severity.HIGH,
            category="E-Mail",
            recommendation='Setze _dmarc.<domain> TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>".',
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2",
        ))
    else:
        policy = re.search(r"p=(\w+)", dmarc)
        if policy and policy.group(1).lower() == "none":
            result.add(Finding(
                id="email.dmarc_policy_none",
                title="DMARC Policy auf p=none",
                description="p=none bedeutet nur Beobachtung — keine aktive Abwehr von Spoofing.",
                severity=Severity.MEDIUM,
                category="E-Mail",
                evidence={"dmarc": dmarc},
                recommendation="Nach Monitoring-Phase auf p=quarantine oder p=reject erhöhen.",
            ))


def check_http(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("HTTP(S) & Security Headers", 45)
    headers_info: dict = {}
    with httpx.Client(
        timeout=10.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}, verify=True
    ) as client:
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                r = client.get(url)
                headers_info[scheme] = {
                    "status": r.status_code,
                    "final_url": str(r.url),
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                }
            except httpx.HTTPError as e:
                headers_info[scheme] = {"error": str(e)}

    result.metadata["http"] = headers_info

    https = headers_info.get("https", {})
    http = headers_info.get("http", {})

    if "error" in https:
        result.add(Finding(
            id="http.https_unreachable",
            title="HTTPS nicht erreichbar",
            description=f"https://{domain} konnte nicht geladen werden.",
            severity=Severity.HIGH,
            category="Web",
            evidence={"error": https["error"]},
        ))
        return

    if "error" not in http and not str(http.get("final_url", "")).startswith("https://"):
        result.add(Finding(
            id="http.no_https_redirect",
            title="HTTP wird nicht auf HTTPS umgeleitet",
            description="Aufrufe über http://... landen nicht automatisch auf https://.",
            severity=Severity.MEDIUM,
            category="Web",
            recommendation="301-Redirect von HTTP auf HTTPS konfigurieren.",
        ))

    hdrs = https.get("headers", {})
    for key, (title, desc, sev) in SECURITY_HEADERS.items():
        if key not in hdrs:
            result.add(Finding(
                id=f"http.header.{key}",
                title=title,
                description=desc,
                severity=sev,
                category="Security Headers",
                recommendation=f"Setze den Response-Header {key}.",
            ))

    server = hdrs.get("server")
    x_powered = hdrs.get("x-powered-by")
    if server:
        result.metadata.setdefault("tech", {})["server"] = server
    if x_powered:
        result.metadata.setdefault("tech", {})["x-powered-by"] = x_powered
        result.add(Finding(
            id="http.header.x_powered_by",
            title="X-Powered-By Header verrät Software-Stack",
            description=f"Der Server sendet X-Powered-By: {x_powered}. Das erleichtert Angreifern die Recherche.",
            severity=Severity.LOW,
            category="Security Headers",
            recommendation="X-Powered-By Header entfernen.",
        ))


def check_tls(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("TLS-Zertifikat", 60)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
    except (socket.timeout, ssl.SSLError, OSError) as e:
        result.add(Finding(
            id="tls.connect_failed",
            title="TLS-Verbindung fehlgeschlagen",
            description=f"Konnte keine TLS-Verbindung zu {domain}:443 aufbauen.",
            severity=Severity.HIGH,
            category="TLS",
            evidence={"error": str(e)},
        ))
        return

    not_after = cert.get("notAfter")
    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    result.metadata["tls"] = {
        "version": version,
        "issuer": issuer,
        "subject": subject,
        "not_after": not_after,
    }

    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            if days_left < 0:
                result.add(Finding(
                    id="tls.expired",
                    title="TLS-Zertifikat abgelaufen",
                    description=f"Das Zertifikat ist seit {-days_left} Tagen abgelaufen.",
                    severity=Severity.CRITICAL,
                    category="TLS",
                ))
            elif days_left < 14:
                result.add(Finding(
                    id="tls.expires_soon",
                    title="TLS-Zertifikat läuft bald ab",
                    description=f"Das Zertifikat läuft in {days_left} Tagen ab.",
                    severity=Severity.HIGH,
                    category="TLS",
                ))
        except ValueError:
            pass

    if version and version in ("TLSv1", "TLSv1.1", "SSLv3"):
        result.add(Finding(
            id="tls.legacy_protocol",
            title=f"Legacy TLS-Protokoll {version}",
            description="Veraltete TLS-Versionen sind unsicher und sollten deaktiviert werden.",
            severity=Severity.HIGH,
            category="TLS",
        ))


def check_subdomains(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Subdomain-Enumeration (crt.sh)", 75)
    ext = tldextract.extract(domain)
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain
    url = f"https://crt.sh/?q=%25.{registered}&output=json"
    try:
        with httpx.Client(timeout=20.0, headers={"User-Agent": USER_AGENT}) as client:
            r = client.get(url)
            if r.status_code == 200 and r.text.strip():
                data = r.json()
                names = set()
                for entry in data:
                    for n in entry.get("name_value", "").split("\n"):
                        n = n.strip().lower().lstrip("*.")
                        if n.endswith(registered):
                            names.add(n)
                subs = sorted(names)
                result.metadata["subdomains"] = subs[:200]
                if len(subs) > 50:
                    result.add(Finding(
                        id="osint.many_subdomains",
                        title=f"{len(subs)} Subdomains öffentlich auffindbar",
                        description="Viele Subdomains vergrößern die Angriffsfläche. Prüfe, ob alle gewollt öffentlich sind.",
                        severity=Severity.INFO,
                        category="OSINT",
                        evidence={"count": len(subs)},
                    ))
    except (httpx.HTTPError, ValueError) as e:
        result.metadata["subdomains_error"] = str(e)


def check_robots(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("robots.txt & sitemap", 90)
    try:
        with httpx.Client(timeout=8.0, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as client:
            r = client.get(f"https://{domain}/robots.txt")
            if r.status_code == 200:
                result.metadata["robots"] = r.text[:4000]
                if re.search(r"(?i)disallow:\s*/admin", r.text):
                    result.add(Finding(
                        id="osint.robots_reveals_admin",
                        title="robots.txt verrät Admin-Pfade",
                        description="robots.txt sollte keine sensiblen Pfade nennen — Angreifer lesen die Datei zuerst.",
                        severity=Severity.LOW,
                        category="OSINT",
                        evidence={"snippet": r.text[:500]},
                    ))
    except httpx.HTTPError:
        pass


def run_osint_scan(domain: str, on_progress: Callable[[str, int], None] | None = None) -> dict:
    """Execute the full OSINT scan for a domain. Returns a serializable dict."""
    domain = _normalize_domain(domain)
    result = ScanResult(target=domain)

    def step(label: str, progress: int) -> None:
        if on_progress:
            on_progress(label, progress)

    step("Starte Scan", 1)
    check_dns(domain, result, step)
    check_email_auth(domain, result, step)
    check_http(domain, result, step)
    check_tls(domain, result, step)
    check_subdomains(domain, result, step)
    check_robots(domain, result, step)
    step("Abgeschlossen", 100)

    return result.to_dict()
