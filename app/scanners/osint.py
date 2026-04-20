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

from app.config import get_settings
from app.integrations import abuseipdb, otx, shodan
from app.integrations.ssllabs import SSLLabsClient, grade_to_severity
from app.scanners.banner_grab import check_banners
from app.scanners.base import Finding, ScanResult, Severity
from app.scanners.cms_scan import check_cms
from app.scanners.cookie_forensics import check_cookie_forensics
from app.scanners.deep.runner import run_deep_scan
from app.scanners.step2.runner import run_step2
from app.scanners.email_auth_deep import check_email_deep
from app.scanners.site_crawler import crawl_site
from app.scanners.email_harvest import harvest_and_check
from app.scanners.exposed_files import check_exposed_files
from app.scanners.healthcare import check_healthcare
from app.scanners.image_metadata import check_image_metadata
from app.scanners.mail_provider import check_mail_provider
from app.scanners.pdf_metadata import check_pdf_metadata
from app.scanners.port_scan import active_port_scan
from app.scanners.privacy import check_privacy
from app.scanners.subdomain_deep import deep_scan_subdomains
from app.scanners.subdomain_walker import walk_subdomains
from app.scanners.tech_fingerprint import check_tech_fingerprint
from app.compliance.finding_enrichment import enrich_findings
from app.scanners.form_security import check_form_security
from app.scanners.default_access import check_default_access
from app.scanners.nmap_scan import check_nmap
from app.scanners.default_creds import check_default_creds
from app.scanners.os_detection import check_os_and_eol
from app.scanners.remote_access import check_remote_access
from app.scanners.server_analysis import check_server
from app.scanners.subdomain_brute import brute_subdomains
from app.scanners.tls_deep import check_tls_deep
from app.scanners.vpn_endpoints import check_vpn_endpoints
from app.scanners.vuln import check_known_vulns

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

SECURITY_HEADERS = {
    # Security headers enable defense-in-depth — missing them does NOT directly
    # compromise the site; they only matter when combined with other vulns
    # (XSS, MITM, malicious upload). Downgrading from MEDIUM/LOW to LOW/INFO.
    "strict-transport-security": (
        "HSTS fehlt",
        "Strict-Transport-Security erzwingt HTTPS beim Browser — Schutz vor Downgrade-Angriffen.",
        Severity.LOW,
    ),
    "content-security-policy": (
        "Content-Security-Policy fehlt",
        "CSP reduziert XSS-Risiken erheblich.",
        Severity.LOW,
    ),
    "x-frame-options": (
        "X-Frame-Options fehlt",
        "Schutz vor Clickjacking (bzw. CSP frame-ancestors).",
        Severity.INFO,
    ),
    "x-content-type-options": (
        "X-Content-Type-Options fehlt",
        "Verhindert MIME-Type Sniffing.",
        Severity.INFO,
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


def _is_ip_address(value: str) -> bool:
    """Check if the input is an IPv4 or IPv6 address rather than a domain."""
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


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


def _fetch_http(scheme: str, domain: str) -> dict:
    """Fetch {scheme}://{domain} with progressive fallback.

    Strategy:
    1. verify=True, our UA, 10s.
    2. verify=True, browser UA, 15s (defeat UA blocklists).
    3. verify=False, browser UA, 15s (fall back on cert issues — record 'cert_insecure': True).
    Returns {"status", "final_url", "headers"} on success or {"error"} + diagnostics on final failure.
    """
    attempts = [
        {"verify": True, "ua": USER_AGENT, "timeout": 10.0, "cert_insecure": False},
        {"verify": True, "ua": BROWSER_UA, "timeout": 15.0, "cert_insecure": False},
        {"verify": False, "ua": BROWSER_UA, "timeout": 15.0, "cert_insecure": True},
    ]
    last_error = ""
    for cfg in attempts:
        try:
            with httpx.Client(
                timeout=cfg["timeout"], follow_redirects=True,
                headers={"User-Agent": cfg["ua"]}, verify=cfg["verify"],
            ) as client:
                r = client.get(f"{scheme}://{domain}")
            return {
                "status": r.status_code,
                "final_url": str(r.url),
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "cert_insecure": cfg["cert_insecure"],
                "ua_used": cfg["ua"],
            }
        except httpx.HTTPError as e:
            last_error = f"{type(e).__name__}: {e}"
            continue
    return {"error": last_error}


def check_http(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("HTTP(S) & Security Headers", 45)
    headers_info: dict = {
        "https": _fetch_http("https", domain),
        "http": _fetch_http("http", domain),
    }

    result.metadata["http"] = headers_info

    https = headers_info.get("https", {})
    http = headers_info.get("http", {})

    # If the osint pre-fetch already got the homepage (with verify=False), HTTPS is
    # clearly reachable — don't falsely flag it even when check_http's stricter path fails.
    pre_fetched = bool(result.metadata.get("homepage_html"))

    if "error" in https and not pre_fetched:
        result.add(Finding(
            id="http.https_unreachable",
            title="HTTPS nicht erreichbar",
            description=f"https://{domain} konnte nicht geladen werden.",
            severity=Severity.HIGH,
            category="Web",
            evidence={"error": https["error"]},
        ))
        return

    if https.get("cert_insecure"):
        result.add(Finding(
            id="http.tls_cert_invalid",
            title="TLS-Zertifikat nicht verifizierbar",
            description=(
                "Der Server liefert ein TLS-Zertifikat das nicht gegen die Standard-Zertifizierungsstellen "
                "verifiziert werden konnte (abgelaufen, self-signed, unvollständige Chain, oder Name-Mismatch). "
                "Browser zeigen eine Warnung — die Website wird so kaum von Patienten genutzt."
            ),
            severity=Severity.HIGH,
            category="TLS",
            recommendation="Let's-Encrypt-Zertifikat korrekt ausstellen und vollständige Kette ausliefern (fullchain.pem).",
        ))

    if "error" in https:
        # Pre-fetch got the content; no further HTTPS analysis possible.
        return

    if "error" not in http and not str(http.get("final_url", "")).startswith("https://"):
        result.add(Finding(
            id="http.no_https_redirect",
            title="HTTP wird nicht auf HTTPS umgeleitet",
            description="Aufrufe über http://... landen nicht automatisch auf https://.",
            # Only affects the first request before HSTS kicks in. With Secure-flagged
            # session cookies it's mostly a hygiene issue.
            severity=Severity.LOW,
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
                # Expired cert = browser warning, users click through, no direct access.
                # Only elevates if combined with mixed-content or password fields.
                result.add(Finding(
                    id="tls.expired",
                    title="TLS-Zertifikat abgelaufen",
                    description=f"Das Zertifikat ist seit {-days_left} Tagen abgelaufen. Browser zeigen eine Warnung; Patienten klicken sie häufig weg, wodurch MITM-Angriffe möglich werden.",
                    severity=Severity.HIGH,
                    category="TLS",
                ))
            elif days_left < 14:
                result.add(Finding(
                    id="tls.expires_soon",
                    title="TLS-Zertifikat läuft bald ab",
                    description=f"Das Zertifikat läuft in {days_left} Tagen ab.",
                    severity=Severity.MEDIUM,
                    category="TLS",
                ))
        except ValueError:
            pass

    if version and version in ("TLSv1", "TLSv1.1", "SSLv3"):
        # SSLv3 = POODLE (CRITICAL historically, needs network position + client compromise)
        # TLSv1.0/1.1 = BEAST/LUCKY13 — practical attacks need MITM and cooperating victim.
        sev = Severity.HIGH if version == "SSLv3" else Severity.MEDIUM
        result.add(Finding(
            id="tls.legacy_protocol",
            title=f"Legacy TLS-Protokoll {version}",
            description="Veraltete TLS-Versionen sind unsicher und sollten deaktiviert werden.",
            severity=sev,
            category="TLS",
        ))


def check_ssllabs(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("SSL Labs Deep-Grade", 68)
    with SSLLabsClient() as client:
        report = client.analyze(domain, use_cache=True)

    if not report:
        result.metadata["ssllabs"] = {"status": "unavailable"}
        return

    endpoints = report.get("endpoints") or []
    grades = []
    for ep in endpoints:
        g = ep.get("grade") or ep.get("gradeTrustIgnored")
        if g:
            grades.append(g)

    result.metadata["ssllabs"] = {
        "status": report.get("status"),
        "grades": grades,
        "endpoints": [
            {
                "ipAddress": ep.get("ipAddress"),
                "grade": ep.get("grade"),
                "hasWarnings": ep.get("hasWarnings"),
            }
            for ep in endpoints
        ],
    }

    if not grades:
        return

    worst = max(grades, key=lambda g: ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"].index(g.upper()) if g.upper() in ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"] else -1)
    sev = grade_to_severity(worst)

    if sev in ("info",):
        # A/A+/A- — report as positive info finding
        result.add(Finding(
            id="tls.ssllabs_grade",
            title=f"SSL Labs Grade {worst}",
            description="Tiefe TLS-Konfigurationsprüfung ergab ein gutes Ergebnis.",
            severity=Severity.INFO,
            category="TLS",
            evidence={"grades": grades},
        ))
    else:
        result.add(Finding(
            id="tls.ssllabs_weak_grade",
            title=f"SSL Labs Grade {worst}",
            description=f"SSL Labs bewertet die TLS-Konfiguration mit {worst}. Details siehe ssllabs.com/ssltest/analyze.html?d={domain}",
            severity=Severity(sev),
            category="TLS",
            evidence={"grades": grades},
            recommendation="Schwache Cipher / veraltete Protokolle deaktivieren, Zertifikatskette prüfen.",
        ))


def check_ip_intel(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    """IP-Intel via Shodan, AbuseIPDB, OTX. Alle Calls sind passiv und optional."""
    ips = (result.metadata.get("dns") or {}).get("A") or []
    if not ips:
        return

    anything_enabled = shodan.is_enabled() or abuseipdb.is_enabled() or otx.is_enabled()
    if not anything_enabled:
        return

    step("IP-Intel (Shodan/AbuseIPDB/OTX)", 82)
    ip_reports: dict[str, dict] = {}

    for ip in ips[:3]:  # cap to avoid slow scans with many A records
        entry: dict = {}

        if shodan.is_enabled():
            sh = shodan.host_lookup(ip)
            if sh:
                ports = sh.get("ports") or []
                entry["shodan"] = {
                    "ports": ports,
                    "hostnames": sh.get("hostnames"),
                    "os": sh.get("os"),
                    "last_update": sh.get("last_update"),
                }
                risky_ports = {
                    3389: ("RDP", Severity.CRITICAL),
                    445: ("SMB", Severity.HIGH),
                    23: ("Telnet", Severity.HIGH),
                    21: ("FTP (unverschlüsselt)", Severity.MEDIUM),
                    1433: ("MSSQL", Severity.HIGH),
                    3306: ("MySQL", Severity.HIGH),
                    5432: ("PostgreSQL", Severity.HIGH),
                    27017: ("MongoDB", Severity.HIGH),
                    6379: ("Redis", Severity.HIGH),
                    9200: ("Elasticsearch", Severity.HIGH),
                }
                for port in ports:
                    if port in risky_ports:
                        label, sev = risky_ports[port]
                        result.add(Finding(
                            id=f"shodan.port.{ip}.{port}",
                            title=f"{label}-Port {port} öffentlich erreichbar ({ip})",
                            description=f"Shodan meldet {label} auf {ip}:{port}. Das ist für MVZs typischerweise ein Top-Risiko.",
                            severity=sev,
                            category="Network Exposure",
                            evidence={"ip": ip, "port": port},
                            recommendation=f"{label} nur via VPN/Firewall erreichbar machen oder komplett schließen.",
                            kbv_ref="KBV IT-Sicherheit §390 SGB V — Netzwerk-Härtung",
                        ))

        if abuseipdb.is_enabled():
            ab = abuseipdb.check_ip(ip)
            if ab:
                score = int(ab.get("abuseConfidenceScore", 0))
                entry["abuseipdb"] = {
                    "score": score,
                    "total_reports": ab.get("totalReports", 0),
                    "country": ab.get("countryCode"),
                }
                if score >= 50:
                    result.add(Finding(
                        id=f"abuseipdb.{ip}",
                        title=f"IP {ip} hat hohe Abuse-Reputation (Score {score}/100)",
                        description="AbuseIPDB meldet zahlreiche Missbrauchsmeldungen für diese IP. Eventuell kompromittiert oder auf Blacklist.",
                        # Bad reputation = monitoring signal, not direct compromise.
                        # Often caused by shared hosting with a noisy neighbor.
                        severity=Severity.MEDIUM if score >= 80 else Severity.LOW,
                        category="Reputation",
                        evidence=ab,
                    ))

        if otx.is_enabled():
            ot = otx.ip_pulses(ip)
            if ot:
                pulses = (ot.get("pulse_info") or {}).get("count", 0)
                entry["otx"] = {"pulse_count": pulses}
                if pulses > 0:
                    result.add(Finding(
                        id=f"otx.{ip}",
                        title=f"IP {ip} in {pulses} OTX-Threat-Pulses gelistet",
                        description="AlienVault OTX verknüpft diese IP mit bekannten Bedrohungs-Kampagnen.",
                        severity=Severity.LOW,
                        category="Threat Intel",
                        evidence={"pulse_count": pulses},
                    ))

        if entry:
            ip_reports[ip] = entry

    if otx.is_enabled():
        dom_intel = otx.domain_pulses(domain)
        if dom_intel:
            pulses = (dom_intel.get("pulse_info") or {}).get("count", 0)
            result.metadata.setdefault("otx_domain", {})["pulse_count"] = pulses
            if pulses > 0:
                result.add(Finding(
                    id="otx.domain",
                    title=f"Domain in {pulses} OTX-Threat-Pulses gelistet",
                    description="AlienVault OTX verknüpft diese Domain mit bekannten Bedrohungs-Kampagnen.",
                    severity=Severity.LOW,
                    category="Threat Intel",
                    evidence={"pulse_count": pulses},
                ))

    if ip_reports:
        result.metadata["ip_intel"] = ip_reports


def _crtsh_cache_key(domain: str) -> str:
    return f"crtsh:{domain}"


def check_subdomains(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Subdomain-Enumeration (crt.sh)", 75)
    ext = tldextract.extract(domain)
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain

    # Redis cache for crt.sh (24h TTL) — the crt.sh JSON API is slow (~15-20s).
    import json as _json
    from app.queue import redis_conn as _redis
    cache_key = f"crtsh:{registered}"
    try:
        cached = _redis.get(cache_key)
        if cached:
            subs = _json.loads(cached)
            result.metadata["subdomains"] = subs
            result.metadata["subdomains_cached"] = True
            return
    except Exception:  # noqa: BLE001
        pass

    url = f"https://crt.sh/?q=%25.{registered}&output=json"
    try:
        with httpx.Client(timeout=25.0, headers={"User-Agent": USER_AGENT}) as client:
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

                # Cache in Redis for 24h.
                try:
                    _redis.setex(cache_key, 24 * 3600, _json.dumps(subs[:200]))
                except Exception:  # noqa: BLE001
                    pass

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


def run_osint_scan(
    domain: str,
    on_progress: Callable[[str, int], None] | None = None,
    deep_scan: bool = False,
    rate_limit_test: bool = False,
) -> dict:
    """Execute the full scan for a domain or IP. Returns a serializable dict."""
    import time as _time
    domain = _normalize_domain(domain)
    is_ip = _is_ip_address(domain)
    result = ScanResult(target=domain)
    result.metadata["deep_scan"] = deep_scan
    result.metadata["rate_limit_test"] = rate_limit_test
    result.metadata["target_type"] = "ip" if is_ip else "domain"
    result.metadata["timing"] = {}

    # When scanning a raw IP, inject it as the A-record so all downstream
    # scanners (port_scan, banner_grab, nmap, shodan, ...) work unchanged.
    if is_ip:
        result.metadata["dns"] = {"A": [domain], "AAAA": [], "MX": [], "NS": [], "CAA": []}

    def step(label: str, progress: int) -> None:
        if on_progress:
            on_progress(label, progress)

    # Cost/runaway guards (inspired by pentagi's per-agent tool-call limits).
    _settings = get_settings()
    _module_timeout_s = int(_settings.scan_module_timeout_seconds or 0)
    _total_budget_s = int(_settings.scan_total_budget_seconds or 0)

    def run(fn, *args, **kwargs):
        """Run a scanner module with timing, error isolation, per-module
        timeout, and global scan budget enforcement.

        If the total scan budget is already exhausted, the module is skipped
        (not executed) and marked as such in scanner_errors — remaining
        pipeline modules also skip, so the scan closes gracefully.
        """
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutTimeout
        name = getattr(fn, "__name__", str(fn))

        # Total-budget gate: stop running new modules once the combined
        # per-module elapsed time passes the budget.
        if _total_budget_s > 0:
            spent = sum((result.metadata.get("timing") or {}).values())
            if spent > _total_budget_s:
                result.metadata.setdefault("scanner_errors", []).append({
                    "module": name,
                    "error": f"skipped: total-scan budget {_total_budget_s}s exceeded ({spent:.0f}s spent)",
                })
                result.metadata["timing"][name] = 0.0
                return

        start = _time.monotonic()
        try:
            if _module_timeout_s > 0:
                # ThreadPoolExecutor + fut.result(timeout) — the worker thread
                # can't be force-killed in pure Python, but it stops blocking us
                # and the next module starts immediately.
                with ThreadPoolExecutor(max_workers=1) as _ex:
                    _fut = _ex.submit(fn, *args, **kwargs)
                    try:
                        _fut.result(timeout=_module_timeout_s)
                    except _FutTimeout:
                        result.metadata.setdefault("scanner_errors", []).append({
                            "module": name,
                            "error": f"timeout after {_module_timeout_s}s — module aborted",
                        })
            else:
                fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            result.metadata.setdefault("scanner_errors", []).append({
                "module": name, "error": f"{type(e).__name__}: {e}"
            })
        elapsed = round(_time.monotonic() - start, 2)
        result.metadata["timing"][name] = elapsed

    step("Starte Scan", 1)

    # Pre-fetch homepage HTML (works for both domain and IP targets).
    # Also captures set-cookie list for cookie_forensics so it doesn't re-fetch.
    # Two-pass: our UA first, then browser UA (some GoDaddy/WAF setups block unknown bots).
    _ua_attempts = [USER_AGENT, BROWSER_UA]
    _got_home = False
    for _ua in _ua_attempts:
        if _got_home:
            break
        for scheme in ("https", "http"):
            try:
                with httpx.Client(
                    timeout=15.0, follow_redirects=True,
                    headers={"User-Agent": _ua}, verify=False,
                ) as _hc:
                    _hp = _hc.get(f"{scheme}://{domain}")
                    if _hp.status_code == 200 and "text/html" in _hp.headers.get("content-type", "").lower():
                        result.metadata["homepage_html"] = _hp.text[:500_000]
                        result.metadata["homepage_headers"] = {k.lower(): v for k, v in _hp.headers.items()}
                        result.metadata["homepage_ua_used"] = _ua
                        raw_cookies: list[str] = []
                        if hasattr(_hp.headers, "get_list"):
                            raw_cookies = _hp.headers.get_list("set-cookie") or []
                        elif _hp.headers.get("set-cookie"):
                            raw_cookies = [_hp.headers["set-cookie"]]
                        result.metadata["homepage_cookies_raw"] = raw_cookies
                        _got_home = True
                        break
            except httpx.HTTPError:
                continue

    # --- Domain-only modules (skip when scanning a raw IP) ---
    if not is_ip:
        run(check_dns, domain, result, step)
        run(check_mail_provider, domain, result, step)
        run(check_email_auth, domain, result, step)
        run(check_email_deep, domain, result, step)
        run(crawl_site, domain, result, step)
        run(check_privacy, domain, result, step)
        run(check_healthcare, domain, result, step)
        run(check_http, domain, result, step)
        run(check_tls, domain, result, step)
        run(check_tls_deep, domain, result, step)
        run(check_ssllabs, domain, result, step)
        run(check_subdomains, domain, result, step)
        run(brute_subdomains, domain, result, step)
        run(walk_subdomains, domain, result, step)
        run(deep_scan_subdomains, domain, result, step)

    # --- Modules that work on both domains AND IPs ---
    run(check_ip_intel, domain, result, step)
    run(check_exposed_files, domain, result, step)
    run(active_port_scan, domain, result, step)
    run(check_banners, domain, result, step)
    run(check_nmap, domain, result, step)
    run(check_default_access, domain, result, step)
    run(check_os_and_eol, domain, result, step)
    run(check_server, domain, result, step)
    run(check_vpn_endpoints, domain, result, step)
    run(check_remote_access, domain, result, step)

    if not is_ip:
        run(check_cookie_forensics, domain, result, step)
        run(check_robots, domain, result, step)
        run(check_cms, domain, result, step)
        run(check_form_security, domain, result, step)

    run(check_tech_fingerprint, domain, result, step)

    if not is_ip:
        run(harvest_and_check, domain, result, step)

    if deep_scan:
        run(run_deep_scan, domain, result, step, rate_limit_test=rate_limit_test)

    # default_creds + default_access depend on deep-scan metadata (wayback live_hits,
    # directory_fuzz paths, firewall_test WAF state). Run AFTER the deep scan so the
    # risk assessment accounts for those signals.
    run(check_default_creds, domain, result, step)

    if not is_ip:
        run(check_pdf_metadata, domain, result, step)
        run(check_image_metadata, domain, result, step)

    run(check_known_vulns, domain, result, step)

    if not is_ip:
        run(run_step2, domain, result, step)

    enrich_findings(result)

    step("Abgeschlossen", 100)

    return result.to_dict()
