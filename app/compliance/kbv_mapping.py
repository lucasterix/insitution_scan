"""KBV IT-Sicherheitsrichtlinie §390 SGB V — Mapping von Finding-IDs auf Anlagen.

Die KBV IT-Sicherheitsrichtlinie gliedert sich (vereinfacht) in:

- Anlage 1: Grundlegende Anforderungen (alle Praxen & MVZ)
- Anlage 2: Mittlere Anforderungen (mittlere Praxisgrößen)
- Anlage 3: Hohe Anforderungen (MVZ mit mehr als 20 Behandlungseinheiten)
- Anlage 4: Anforderungen an Medizinprodukte
- Anlage 5: Anforderungen an dezentrale Komponenten der Telematikinfrastruktur

Dieses Mapping übersetzt unsere Finding-IDs auf die thematischen Schwerpunkte
der Anlagen, damit der Bericht den DPOs/IT-Dienstleistern konkret sagen kann,
welche Anforderung wodurch gedeckt/verletzt ist.

Hinweis: Die Zuordnung ist eine praxistaugliche Näherung, kein Rechtstext.
Die finale Compliance-Bewertung muss weiterhin durch einen Fachkundigen
erfolgen — das Tool liefert nur die technische Grundlage.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KBVRequirement:
    anlage: int
    code: str  # z.B. "A1.1"
    title: str
    description: str
    finding_id_prefixes: tuple[str, ...]  # Wenn irgendein Finding mit diesem Prefix existiert, gilt die Anforderung als "verletzt"


# Listing ist kein 1:1-Abgleich, sondern ein praktisches Mapping der
# Anforderungsthemen auf unsere technischen Checks.
KBV_REQUIREMENTS: tuple[KBVRequirement, ...] = (
    KBVRequirement(
        anlage=1,
        code="A1.1",
        title="Sichere Dokumentenzustellung per E-Mail (SPF/DMARC)",
        description="Die Praxis/das MVZ stellt sicher, dass E-Mails an Patienten und andere Praxen nicht gefälscht werden können.",
        finding_id_prefixes=("email.spf_missing", "email.spf_too_permissive", "email.dmarc_missing", "email.dmarc_policy_none"),
    ),
    KBVRequirement(
        anlage=1,
        code="A1.2",
        title="Transportverschlüsselung für Web-Dienste",
        description="Webseiten und Patientenportale werden über HTTPS ausgeliefert, HTTP wird umgeleitet.",
        finding_id_prefixes=("http.https_unreachable", "http.no_https_redirect", "tls.connect_failed", "tls.expired", "tls.legacy_protocol"),
    ),
    KBVRequirement(
        anlage=1,
        code="A1.3",
        title="Aktuelles, vertrauenswürdiges Zertifikat",
        description="TLS-Zertifikate sind gültig, nicht abgelaufen und nicht kurz vor Ablauf.",
        finding_id_prefixes=("tls.expired", "tls.expires_soon"),
    ),
    KBVRequirement(
        anlage=2,
        code="A2.1",
        title="E-Mail-Absender-Authentisierung (Policy aktiv)",
        description="DMARC ist auf quarantine oder reject eingestellt, nicht nur auf none/Monitoring.",
        finding_id_prefixes=("email.dmarc_policy_none", "email.dmarc_missing"),
    ),
    KBVRequirement(
        anlage=2,
        code="A2.2",
        title="Web-Sicherheitsheader",
        description="Die Webseite sendet mindestens HSTS, X-Content-Type-Options und X-Frame-Options bzw. eine entsprechende CSP.",
        finding_id_prefixes=("http.header.strict-transport-security", "http.header.x-content-type-options", "http.header.x-frame-options", "http.header.content-security-policy"),
    ),
    KBVRequirement(
        anlage=2,
        code="A2.3",
        title="Keine Offenlegung technischer Details",
        description="Server-Banner und X-Powered-By geben keine exakten Versionsnummern preis.",
        finding_id_prefixes=("http.header.x_powered_by", "tech.version_disclosure"),
    ),
    KBVRequirement(
        anlage=3,
        code="A3.1",
        title="Kein direkter Remote-Zugang aus dem Internet",
        description="Dienste wie RDP, SMB, Telnet, FTP sind aus dem Internet nicht erreichbar.",
        finding_id_prefixes=("shodan.port.",),
    ),
    KBVRequirement(
        anlage=3,
        code="A3.2",
        title="Keine öffentlich erreichbaren Datenbanken",
        description="MSSQL, MySQL, PostgreSQL, MongoDB, Redis und Elasticsearch sind aus dem Internet nicht erreichbar.",
        finding_id_prefixes=("shodan.port.",),  # further filtered via ports in analysis
    ),
    KBVRequirement(
        anlage=3,
        code="A3.3",
        title="CAA-Record zur Begrenzung der Zertifikatsaussteller",
        description="Ein CAA-Record schränkt ein, welche CAs für die Domain Zertifikate ausstellen dürfen.",
        finding_id_prefixes=("dns.caa_missing",),
    ),
    KBVRequirement(
        anlage=3,
        code="A3.4",
        title="Reputation der eigenen Infrastruktur",
        description="Die eigene IP/Domain taucht nicht in Blacklists oder Threat-Intel-Feeds auf.",
        finding_id_prefixes=("abuseipdb.", "otx."),
    ),
    KBVRequirement(
        anlage=3,
        code="A3.5",
        title="Tiefe TLS-Konfigurationsprüfung",
        description="Die TLS-Konfiguration erhält von SSL Labs mindestens Grade B.",
        finding_id_prefixes=("tls.ssllabs_weak_grade",),
    ),
    KBVRequirement(
        anlage=3,
        code="A3.6",
        title="Patch-Management der öffentlich erreichbaren Software",
        description="Auf öffentlich erreichbaren Servern/Diensten sind keine bekannten CVEs identifizierbar.",
        finding_id_prefixes=("vuln.",),
    ),
    KBVRequirement(
        anlage=1,
        code="A1.4",
        title="Keine sensiblen Dateien öffentlich abrufbar",
        description=".git, .env, Datenbank-Dumps, Backup-Archive und ähnliche Dateien sind nicht über das Web erreichbar.",
        finding_id_prefixes=("exposed.",),
    ),
    KBVRequirement(
        anlage=3,
        code="A3.7",
        title="Keine sensiblen Subdomains öffentlich (Staging/Admin)",
        description="Entwicklungs-, Staging- und Admin-Subdomains sind nicht aus dem Internet erreichbar.",
        finding_id_prefixes=("subdomain.sensitive.",),
    ),
    KBVRequirement(
        anlage=3,
        code="A3.8",
        title="Keine kritischen Ports aus dem Internet erreichbar",
        description="RDP, SMB, Telnet, VNC, MSSQL, MySQL, PostgreSQL, MongoDB, Redis und Elasticsearch sind aus dem Internet nicht erreichbar.",
        finding_id_prefixes=("port.", "shodan.port."),
    ),
    KBVRequirement(
        anlage=2,
        code="A2.4",
        title="DKIM aktiv konfiguriert",
        description="Mindestens ein DKIM-Selector ist veröffentlicht und signiert ausgehende Mails.",
        finding_id_prefixes=("email.dkim_missing",),
    ),
    KBVRequirement(
        anlage=2,
        code="A2.5",
        title="MTA-STS Transportverschlüsselung für E-Mail",
        description="MTA-STS erzwingt TLS zwischen Mail-Servern und schützt vor STARTTLS-Downgrade.",
        finding_id_prefixes=("email.mta_sts_missing", "email.mta_sts_policy_missing"),
    ),
    KBVRequirement(
        anlage=1,
        code="A1.5",
        title="Keine Klarnamen in öffentlichen PDF-Metadaten",
        description="Öffentliche PDFs (Patientenaufklärung, Preislisten etc.) enthalten keine Klarnamen oder Standort-Metadaten.",
        finding_id_prefixes=("pdf.author_leaked",),
    ),
    KBVRequirement(
        anlage=1,
        code="A1.6",
        title="Vollständiges TMG/DDG-Impressum",
        description="Das Impressum enthält alle nach §5 DDG + HWG + Berufsordnung erforderlichen Angaben (Anschrift, Kammer, Berufsbezeichnung, Aufsicht).",
        finding_id_prefixes=("privacy.impressum_missing", "privacy.impressum_incomplete"),
    ),
    KBVRequirement(
        anlage=2,
        code="A2.6",
        title="Keine DSGVO-relevanten Tracker ohne Consent",
        description="Google Analytics, Meta Pixel und vergleichbare Tracker werden nicht ohne aktive Einwilligung geladen.",
        finding_id_prefixes=("privacy.tracker.",),
    ),
    KBVRequirement(
        anlage=2,
        code="A2.7",
        title="Cookie-Security-Flags gesetzt",
        description="Alle Cookies werden mit Secure, HttpOnly und SameSite ausgeliefert.",
        finding_id_prefixes=("privacy.cookie_flags_missing",),
    ),
    KBVRequirement(
        anlage=4,
        code="A4.1",
        title="TI-Konnektor nicht aus dem Internet erreichbar",
        description="Konnektor-Web-UIs (SecuNET, KoCoBox, CGM) sind nicht von außen erreichbar.",
        finding_id_prefixes=("healthcare.connector.",),
    ),
    KBVRequirement(
        anlage=4,
        code="A4.2",
        title="Keine unauthentisierten Patienten-/Medizin-APIs",
        description="APIs für Patienten-, Termin- oder Medizin-Daten sind nicht ohne Authentifizierung öffentlich erreichbar.",
        finding_id_prefixes=("healthcare.api_exposed.",),
    ),
    KBVRequirement(
        anlage=5,
        code="A5.1",
        title="Korrekt aufgebaute TI/KIM-Infrastruktur (Positiv-Signal)",
        description="KIM-DNS-Einträge sind vorhanden (positiv) und keine TI-Komponente ist öffentlich erreichbar.",
        finding_id_prefixes=(),  # This is a positive requirement; status stays 'ok' unless connector hits exist.
    ),
)


def status_for_requirement(req: KBVRequirement, finding_ids: set[str]) -> str:
    """Return 'fail' if any matching finding exists, else 'ok'."""
    for fid in finding_ids:
        for prefix in req.finding_id_prefixes:
            if fid == prefix or fid.startswith(prefix):
                return "fail"
    return "ok"
