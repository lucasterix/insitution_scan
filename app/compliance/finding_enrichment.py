"""Automatic finding enrichment: legal references + exploit examples.

Applied as a post-processing step after all scanners have run. Adds:
- ⚖️ Rechtsgrundlage (which law/regulation is violated)
- 🎯 Exploit-Szenario (practical business example)

Only enriches findings that don't already contain these markers.
"""
from __future__ import annotations

from app.scanners.base import ScanResult

# finding_id prefix → {legal, exploit}
# These are applied to findings whose id STARTS WITH the key.
ENRICHMENTS: dict[str, dict[str, str]] = {
    "email.spf_missing": {
        "legal": "DSGVO Art. 32 Abs. 1 (technische Maßnahmen zum Schutz personenbezogener Daten), BSI IT-Grundschutz APP.5.3.A1 (Mail-Transport-Sicherheit)",
        "exploit": "Ein Angreifer sendet als praxis@ihre-domain.de eine E-Mail an Patienten: 'Bitte laden Sie Ihre Befunde unter folgendem Link herunter.' Ohne SPF kann der Mail-Server des Empfängers die Fälschung nicht erkennen — der Patient klickt und gibt seine Versichertendaten auf einer Phishing-Seite ein.",
    },
    "email.dmarc_missing": {
        "legal": "DSGVO Art. 32 (TOM), BSI IT-Grundschutz APP.5.3 (E-Mail-Sicherheit)",
        "exploit": "Ohne DMARC erhält die Praxis keinen Report über versuchte E-Mail-Spoofing-Angriffe. Ein Angreifer versendet unbemerkt hunderte Phishing-Mails im Namen der Praxis an Patienten. Erst Wochen später beschwert sich ein Patient — die Praxis erfährt erst dann vom Angriff.",
    },
    "email.dkim_missing": {
        "legal": "DSGVO Art. 32 (Integrität der Kommunikation), KBV IT-Sicherheitsrichtlinie Anlage 2",
        "exploit": "Ohne DKIM-Signatur kann ein Angreifer den Inhalt einer E-Mail auf dem Transportweg verändern (z.B. einen Laborbefund-Anhang austauschen), ohne dass der Empfänger es merkt. Bei medizinischen Befunden kann das lebensbedrohlich sein.",
    },
    "email.mta_sts_missing": {
        "legal": "DSGVO Art. 32 (Verschlüsselung im Transit), BSI-Grundschutz NET.3.3",
        "exploit": "Ohne MTA-STS kann ein Man-in-the-Middle im Netzwerk die TLS-Verschlüsselung zwischen Mail-Servern per STARTTLS-Downgrade aushebeln und Patientenbefunde im Klartext mitlesen.",
    },
    "http.header.strict-transport-security": {
        "legal": "DSGVO Art. 32 (Transportverschlüsselung), BSI IT-Grundschutz APP.3.2.A1",
        "exploit": "In einem Praxis-WLAN tippt ein Patient http://praxis.de ein. Ohne HSTS leitet der Browser nicht automatisch auf HTTPS um — ein Angreifer im selben WLAN fängt die Session-Cookies ab und übernimmt die eingeloggte Sitzung (Session Hijacking).",
    },
    "http.https_unreachable": {
        "legal": "DSGVO Art. 32 (Verschlüsselung), §203 StGB (Verletzung von Privatgeheimnissen)",
        "exploit": "Formulardaten (Terminbuchung, Kontaktanfrage) werden unverschlüsselt übertragen. Jeder im selben Netzwerk kann Name, Telefonnummer und Gesundheitsanliegen des Patienten mitlesen.",
    },
    "tls.expired": {
        "legal": "DSGVO Art. 32, KBV IT-Sicherheitsrichtlinie Anlage 1 (A1.3)",
        "exploit": "Browser zeigen eine Sicherheitswarnung — Patienten verlieren Vertrauen in die Praxis-Website und buchen bei der Konkurrenz. Technisch: Ein Angreifer kann ein eigenes Zertifikat unterschieben (MITM).",
    },
    "tls.no_forward_secrecy": {
        "legal": "BSI TR-02102-2 (Kryptographische Verfahren), DSGVO Art. 32 (Stand der Technik)",
        "exploit": "Ein Geheimdienst oder ISP zeichnet den verschlüsselten Traffic heute auf. Wenn in 5 Jahren der Private Key des Servers durch einen Hack bekannt wird, können alle aufgezeichneten Sessions nachträglich entschlüsselt werden — inklusive Patientendaten. Mit Forward Secrecy (PFS) ist das nicht möglich.",
    },
    "dns.caa_missing": {
        "legal": "BSI IT-Grundschutz APP.3.2 (Zertifikatsmanagement)",
        "exploit": "Ohne CAA-Record darf jede Zertifizierungsstelle weltweit ein TLS-Zertifikat für die Praxis-Domain ausstellen. Ein Angreifer beantragt bei einer unseriösen CA ein gültiges Zertifikat und betreibt damit eine perfekte Phishing-Kopie der Praxis-Website.",
    },
    "shodan.port.": {
        "legal": "KBV IT-Sicherheitsrichtlinie Anlage 3 (Netzwerk-Segmentierung), DSGVO Art. 32 (Zugriffskontrolle)",
        "exploit": "RDP (Port 3389) aus dem Internet erreichbar: Ein Angreifer startet einen automatisierten Brute-Force-Angriff auf den Windows-Login. Bei Erfolg hat er Vollzugriff auf den Praxis-PC, das PVS und alle Patientendaten. Ransomware-Gruppen scannen aktiv nach offenen RDP-Ports.",
    },
    "port.": {
        "legal": "KBV IT-Sicherheitsrichtlinie Anlage 3 (Netzwerk-Härtung)",
        "exploit": "Offene Datenbank-Ports (MySQL 3306, PostgreSQL 5432) aus dem Internet: Ein Angreifer kann direkt SQL-Abfragen gegen die Patienten-Datenbank senden, ohne die Webseite zu benutzen. Default-Credentials (root/root) werden automatisch durchprobiert.",
    },
    "wp.user_enum": {
        "legal": "DSGVO Art. 32 (Zugriffskontrolle), KBV Anlage 2 (Zugriffskontrolle)",
        "exploit": "Die WordPress-API liefert alle Benutzernamen: admin, dr.mueller, empfang. Der Angreifer startet gezieltes Credential-Stuffing mit Passwörtern aus LeakCheck-Datenbanken. Bei Treffer: voller CMS-Zugriff → Webshell-Upload → Zugriff auf den Server.",
    },
    "wp.xmlrpc_enabled": {
        "legal": "KBV IT-Sicherheitsrichtlinie Anlage 2 (Patch-Management)",
        "exploit": "Über xmlrpc.php kann ein Angreifer in einem einzigen HTTP-Request 500 Passwörter gleichzeitig testen (system.multicall). Rate-Limiting greift nicht, weil es technisch nur ein Request ist. Nach 10 Minuten hat er das Passwort von 'empfang' erraten.",
    },
    "wp.plugin.": {
        "legal": "KBV IT-Sicherheitsrichtlinie Anlage 2 (Patch-Management), DSGVO Art. 32 (Stand der Technik)",
        "exploit": "Ein veraltetes WordPress-Plugin (z.B. wp-file-manager < 7.0) erlaubt unauthentisiertes Hochladen einer PHP-Webshell. Der Angreifer hat damit Kommandozeilen-Zugriff auf den Server, kann die wp-config.php (mit Datenbankpasswort) lesen und sämtliche Patientendaten exportieren.",
    },
    "exposed.": {
        "legal": "DSGVO Art. 32 (Vertraulichkeit), §203 StGB (ärztliche Schweigepflicht)",
        "exploit": ".env-Datei öffentlich abrufbar: Enthält typischerweise Datenbankpasswort, API-Keys, SMTP-Credentials. Der Angreifer liest die Datei, loggt sich in die Datenbank ein und exportiert alle Patientenakten. Backup.sql.gz enthält eine komplette Kopie aller Patienten-, Termin- und Abrechnungsdaten.",
    },
    "privacy.tracker.": {
        "legal": "DSGVO Art. 6 Abs. 1 lit. a (Einwilligung), TTDSG §25 (Zugriff auf Endeinrichtung), EuGH Planet49 (C-673/17)",
        "exploit": "Google Analytics überträgt Besucherdaten (IP, Seitenaufrufe wie '/termin-neurologie') ohne Einwilligung an Google-Server in den USA. Eine Abmahnung nach TTDSG §25 kostet 5.000–15.000 €, die DSB-Beanstandung ist ein Reputationsschaden. Bei Arztpraxen ist die Tracking-Problematik besonders brisant, weil die besuchten Unterseiten Rückschlüsse auf Diagnosen erlauben.",
    },
    "privacy.impressum_missing": {
        "legal": "§5 DDG (Impressumspflicht), §10 MDStV, HWG §11 (Heilmittelwerbung)",
        "exploit": "Fehlendes Impressum: Abmahnung durch Wettbewerber oder Verbraucherschutzverband. Kostenpunkt: 800–3.000 € pro Abmahnung + Unterlassungserklärung. Kommt bei MVZ-Websites regelmäßig vor.",
    },
    "privacy.impressum_incomplete": {
        "legal": "§5 DDG, Musterberufsordnung-Ä §27, HWG",
        "exploit": "Fehlende Ärztekammer-Angabe oder Berufsbezeichnung im Impressum: Abmahnanwälte scannen automatisch nach diesen Lücken. Pro Abmahnung 1.000–5.000 €.",
    },
    "pdf.author_leaked": {
        "legal": "DSGVO Art. 5 Abs. 1 lit. c (Datenminimierung), Art. 32 (TOM)",
        "exploit": "Die Praxis-Broschüre 'Patientenaufklärung_Koloskopie.pdf' trägt im Author-Feld den Klarnamen 'Dr. med. Maria Schneider'. Ein Angreifer nutzt diesen Namen für Spear-Phishing: 'Lieber Patient, Dr. Schneider bittet Sie, Ihre aktualisierten Versichertendaten hier einzugeben.' Der Patient vertraut, weil der Name stimmt.",
    },
    "image.exif_gps_leaked": {
        "legal": "DSGVO Art. 5 (Datenminimierung), Art. 32 (TOM), ggf. §201a StGB (Verletzung des höchstpersönlichen Lebensbereichs)",
        "exploit": "Ein Praxisfoto auf der Website ('Unser Team') enthält GPS-Koordinaten aus dem Home-Office des Praxisinhabers. Ein unzufriedener Patient oder ein Stalker kennt damit die Privatadresse des Arztes.",
    },
    "healthcare.connector.": {
        "legal": "KBV IT-Sicherheitsrichtlinie Anlage 4+5, gematik-Spezifikation (TI-Konnektor), §75b SGB V",
        "exploit": "Der TI-Konnektor-Web-UI ist aus dem Internet erreichbar. Über bekannte CVEs (z.B. SecuNET-Firmware-Lücken) kann ein Angreifer den Konnektor übernehmen, sich als die Praxis gegenüber der Telematikinfrastruktur ausgeben und auf die elektronische Patientenakte (ePA) aller Patienten zugreifen.",
    },
    "deep.open_redirect": {
        "legal": "OWASP Top 10 A10 (Unvalidated Redirects), BSI IT-Grundschutz APP.3.1",
        "exploit": "Der Angreifer verschickt an Praxis-Patienten: 'Klicken Sie hier für Ihre Befunde: https://praxis-musterstadt.de/login?next=https://evil.com'. Der Link beginnt mit der vertrauenswürdigen Praxis-Domain — nach dem Klick landet der Patient auf einer Fake-Login-Seite und gibt sein Passwort ein.",
    },
    "deep.host_header_injection": {
        "legal": "OWASP Top 10 (Server-Side Request Forgery Variant), BSI IT-Grundschutz APP.3.1",
        "exploit": "Ein Patient klickt 'Passwort vergessen'. Der Angreifer hat den Host-Header manipuliert — die Praxis-Software generiert den Reset-Link mit evil.com statt praxis.de. Der Patient klickt den Link in der echten Reset-Mail und gibt sein neues Passwort auf der Angreifer-Seite ein.",
    },
    "deep.cors_misconfigured": {
        "legal": "DSGVO Art. 32 (Zugriffskontrolle), OWASP Top 10 A07 (Cross-Origin Failures)",
        "exploit": "Die API akzeptiert jeden Origin mit Credentials. Ein Angreifer bettet ein unsichtbares Script auf evil.com ein. Wenn ein eingeloggter Mitarbeiter evil.com besucht, liest das Script über die Praxis-API alle Patiententermine und Befunde aus — im Browser des Opfers, ohne dass jemand etwas merkt.",
    },
    "deep.js_secret.": {
        "legal": "DSGVO Art. 32 (Vertraulichkeit von Zugangsdaten), §203 StGB",
        "exploit": "Im JavaScript-Bundle der Praxis-Website steckt ein AWS_SECRET_ACCESS_KEY. Der Angreifer öffnet die Browser-DevTools, kopiert den Schlüssel, und hat Zugriff auf den S3-Bucket der Praxis mit allen Backup-Dateien — inklusive Patientendatenbank.",
    },
    "step2.subdomain_takeover.": {
        "legal": "DSGVO Art. 32 (Domain-Hygiene), Markenrecht (§14 MarkenG bei Phishing)",
        "exploit": "termin.praxis-musterstadt.de hatte einen CNAME auf eine Heroku-App, die nicht mehr existiert. Der Angreifer registriert die Heroku-App unter demselben Namen, hostet dort eine Phishing-Login-Seite — mit gültigem TLS-Zertifikat auf der Praxis-Subdomain.",
    },
    "step2.spf_takeover": {
        "legal": "DSGVO Art. 32 (TOM, E-Mail-Sicherheit), BSI IT-Grundschutz APP.5.3",
        "exploit": "Der SPF-Record enthält 'include:alte-agentur.de'. Die Agentur hat die Domain gekündigt. Der Angreifer registriert alte-agentur.de für 9 €, setzt dort einen SPF-Record, und kann jetzt E-Mails senden die den SPF-Check der Praxis bestehen — perfektes Phishing mit 'Absender verifiziert'-Badge.",
    },
    "step2.api_unauth_sensitive": {
        "legal": "DSGVO Art. 32 (Zugriffskontrolle), §203 StGB (ärztliche Schweigepflicht), KBV Anlage 3",
        "exploit": "/api/patients liefert ohne Login eine JSON-Liste aller Patienten mit Name, Geburtsdatum, Versichertennummer und nächstem Termin. Der Angreifer exportiert 5.000 Datensätze in 2 Sekunden. Meldepflicht nach DSGVO Art. 33 innerhalb 72 Stunden, Bußgeld bis 4% des Jahresumsatzes.",
    },
    "vuln.": {
        "legal": "KBV IT-Sicherheitsrichtlinie Anlage 2+3 (Patch-Management), BSI IT-Grundschutz OPS.1.1.3 (Patch- und Änderungsmanagement)",
        "exploit": "Die eingesetzte Software-Version hat eine bekannte Schwachstelle mit öffentlich verfügbarem Exploit-Code. Automatisierte Scanner (Shodan, Censys) identifizieren verwundbare Systeme innerhalb von Stunden nach Veröffentlichung eines CVE. Bei kritischen Lücken (CVSS ≥ 9.0) beginnen Ransomware-Gruppen innerhalb von 48 Stunden mit der Ausnutzung.",
    },
    "auth.csrf_token_missing": {
        "legal": "OWASP Top 10 A01 (Broken Access Control), DSGVO Art. 32",
        "exploit": "Der Angreifer sendet eine E-Mail mit einem unsichtbaren Bild-Tag: <img src='https://praxis.de/admin/user/delete?id=1'>. Wenn ein eingeloggter Admin diese E-Mail öffnet, wird der Benutzer gelöscht — ohne dass der Admin etwas klickt.",
    },
    "auth.mfa_not_detected": {
        "legal": "KBV IT-Sicherheitsrichtlinie Anlage 2 (Zugriffskontrolle), BSI IT-Grundschutz ORP.4.A8",
        "exploit": "Ohne MFA genügt ein geleaktes Passwort aus einer alten Breach-Datenbank. Der Angreifer loggt sich mit empfang@praxis.de + altem Passwort ein, hat Zugriff auf das CMS, ändert die Telefonnummer im Impressum auf seine eigene und empfängt Patientenanrufe.",
    },
    "deep.rate_limit_missing": {
        "legal": "KBV IT-Sicherheitsrichtlinie Anlage 2, OWASP Top 10 A07 (Identification and Authentication Failures)",
        "exploit": "Der Login-Endpunkt hat kein Rate-Limiting. Der Angreifer testet 10.000 Passwörter pro Minute mit einem Script. Nach 2 Stunden hat er das Passwort von 'empfang' erraten (Credential Stuffing aus der LeakCheck-Datenbank).",
    },
    "vpn.endpoint.": {
        "legal": "KBV IT-Sicherheitsrichtlinie Anlage 3 (Remote-Zugänge), BSI IT-Grundschutz NET.3.3",
        "exploit": "Fortinet SSL-VPN öffentlich erreichbar: CVE-2023-27997 erlaubt Pre-Auth Remote Code Execution. Der Angreifer bekommt ohne Passwort Kommandozeilen-Zugriff auf das VPN-Gateway, tunnelt sich ins Praxis-LAN und hat Zugriff auf jeden PC, Drucker und das PVS.",
    },
    "cookie.jwt_alg_none": {
        "legal": "OWASP Top 10 A07 (Auth Failures), DSGVO Art. 32",
        "exploit": "Der JWT im Cookie hat alg=none — keine Signaturprüfung. Der Angreifer öffnet die Browser-DevTools, ändert im JWT 'role: user' zu 'role: admin', und ist sofort Administrator der Anwendung.",
    },
}


def enrich_findings(result: ScanResult) -> None:
    """Post-process: add legal references + exploit examples to findings."""
    for finding in result.findings:
        for prefix, data in ENRICHMENTS.items():
            if finding.id == prefix or finding.id.startswith(prefix):
                desc = finding.description
                if data.get("legal") and "Rechtsgrundlage" not in desc:
                    desc += f"\n\n⚖️ Rechtsgrundlage: {data['legal']}"
                if data.get("exploit") and "Exploit-Szenario" not in desc:
                    desc += f"\n\n🎯 Exploit-Szenario aus der Praxis: {data['exploit']}"
                finding.description = desc
                break
