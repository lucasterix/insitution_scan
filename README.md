# insitution_scan

# MVZ Self-Security Scanner (White-Hat Self-Test Tool)

**Ein Open-Source Self-Assessment Tool für Medizinische Versorgungszentren (MVZ)**  
Automatisierte und halbautomatisierte Prüfung auf gängige Sicherheitslücken, OSINT-Risiken und KBV-IT-Sicherheitsanforderungen.

Entwickelt für MVZ-Betreiber, die ihre eigene IT-Infrastruktur regelmäßig und rechtssicher prüfen wollen – ohne fremde Systeme anzugreifen.

---

## 🎯 Ziel des Projekts

- Schnelle Erkennung der häufigsten Schwachstellen in MVZs (offene RDP-Ports, fehlende E-Mail-Authentifizierung, Metadaten-Leaks, veraltete Software etc.)
- Automatisierter Abgleich mit **KBV-IT-Sicherheitsrichtlinie** (§ 390 SGB V)
- Erstellung eines prüffähigen Reports für Datenschutzbeauftragte, IT-Dienstleister und Haftungsabsicherung
- 100 % White-Hat: Nur eigene Domains, IPs und Systeme

---

## 🛡️ Sichere Testumgebung (Pflicht für alle Module)

- Schriftliche Freigabe des MVZ-Inhabers + Anwalts-Dokumentation
- Vollständiges Logging (Sysmon, osquery, EDR)
- Snapshots / Immutable Backups vor jedem Test

---

## 📋 Funktionen & Module

### 1. OSINT & Reconnaissance Modul

```yaml
Eingabe: Domain + MVZ-Name
Ausgabe: JSON + übersichtlicher Report
Checks:

Website Tech-Stack (WordPress, Plugins, veraltete JS-Bibliotheken)
Subdomains (crt.sh, Certificate Transparency)
Security Headers & SSL/TLS (ssllabs, testssl.sh)
SPF / DKIM / DMARC Prüfung (mxtoolbox API + dig)
Shodan / Censys Exposure (offene Ports, RDP, Exchange etc.)
Leaked Credentials (Have I Been Pwned Domain-Suche, leakcheck.io)
Öffentliche Dokumente & Metadaten (Google Dorks + metadata2go)
Stellenausschreibungen & Mitarbeiter-OSINT (LinkedIn/Xing, Indeed)
Historische Versionen (Wayback Machine)

2. E-Mail & Phishing Resilience Modul

SPF/DKIM/DMARC Analyse + Policy-Bewertung (p=none = kritisch)
Test auf Mailbox Forwarding Rules (Exchange/M365)
Spoofing-Simulation (nur intern an eigene Test-Postfächer)

3. Credential & Access Control Modul

Passwort-Policy Prüfung (AD + Linux)
MFA-Status & Conditional Access Checks
Password-Spraying & Brute-Force Detection Rules (Sigma)
Password-Never-Expires Accounts

4. Vulnerability & Patch Management Modul

Authentifizierter Vulnerability Scan (OpenVAS/Greenbone)
EOL-Software & OS-Erkennung
CVE-Priorisierung via NVD + EPSS + CISA KEV
Patch-Status (Windows Hotfixes, apt, etc.)

5. Network Exposure Modul

Externe Port-Scans (nur eigene IPs, -T3)
Offene Remote-Dienste (RDP, SSH, VPN, Admin-Panels)
SIEM-Regeln für Bruteforce-Erkennung

6. Web Application Security Modul

Passive ZAP Baseline Scan (OWASP ZAP)
Security Headers + TLS-Prüfung
Veraltete Bibliotheken (Retire.js)
Grundlegende OWASP Top 10 Checks

7. Configuration & Hardening Modul

CIS Benchmark Vergleich
Lynis Audits (Linux)
Privilegierte Gruppen-Änderungen
Unsichere Konfigurationen (Shares, Buckets, Defaults)

8. Backup & Ransomware Resilience Modul

Backup-Policy Prüfung (Offline/Immutable)
Restore-Drill Unterstützung (Dokumentation)
Detection Rules für Backup-Manipulation (vssadmin etc.)

9. Compliance Modul (KBV-spezifisch)
Automatischer Abgleich der Ergebnisse mit:

KBV IT-Sicherheitscheckliste (Anlagen 1–5)
DSGVO-relevante Funde
Empfohlene Maßnahmen + Priorität


🛠 Technische Anforderungen & Empfohlene Tools
Core Stack:

Python 3.11+
Docker (für ZAP, testssl.sh etc.)
SQLite / PostgreSQL für Ergebnisse

Wichtige Tools (automatisiert aufrufbar):

testssl.sh, nmap, whatweb, nuclei
OWASP ZAP (Baseline Mode)
OpenVAS / Greenbone
Lynis
Sigma Rule Konverter / Validator


📁 Projektstruktur (Vorschlag)
text/mvz-security-scanner
├── modules/              # OSINT, Web, Network, Compliance etc.
├── tools/                # Wrapper für externe Tools
├── reports/              # HTML + PDF Template
├── config/               # KBV-Mapping, Severity-Matrix
├── docs/
│   ├── KBV-Abgleich.md
│   └── sichere-testumgebung.md
├── main.py               # CLI Einstieg
└── README.md

🚀 Nächste Schritte für die Entwickler

OSINT-Modul zuerst fertigstellen (höchster Mehrwert)
Modulares Design mit klaren Interfaces
Report-Engine mit Farbcodierung + KBV-Verlinkung
Docker-Compose für alle externen Tools
CLI + später optionale Streamlit-Web-GUI


⚠️ Rechtliche Hinweise

Nur auf eigenen Systemen einsetzen
Alle Tests müssen dokumentiert und freigegeben sein
Report dient ausschließlich der eigenen Absicherung und Verbesserung
Keine Haftung für unsachgemäße Nutzung


Mitwirkende

Inhaber & Anwalt: [Dein Name]
Initiale Checklisten: Kollege + befreundeter Programmierer
White-Hat Security Guidance: Grok (xAI)


License: MIT (mit Hinweis auf medizinische Nutzung)
Status: In aktiver Entwicklung – erste MVP-Version geplant
