<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green" />
  <img src="https://img.shields.io/badge/Scanners-45+_Module-orange" />
  <img src="https://img.shields.io/badge/nmap-7.95-blue?logo=nmap" />
  <img src="https://img.shields.io/badge/nuclei-3.7-purple" />
  <img src="https://img.shields.io/badge/Deploy-GitHub_Actions-black?logo=githubactions" />
</p>

<h1 align="center">MVZ Self-Scan</h1>
<p align="center">
  <strong>Automatisiertes Pentest-Self-Assessment für Medizinische Versorgungszentren</strong><br>
  45+ Scanner-Module | nmap + nuclei | KBV §390 SGB V | DSGVO | WAF-Test | Prüffähiger PDF-Report
</p>

<p align="center">
  <a href="https://scan.zdkg.de"><strong>Live-Demo &rarr;</strong></a>
</p>

---

## Was ist das?

MVZ Self-Scan ist ein spezialisiertes Pentest-Self-Assessment-Tool für den deutschen Gesundheitssektor. Es scannt die öffentlich erreichbare Angriffsfläche einer Domain vollautomatisch und liefert:

- **Ein Security-Dashboard** mit Letter-Grade (A+ bis F), Risiko-Score, Top-Risiken und KBV-Compliance-Prozent
- **Einen prüffähigen PDF-Report** (9 Kapitel, nach §390 SGB V / DSGVO Art. 32 / BSI-Grundschutz strukturiert)
- **Healthcare-spezifische Checks** die kein generisches Tool abdeckt (KIM, TI-Konnektor, PVS-Fingerprint, Doctolib/Samedi-Widgets)
- **Step-2 Analyse** die gewonnene Informationen aus Step 1 für gezielte Folge-Probes verwendet
- **Automatische Finding-Enrichment** mit exakter Rechtsgrundlage (DSGVO Art., §390 SGB V, BSI-Grundschutz) und konkretem Exploit-Szenario aus der betrieblichen Praxis zu jedem Befund (45 Enrichment-Regeln)
- **nmap** (v7.95) Service-Version-Detection mit -sV und **nuclei** (v3.7) für aktive CVE-Exploit-Verification
- **Aggressive Tests** (optional) mit WAF-Detection, Payload-Block-Threshold und Rate-Limit-Prüfung

Ein Scan dauert **15–45 Sekunden** (Normal) bzw. **2–5 Minuten** (Deep-Scan).

---

## Scanner-Architektur

```
                               ┌─────────────────────────────┐
                               │    Step 1: Passive OSINT     │
                               │    + Active Lightweight      │
                               └──────────┬──────────────────┘
                                          │
      ┌───────────┬───────────┬───────────┼───────────┬───────────┬───────────┐
      ▼           ▼           ▼           ▼           ▼           ▼           ▼
   ┌──────┐  ┌──────┐  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────┐ ┌──────────┐
   │ DNS  │  │Email │  │ Web/TLS  │ │ Network  │ │Healthcare│ │DSGVO │ │Metadaten │
   │      │  │Auth  │  │ Headers  │ │ Exposure │ │ KIM/TI   │ │      │ │PDF/Image │
   └──┬───┘  └──┬───┘  └──┬───────┘ └──┬───────┘ └──┬───────┘ └──┬───┘ └──┬───────┘
      │         │         │            │            │            │         │
      └─────────┴─────────┴────────────┼────────────┴────────────┴─────────┘
                                       ▼
                            ┌──────────────────────┐
                            │  Tech Fingerprint    │
                            │  + NVD CVE Lookup    │
                            │  + CISA KEV + EPSS   │
                            └──────────┬───────────┘
                                       │
                          ┌────────────┴────────────┐
                          ▼                         ▼
                 ┌─────────────────┐      ┌─────────────────┐
                 │  Deep Scan      │      │  Step-2 Analyse  │
                 │  (11 Module)    │      │  (6 Module)      │
                 │  Optional       │      │  Immer aktiv     │
                 └─────────────────┘      └─────────────────┘
                          │                         │
                          └────────────┬────────────┘
                                       ▼
                            ┌──────────────────────┐
                            │  Dashboard + PDF     │
                            │  KBV-Compliance      │
                            │  Risk Score A+ – F   │
                            └──────────────────────┘
```

---

## Geprüfte Schwachstellen im Detail

### 1. DNS & Namensauflösung
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| A/AAAA/MX/NS/CAA Records | Fehlende CAA Records erlauben beliebigen CAs Zertifikatsausstellung | LOW |
| DNS Zone Transfer (AXFR) | Fehlkonfigurierter NS liefert gesamte Zone aus | CRITICAL |
| DNS Rebinding | Subdomain zeigt auf private IP → SSRF aus dem Browser | HIGH |
| SPF Include Chain | Expired Include-Domain → SPF-Takeover → E-Mail-Spoofing | CRITICAL |

### 2. E-Mail-Sicherheit
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| SPF Record | Fehlend/zu permissiv (+all) → E-Mail-Spoofing | HIGH–CRITICAL |
| DMARC Record + Policy | Fehlend oder p=none → kein aktiver Phishing-Schutz | HIGH–MEDIUM |
| DKIM Selektor-Brute (18 Selektoren) | Kein DKIM → DMARC wirkungslos | HIGH |
| MTA-STS + Policy-Datei | Fehlend → STARTTLS-Downgrade möglich | MEDIUM |
| TLS-RPT | Fehlend → TLS-Fehler bleiben unsichtbar | LOW |
| Mail-Provider-Detection (16 Provider) | M365/Google-spezifische Härtungsempfehlungen | INFO |

### 3. Web / TLS / HTTP
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| HTTPS-Erreichbarkeit | Kein HTTPS → gesamter Traffic abfangbar | HIGH |
| HTTP→HTTPS Redirect | Fehlt → Downgrade-Angriff | MEDIUM |
| SSL Labs Deep Grade (A+ bis F) | Schwache Cipher/Protokolle | MEDIUM–CRITICAL |
| TLS-Zertifikat Ablauf | Abgelaufen/bald ablaufend | HIGH–CRITICAL |
| Legacy-Protokolle (TLSv1, SSLv3) | Kryptographisch gebrochen | HIGH |
| HSTS Header | Fehlt → Browser akzeptiert HTTP-Downgrade | MEDIUM |
| CSP Header | Fehlt → XSS-Schutz reduziert | MEDIUM |
| X-Frame-Options | Fehlt → Clickjacking | LOW |
| X-Content-Type-Options | Fehlt → MIME Sniffing | LOW |
| Referrer-Policy | Fehlt → Referrer-Leak | INFO |
| Permissions-Policy | Fehlt → Browser-Feature-Missbrauch | INFO |
| Cookie-Flags (Secure/HttpOnly/SameSite) | Fehlende Flags → XSS/CSRF/MITM-Risiko | MEDIUM |

### 4. CMS & WordPress
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| WordPress-Version-Detection | Version offengelegt → gezielter Exploit | LOW |
| Plugin-Enumeration (HTML ?ver= Parsing) | Veraltete Plugins = #1 Breach-Ursache | variiert |
| 17 Known-Bad-Plugin-Heuristiken | CVE-2020-25213 (wp-file-manager RCE), CVE-2023-3460 (Ultimate Member), CVE-2023-6875 (Really Simple SSL) u.v.m. | CRITICAL–HIGH |
| User-Enumeration (/wp-json/wp/v2/users) | Login-Namen öffentlich → Brute-Force-Vorstufe | HIGH |
| Author-Enumeration (/?author=1..3) | Login-Namen via Redirect-Chase | MEDIUM |
| xmlrpc.php Erreichbarkeit | Brute-Force-Amplifier via system.multicall | MEDIUM |
| readme.html Leak | WordPress-Version in Klartext | LOW |
| WP-Exploit-Path-Verification (Step-2) | Spezifische CVE-Exploit-Pfade aktiv proben | CRITICAL–HIGH |
| Drupal / TYPO3 / Joomla Detection | CMS + Version, Hinweis auf Security Advisories | INFO |

### 5. Network Exposure & Ports
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| Active Port Scan (16 TCP-Ports) | RDP/SMB/Telnet/VNC öffentlich → Kompromittierungsindikator | CRITICAL |
| Shodan Host Lookup | Offene Ports/Dienste aus cached Internet-Scans | HIGH–CRITICAL |
| Banner Grab (SSH/FTP/SMTP/MySQL/IIS/nginx) | Versions-Offenlegung → gezielter CVE-Match | LOW |
| VPN-Endpoint-Detection (17 Pfade) | Fortinet/Palo Alto/Pulse/F5/Cisco/Citrix/SonicWall/Check Point/WatchGuard mit bekannten Pre-Auth-Zero-Days | HIGH |
| Subdomain-Enumeration (crt.sh) | Vergessene Subdomains vergrößern Angriffsfläche | INFO |
| Subdomain-Walker (60+ Sensitive Keywords) | staging/admin/phpmyadmin/grafana/konnektor/kim/medistar... | CRITICAL–INFO |
| Subdomain-Deep-Scan (Headers + TLS pro Sub) | Fehlende Security-Header auf Subdomains | MEDIUM |
| Subdomain-Takeover (30 Services) | Dangling CNAME → GitHub Pages/S3/Heroku/Azure/Shopify claimable | CRITICAL |
| TLS SAN Expansion (Step-2) | Versteckte Domains aus Zertifikat-SANs | MEDIUM |

### 6. Exposed Files & Directories
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| 38 Sensitive-Path-Probes | .git, .env, .env.bak, wp-config.php.bak, backup.zip/sql, id_rsa, .htpasswd, phpinfo, phpMyAdmin, Adminer | CRITICAL–LOW |
| Directory Fuzzing (170 Pfade) | Admin-Panels, API-Docs, Debug-Endpoints, Dev-Stages | variiert |
| SPA-Catch-All-Defense | Baseline-Hash + Längen-Fallback eliminiert False Positives | — |
| security.txt Check | /.well-known/security.txt fehlt → kein Meldeweg für Forscher | LOW |

### 7. Healthcare-spezifisch
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| KIM-DNS (SRV, A-Records) | KIM-Infrastruktur-Detection (Positiv-Signal) | INFO |
| TI-Konnektor-Web-UI (10 Pfade) | SecuNET/KoCoBox/CGM/RISE aus dem Internet erreichbar | CRITICAL |
| PVS-Fingerprint (22 Marken) | TurboMed/MEDISTAR/Albis/CGM/x.isynet/Tomedo/duria/Dampsoft/QUINCY + Doctolib/Samedi/Jameda/Clickdoc/RED connect | INFO |
| Patient-Portal/API-Pfade (17 Pfade) | /patienten, /befunde, /rezept, /api/patients, /api/medical | CRITICAL–INFO |
| KIM-Provider-Detection | CGM/Arvato/medatixx/Telekom KIM-Provider via MX | INFO |

### 8. DSGVO / Datenschutz
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| Tracker-Detection (14 Signaturen) | Google Analytics/GTM, Meta Pixel, Google Ads, Hotjar, Clarity, TikTok, LinkedIn ohne Consent = DSGVO-Verstoß | HIGH |
| Impressum-TMG-Validierung | §5 DDG: Anschrift, Telefon, E-Mail, Ärztekammer, Berufsbezeichnung | HIGH–MEDIUM |
| Cookie-JWT-Forensik | alg=none (CRITICAL), langlebige Tokens, Klartext-PII-Claims | CRITICAL–LOW |
| PDF-Metadaten Author-Leak | Klarnamen in öffentlichen PDFs (DSGVO Art. 5) | MEDIUM |
| Bild-EXIF GPS-Leak | GPS-Koordinaten in Bildern (Standort-Leak, Doxxing-Risiko) | HIGH |
| Bild-EXIF Personal | Artist/CameraOwnerName in Bildern | MEDIUM |

### 9. CVE / Vulnerability Intelligence
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| Tech-Fingerprint → CPE → NVD | Versionserkennung für nginx, Apache, OpenSSH, MariaDB, MySQL, IIS, FTP-Server, WordPress, Drupal, TYPO3, Joomla + 16 WP-Plugins | variiert |
| CISA KEV Enrichment | In der KEV-Liste = aktiv ausgenutzt → automatisch CRITICAL | CRITICAL |
| EPSS Scoring | Exploit-Wahrscheinlichkeit innerhalb 30 Tagen → Severity-Boost | — |
| False-Positive-Filter | CVEs vor 2019 werden ignoriert (außer in KEV) | — |
| Redis-Cache (24h) | NVD-Responses werden gecacht → Repeat-Scans sind instant | — |

### 10. Firewall / WAF (Aggressive Tests, optional)
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| WAF-Vendor-Detection (18 Fingerprints) | Cloudflare, AWS WAF, ModSecurity, Sucuri, Imperva, F5, Akamai, Barracuda, DenyAll, Plesk | INFO |
| Payload-Block-Threshold | 9 Canary-Payloads (SQLi, XSS, Path Traversal, RFI, Cmd Injection, Log4j) — wie viele blockt die WAF? | HIGH–INFO |
| Rate-Limit-Test (15 Rapid-Fire Requests) | Login-/API-Endpunkte ohne HTTP 429 → Brute-Force möglich | HIGH |

### 11. nmap Service-Detection
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| nmap -sT -sV --top-ports 100 | Exakte Service-Identifikation via Protokoll-Probing (besser als Banner-Grab) | INFO |
| Versions-Feed ins CVE-Matching | Jede erkannte Version → NVD/KEV/EPSS automatisch | variiert |

### 12. Deep Scan (13 Module, optional)
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| DNS Zone Transfer (AXFR) | Gesamte Zone auslesbar | CRITICAL |
| Wayback Machine Historie | Vergessene SQL-Dumps/Backups/Configs noch live | HIGH |
| GraphQL Introspection | Schema + Mutations öffentlich → komplette API-Struktur geleakt | HIGH–MEDIUM |
| OpenAPI/Swagger Spec | API-Spezifikation öffentlich → Endpoint-Enumeration | HIGH–MEDIUM |
| Host-Header-Injection | Password-Reset-Poisoning via manipuliertem Host/X-Forwarded-Host | HIGH–MEDIUM |
| Mixed Content | HTTP-Ressourcen auf HTTPS-Seite (Scripts = HIGH, Bilder = LOW) | HIGH–LOW |
| Open Redirect (20 Parameter) | url/next/redirect/goto → Phishing via vertrauenswürdiger Domain | HIGH |
| HTTP-Methods (TRACE/PUT/DELETE) | XST, unautorisierte Uploads/Löschungen | HIGH–MEDIUM |
| Active CORS Test | Reflected Origin, null Origin, Wildcard + Credentials | CRITICAL–HIGH |
| JS-File Secret Scanner | AWS Keys, Stripe Live Keys, GitHub Tokens, Private Keys in JS-Bundles | CRITICAL–LOW |
| Directory Fuzzing (170 Pfade) | Admin-Panels, Debug-Endpoints, versteckte Dienste | variiert |

### 11. Step-2 Analyse (6 Module, automatisch)
| Check | Schwachstelle | Severity |
|-------|---------------|----------|
| TLS SAN Expansion | Unbekannte Domains aus Zertifikat-SANs → versteckte Angriffsfläche | MEDIUM |
| Subdomain-Takeover | Dangling CNAME zu 30 Services (S3, GitHub, Heroku, Azure, Shopify, Netlify, Vercel...) | CRITICAL |
| DNS Rebinding | Hostname zeigt auf private IP → SSRF/Interner-Zugriff | HIGH |
| API Auth Test | JS/OpenAPI/Healthcare-Endpoints ohne Auth → IDOR/Broken Access Control | CRITICAL–MEDIUM |
| SPF Chain Analysis | Expired Include-Domain → E-Mail-Spoofing via SPF-Takeover | CRITICAL |
| WP Exploit Verification | Bekannte CVE-Exploit-Pfade aktiv bestätigen (elFinder RCE etc.) | CRITICAL–HIGH |

---

## API-Integrationen

| API | Typ | Key nötig? | Was wir nutzen |
|-----|-----|------------|----------------|
| **SSL Labs v3** | TLS Deep Grade | Nein | A+ bis F Bewertung, Cipher/Protokoll-Details |
| **NVD (NIST)** | CVE-Datenbank | Optional (höheres Rate-Limit) | CPE → CVE-Lookup für jede erkannte Software-Version |
| **CISA KEV** | Known-Exploited-Vuln | Nein | "Aktiv ausgenutzt"-Flag → automatisch CRITICAL |
| **EPSS (FIRST.org)** | Exploit-Wahrscheinlichkeit | Nein | Severity-Boost bei >50% Exploit-Chance |
| **crt.sh** | Certificate Transparency | Nein | Subdomain-Enumeration via CT-Logs |
| **Shodan** | Internet-Scan-Datenbank | Ja (Dev $49) | Offene Ports/Dienste/Banner cached |
| **LeakCheck.io** | Credential-Leak-Check | Ja (Public API Key) | E-Mail-Adressen gegen Breach-Datenbank prüfen |
| **AbuseIPDB** | IP-Reputation | Ja (Free 1k/Tag) | Blacklist-Check eigener IPs |
| **AlienVault OTX** | Threat Intel | Ja (Free) | Domain/IP in Threat-Kampagnen gelistet? |
| **SecurityTrails** | DNS History | Ja (Free 50/Monat) | Alte DNS-Records → vergessene Infrastruktur |
| **VirusTotal** | Domain Reputation | Ja (Free 500/Tag) | Domain/IP als Malware-Host geflaggt? |
| **Hunter.io** | E-Mail-OSINT | Ja (Free 25/Monat) | E-Mail-Pattern-Discovery für Domains |

---

## Tech Stack

| Schicht | Technologie |
|---------|-------------|
| **Backend** | Python 3.12, FastAPI, SQLAlchemy 2.0 (async), Pydantic |
| **Worker** | RQ (Redis Queue), synchroner Worker-Prozess |
| **Datenbank** | PostgreSQL 16, Redis 7 |
| **Frontend** | Jinja2, HTMX 2.0, Tailwind CSS (CDN) |
| **PDF-Report** | WeasyPrint (A4, 9 Kapitel, Deckblatt, Inhaltsverzeichnis) |
| **Auth** | bcrypt, Starlette SessionMiddleware, signed cookie |
| **Security Tools** | nmap 7.95 (Service Detection), nuclei 3.7 (CVE Templates) |
| **Deploy** | Docker Compose, GitHub Actions → GHCR → SSH Deploy |
| **TLS** | nginx Reverse-Proxy, Let's Encrypt / certbot |

---

## Quick Start

```bash
git clone https://github.com/lucasterix/insitution_scan.git
cd insitution_scan
docker compose up --build
```

App läuft auf **http://localhost:8000**. Beim ersten Aufruf wird ein Admin-Account angelegt.

### Optionale API Keys (.env)

```env
SHODAN_API_KEY=...          # Shodan Dev Plan ($49 lifetime)
LEAKCHECK_API_KEY=...       # LeakCheck.io Public API Key
OTX_API_KEY=...             # AlienVault OTX (free)
ABUSEIPDB_API_KEY=...       # AbuseIPDB (free, 1k/day)
NVD_API_KEY=...             # NVD (free, höheres Rate-Limit)
SECURITYTRAILS_API_KEY=...  # SecurityTrails (free, 50/month)
VIRUSTOTAL_API_KEY=...      # VirusTotal (free, 500/day)
HUNTER_API_KEY=...          # Hunter.io (free, 25/month)
```

---

## Projektstruktur

```
app/
├── main.py                     # FastAPI + Auth-Middleware + Lifespan
├── auth.py                     # bcrypt + Session-Helpers
├── config.py                   # Pydantic Settings (env vars)
├── db.py                       # Async SQLAlchemy + Auto-Migration
├── models.py                   # User + Scan (deep_scan, ownership_confirmed, context)
├── queue.py / worker.py        # RQ Redis Queue + Worker
├── tasks.py                    # Scan-Job-Orchestrierung
├── compliance/
│   ├── analysis.py             # KBV §390 SGB V Compliance-Score
│   ├── dashboard.py            # Risk Score (A+ – F), Category Grouping
│   └── kbv_mapping.py          # 18 Anforderungen → Finding-ID-Mapping
├── integrations/               # 10 Third-Party API Clients
├── scanners/
│   ├── osint.py                # Master-Pipeline (38 Module orchestriert)
│   ├── banner_grab.py          # Service-Version aus Port-Bannern
│   ├── cms_scan.py             # WordPress/Drupal/TYPO3/Joomla
│   ├── cookie_forensics.py     # JWT-Decode, alg=none, PII-Claims
│   ├── email_auth_deep.py      # DKIM/MTA-STS/TLS-RPT
│   ├── email_harvest.py        # E-Mail-Adressen + LeakCheck
│   ├── exposed_files.py        # 38 Sensitive Paths + SPA-Defense
│   ├── healthcare.py           # KIM/TI-Konnektor/PVS/Patient-APIs
│   ├── image_metadata.py       # EXIF GPS + Personal (Pillow)
│   ├── mail_provider.py        # M365/Google/IONOS/KIM-Provider
│   ├── pdf_metadata.py         # Author/Creator via pypdf
│   ├── port_scan.py            # 16 TCP-Ports aktiv
│   ├── privacy.py              # Tracker/Cookies/Impressum-TMG
│   ├── site_crawler.py         # BFS 40 Pages, sammelt alle URLs
│   ├── subdomain_deep.py       # Headers+TLS pro alive Sub
│   ├── subdomain_walker.py     # 60+ Keywords (inkl. Healthcare)
│   ├── tech_fingerprint.py     # Server/Generator/jQuery/Bootstrap
│   ├── vpn_endpoints.py        # 17 VPN-Login-Pfade + CVE-Referenzen
│   ├── vuln.py                 # CPE→NVD→KEV→EPSS (30+ CPE-Mappings)
│   ├── deep/                   # 11 Deep-Scan-Module (optional)
│   │   ├── active_cors.py
│   │   ├── directory_fuzz.py
│   │   ├── graphql_introspection.py
│   │   ├── host_header_injection.py
│   │   ├── http_methods.py
│   │   ├── js_secrets.py
│   │   ├── mixed_content.py
│   │   ├── open_redirect.py
│   │   ├── openapi_parser.py
│   │   ├── wayback.py
│   │   └── zone_transfer.py
│   └── step2/                  # 6 Step-2-Analyse-Module (automatisch)
│       ├── api_auth_test.py
│       ├── dns_rebinding.py
│       ├── spf_chain.py
│       ├── subdomain_takeover.py
│       ├── tls_san_expansion.py
│       └── wp_exploit_verify.py
├── routers/
│   ├── auth.py                 # Login/Logout/Setup
│   ├── pages.py                # Dashboard, Scan-Detail, PDF-Export
│   └── api.py                  # JSON API
└── templates/
    ├── base.html               # Sticky-Nav, User-Dropdown
    ├── index.html              # Landing: Hero + Feature-Grid + Scans
    ├── login.html / setup.html
    ├── scan_new.html           # Consent-Gate + Deep-Scan-Toggle
    ├── scan_detail.html        # Dashboard-Shell
    ├── report_pdf.html         # 9-Kapitel-PDF (Cover, TOC, Legal, ...)
    └── partials/
        └── scan_status.html    # HTMX-Polling Dashboard
```

---

## PDF-Report-Struktur

Der generierte Prüfbericht folgt den rechtlichen Anforderungen für den deutschen Gesundheitssektor:

| Kapitel | Inhalt |
|---------|--------|
| **Deckblatt** | Institution, Domain, Scan-Zeitpunkt, Gesamt-Grade (A+ – F) |
| **1. Management-Zusammenfassung** | KPI-Grid (Critical/High/Medium/Low/Info), Top-5-Risiken, KBV-Score |
| **2. Rechtliche Grundlagen** | §390 SGB V, DSGVO Art. 32, §203 StGB, §5 DDG, HWG, BSI-Grundschutz, gematik |
| **3. Methodik** | Tabelle aller 11 Prüfbereiche mit Verfahrensbeschreibung |
| **4. Risikoprofil** | Gewichteter Score, Severity-Verteilung, Befunde nach Bereich |
| **5. KBV-Compliance** | 18 Anforderungen aus Anlage 1–5, per-Anlage ✓/✗ mit Erklärung |
| **6. Metadaten-Leaks** | PDF-/Bild-Evidenztabellen mit URL + Feld + Wert (nur bei Fund) |
| **7. Detailbefunde** | Alle Findings nach Schweregrad sortiert, mit Empfehlung + KBV-Ref |
| **8. Technischer Anhang** | JSON-Rohdaten aller Scanner |
| **9. Haftungsausschluss** | White-Hat, kein Ersatz für Pentest, Zuordnung ist Näherung |

---

## Deployment (Produktion)

Das Projekt deployed automatisch bei Push auf `main`:

```
Push → GitHub Actions → Docker Buildx → GHCR Image → SSH auf Hetzner → docker compose up
```

**Secrets** (bereits konfiguriert): `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_PORT`, `DEPLOY_SSH_KEY`

**Server**: Ubuntu 24.04 auf Hetzner Cloud, nginx Reverse-Proxy, Let's Encrypt TLS, `/opt/institutionscan/`

---

## Scan-Pipeline (Reihenfolge)

```
Homepage Pre-Fetch (shared HTML) → DNS → Mail-Provider → SPF/DMARC →
DKIM/MTA-STS/TLS-RPT → Site-Crawler (BFS 40 Pages) → Privacy/Tracker/Impressum →
Healthcare (KIM/TI/PVS) → HTTP/Headers → TLS → SSL Labs → crt.sh (cached) →
Subdomain-Walker → Subdomain-Deep-Scan → IP-Intel (Shodan/AbuseIPDB/OTX) →
Exposed Files → Port-Scan → Banner-Grab → VPN-Endpoints → Cookie-Forensik →
robots.txt → CMS/WordPress → Tech-Fingerprint → E-Mail-Harvest + LeakCheck →

[Deep Scan: Zone-Transfer → Wayback → GraphQL → OpenAPI → Host-Header →
 Mixed-Content → Open-Redirect → HTTP-Methods → CORS → JS-Secrets → Dir-Fuzz] →

PDF-Metadaten → Bild-EXIF → NVD/KEV/EPSS CVE-Lookup →

Step-2: TLS-SAN → Subdomain-Takeover → DNS-Rebinding → SPF-Chain →
        API-Auth-Test → WP-Exploit-Verification
```

---

## KBV-Compliance-Mapping

18 automatisiert prüfbare Anforderungen aus den KBV-Anlagen 1–5:

| Anlage | Code | Anforderung |
|--------|------|-------------|
| 1 | A1.1 | SPF/DMARC aktiv |
| 1 | A1.2 | HTTPS + Redirect |
| 1 | A1.3 | TLS-Zertifikat gültig |
| 1 | A1.4 | Keine sensiblen Dateien exponiert |
| 1 | A1.5 | Keine Klarnamen in PDF-Metadaten |
| 1 | A1.6 | Vollständiges TMG-Impressum |
| 1 | A1.7 | Keine GPS-/Personen-EXIF in Bildern |
| 2 | A2.1 | DMARC Policy aktiv (nicht none) |
| 2 | A2.2 | Security Headers (HSTS, CSP, X-Frame) |
| 2 | A2.3 | Keine Server-Version-Offenlegung |
| 2 | A2.4 | DKIM konfiguriert |
| 2 | A2.5 | MTA-STS aktiv |
| 2 | A2.6 | Keine Tracker ohne Consent |
| 2 | A2.7 | Cookie-Security-Flags |
| 3 | A3.1–3.2 | Kein RDP/SMB/DB aus dem Internet |
| 3 | A3.3 | CAA Record |
| 3 | A3.4 | Keine Blacklist-Einträge |
| 3 | A3.5 | SSL Labs Grade ≥ B |
| 3 | A3.6 | Keine bekannten CVEs |
| 3 | A3.7 | Keine sensiblen Subdomains |
| 3 | A3.8 | Keine kritischen Ports offen |
| 4 | A4.1 | TI-Konnektor nicht aus Internet erreichbar |
| 4 | A4.2 | Keine unauthentisierten Patient-APIs |
| 5 | A5.1 | TI/KIM-Infrastruktur korrekt |

---

## Roadmap

- [x] **Nuclei Integration** — CVE/WordPress/Default-Login/Misconfig Templates
- [x] **nmap Integration** — Service Version Detection (-sV)
- [x] **WAF/Firewall-Test** — Payload-Block-Threshold + Rate-Limiting
- [x] **Finding-Enrichment** — 45 Regeln mit Rechtsgrundlage + Exploit-Beispiel
- [x] **Subdomain-Brute-Force** — 200-Wort DNS-Wordlist
- [x] **CSRF/MFA-Detection** — Form-Security-Scanner
- [x] **Forward-Secrecy-Check** — Lokale Cipher-Inspektion
- [ ] **Authentisierte Scans** — Login-Flow → Session-Replay → Behind-Auth-Testing
- [ ] **Scheduled Re-Scans** — rq-scheduler + Delta-Alerts bei neuem CRITICAL
- [ ] **Multi-Tenant** — Organisationen, Nutzer-Rollen, Scan-Ownership
- [ ] **OWASP ZAP Baseline** — Automatisierter Web-App-Scan als optionales Modul
- [ ] **Form-Fuzzing** — Input-Validation-Tests auf entdeckten Formularen
- [ ] **Subdomain-Screenshots** — Playwright/Chromium für visuelle Dokumentation
- [ ] **Ticket-Export** — Jira/GitLab-Integration für Remediation-Tracking

---

## Für Frontend-Entwickler

Der zweite Entwickler arbeitet an UX/UI. Wichtig:

- **Templates**: `app/templates/` — Jinja2 + HTMX + Tailwind CDN, kein JS-Bundler
- **Ohne Rückfrage änderbar**: Templates, Static Assets, neue UI-Seiten
- **Abstimmung nötig**: Datenbank-Schema, POST-Formulare, JSON-API, Scanner-Logik
- **Dev-Loop**: `docker compose up`, Template-Änderungen sofort sichtbar (Volume-Mount)

---

## Rechtliche Hinweise

- Nur auf eigenen Systemen einsetzen
- Schriftliche Freigabe des MVZ-Inhabers und Anwalts-Dokumentation vor produktivem Einsatz
- Consent-Gate (Pflicht-Checkbox) mit §202c-StGB-Warnung auf dem Scan-Formular
- Alle Scans werden mit Zeitstempel + Eigentümer-Bestätigung protokolliert
- Report dient der eigenen Absicherung und Verbesserung — keine rechtsverbindliche Bewertung
- Keine Haftung für unsachgemäße Nutzung

---

## License

MIT (mit Hinweis auf medizinische Nutzung)
