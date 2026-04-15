# MVZ Self-Security Scanner

**Ein Open-Source Self-Assessment Tool für Medizinische Versorgungszentren (MVZ).**
Automatisierte Prüfung auf gängige Sicherheitslücken, OSINT-Risiken und KBV-IT-Sicherheitsanforderungen.

- 🌐 **Live**: https://scan.zdkg.de
- 🐳 **Runtime**: FastAPI + HTMX, Postgres, Redis/RQ, Docker Compose
- 🚀 **CI/CD**: Push to `main` → GitHub Actions baut Image → GHCR → SSH-Deploy auf Hetzner
- ⚖️ **White-Hat only**: Nur eigene Domains, IPs und Systeme

---

## 🚀 Local Quick Start

Voraussetzung: Docker + Docker Compose.

```bash
git clone https://github.com/lucasterix/insitution_scan.git
cd insitution_scan
docker compose up --build
```

App läuft auf http://localhost:8000. Postgres, Redis und der RQ-Worker werden automatisch mitgestartet.

**Python-Tooling lokal ohne Docker** (optional, nur für Linting/Typchecking im Editor):

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## 🗂 Projektstruktur

```
.
├── app/
│   ├── main.py                  # FastAPI app + lifespan (init_db)
│   ├── config.py                # Pydantic Settings (env vars)
│   ├── db.py                    # Async SQLAlchemy engine & Base
│   ├── models.py                # Scan-Model (id, status, progress, result JSON)
│   ├── queue.py                 # RQ queue + Redis connection
│   ├── worker.py                # RQ worker entry point (`python -m app.worker`)
│   ├── tasks.py                 # run_scan_job – sync, läuft im Worker
│   ├── scanners/
│   │   ├── base.py              # Finding, Severity, ScanResult
│   │   └── osint.py             # DNS, SPF/DKIM/DMARC, Headers, TLS, Subdomains, robots.txt
│   ├── routers/
│   │   ├── pages.py             # HTML Routes (/, /scans/new, /scans/{id})
│   │   └── api.py               # JSON API (/api/scans, /api/scans/{id})
│   ├── templates/               # Jinja2 + HTMX (polling)
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── scan_new.html
│   │   ├── scan_detail.html
│   │   └── partials/
│   │       └── scan_status.html # wird alle 2s per HTMX gepollt
│   └── static/
│       └── app.css              # minimal, Tailwind kommt via CDN
├── deploy/
│   ├── docker-compose.prod.yml  # Production stack (zieht Image von GHCR)
│   ├── nginx/scan.zdkg.de.conf  # Reverse-Proxy + TLS (Referenz – aktiver Stand liegt auf dem Server)
│   └── scripts/deploy.sh        # wird per GHA auf dem Server ausgeführt
├── .github/workflows/deploy.yml # Build → GHCR → SSH deploy
├── Dockerfile
├── docker-compose.yml           # Dev-Stack (app + worker + postgres + redis)
└── requirements.txt
```

---

## 👥 Für den zweiten Entwickler (Frontend/UX)

Willkommen! Das Setup ist bewusst klein gehalten — **keine Node-Toolchain, kein Vite, kein Webpack**. Wir nutzen:

- **Jinja2** für Server-side Templates → alle HTML-Dateien liegen in [app/templates/](app/templates/)
- **HTMX** für interaktive Updates ohne SPA (z.B. das Live-Polling auf der Scan-Detail-Seite) — wird via CDN in [base.html](app/templates/base.html) geladen
- **Tailwind CSS** via CDN in [base.html](app/templates/base.html) — keine Build-Step nötig
- **Kein JS-Bundler**. Falls du Komponenten-Logik brauchst, bitte kurz mit mir (Daniel) abstimmen — wir können Alpine.js oder Hyperscript einfach per CDN ergänzen, müssen aber keine Vite-Pipeline einführen.

### Was du ohne Rückfrage anfassen darfst

- [app/templates/](app/templates/) — komplettes Redesign, Komponenten-Struktur, Dark-Mode, Barrierefreiheit
- [app/static/](app/static/) — CSS, Icons, Fonts, Logos, statische Assets
- Neue Routen für reine UI-Seiten (Landing Page, Doku, About) in [app/routers/pages.py](app/routers/pages.py)
- Tailwind-Config via `<script>`-Block im `<head>` von [base.html](app/templates/base.html) (siehe [Tailwind Play CDN config](https://tailwindcss.com/docs/installation/play-cdn#customizing))

### Was du bitte mit dem Backend-Teil abstimmst

- Änderungen an [app/models.py](app/models.py) (Datenbank-Schema)
- Änderungen an den POST-Formularen (Feld-Namen, Validierung) in [app/routers/pages.py](app/routers/pages.py)
- Änderungen an der JSON-API ([app/routers/api.py](app/routers/api.py)) — andere Integrationen hängen daran
- Änderungen an [app/scanners/](app/scanners/) (Scan-Logik)

### Relevante Seiten im aktuellen Stand

| Route | Template | Zweck |
|---|---|---|
| `GET /` | [index.html](app/templates/index.html) | Übersicht aller Scans |
| `GET /scans/new` | [scan_new.html](app/templates/scan_new.html) | Formular für neuen Scan |
| `POST /scans` | redirect | Scan anlegen + in Queue schieben |
| `GET /scans/{id}` | [scan_detail.html](app/templates/scan_detail.html) | Scan-Details + HTMX-Polling |
| `GET /scans/{id}/status` | [partials/scan_status.html](app/templates/partials/scan_status.html) | HTMX-Fragment (Progress + Findings) |
| `GET /healthz` | — | JSON health check |
| `GET /api/scans` | — | JSON-Liste aller Scans |
| `GET /api/scans/{id}` | — | JSON-Detail (für Export) |

### Severity-Farbsystem

Die Finding-Karten in [partials/scan_status.html](app/templates/partials/scan_status.html) nutzen fünf Stufen:

| Severity | Farbe (Tailwind) |
|---|---|
| `critical` | rose |
| `high` | orange |
| `medium` | amber |
| `low` | sky |
| `info` | slate |

Falls du die Palette änderst, bitte die `severity_counts`-Kacheln und die Finding-Karten konsistent halten.

### Dev-Loop

```bash
docker compose up           # erstes Mal: --build
```

- Template- und Static-Dateien werden via `./app:/app/app` gemountet → **Änderungen sind sofort per Reload sichtbar**.
- Python-Code-Änderungen: `docker compose restart app worker`.

**Dummy-Scan für UI-Arbeit**: Trag eine Domain ein, die du besitzt (z.B. `zdkg.de`). Der Scan läuft ~10–20 Sekunden und liefert realistische Daten fürs UI.

---

## 🛡 Funktionen & Module

### Aktuell implementiert (MVP)

**OSINT-Modul** ([app/scanners/osint.py](app/scanners/osint.py)):
- DNS Records (A, AAAA, MX, NS, CAA)
- E-Mail-Auth (SPF, DMARC) inkl. Policy-Bewertung
- HTTP/HTTPS-Reachability, HTTP→HTTPS-Redirect-Check
- Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- TLS-Zertifikat (Ablaufdatum, Protokoll-Version, Issuer)
- Subdomain-Enumeration via crt.sh
- robots.txt Leak-Check

### Geplant

Siehe Roadmap am Ende dieses Dokuments.

---

## 🧩 Infrastruktur

### Produktions-Deployment

- **Host**: Hetzner Cloud, Ubuntu 24.04
- **Reverse Proxy**: nginx auf dem Host → `127.0.0.1:8090` (app container)
- **TLS**: certbot/Let's Encrypt, Zertifikat unter `/etc/letsencrypt/live/scan.zdkg.de/`
- **Compose-Root auf dem Server**: `/opt/institutionscan/`
- **Datenvolumes**: `/opt/institutionscan/data/postgres`, `/opt/institutionscan/data/redis`

### GitHub Actions Pipeline ([.github/workflows/deploy.yml](.github/workflows/deploy.yml))

```
push to main
   │
   ▼
build: Docker Buildx → ghcr.io/lucasterix/insitution_scan:sha-<shorthash>
   │                                                       :main
   │                                                       :latest
   ▼
deploy: scp docker-compose.prod.yml + deploy.sh → /opt/institutionscan
        ssh + deploy.sh → docker compose pull → up -d
```

**Benötigte Repo-Secrets** (bereits gesetzt):
- `DEPLOY_HOST` — `188.245.172.75`
- `DEPLOY_USER` — `root`
- `DEPLOY_PORT` — `22`
- `DEPLOY_SSH_KEY` — ed25519 Private Key (dediziert für diesen Workflow)

### Manueller Deploy / Notbetrieb

```bash
# auf dem Server
cd /opt/institutionscan
./deploy.sh latest
docker compose -f docker-compose.prod.yml logs -f app
```

---

## 🗺 Roadmap

### 1. OSINT & Reconnaissance Modul ✅ MVP

### 2. E-Mail & Phishing Resilience Modul
- SPF/DKIM/DMARC Analyse + Policy-Bewertung ✅ teilweise
- Test auf Mailbox Forwarding Rules (Exchange/M365)
- Spoofing-Simulation (nur intern an eigene Test-Postfächer)

### 3. Credential & Access Control Modul
- Passwort-Policy Prüfung (AD + Linux)
- MFA-Status & Conditional Access Checks
- Password-Spraying & Brute-Force Detection Rules (Sigma)

### 4. Vulnerability & Patch Management Modul
- Authentifizierter Vulnerability Scan (OpenVAS/Greenbone)
- EOL-Software & OS-Erkennung
- CVE-Priorisierung via NVD + EPSS + CISA KEV

### 5. Network Exposure Modul
- Externe Port-Scans (nur eigene IPs, -T3)
- Offene Remote-Dienste (RDP, SSH, VPN, Admin-Panels)

### 6. Web Application Security Modul
- Passive ZAP Baseline Scan (OWASP ZAP)
- Retire.js für veraltete Bibliotheken

### 7. Configuration & Hardening Modul
- CIS Benchmark Vergleich
- Lynis Audits (Linux)

### 8. Backup & Ransomware Resilience Modul
- Backup-Policy Prüfung (Offline/Immutable)
- Detection Rules für Backup-Manipulation

### 9. Compliance Modul (KBV-spezifisch)
- Automatischer Abgleich mit KBV IT-Sicherheitscheckliste (Anlagen 1–5)
- DSGVO-relevante Funde
- PDF-Export mit Empfehlungen + Priorität

### Quer-Themen
- Multi-User + Login
- Periodische Re-Scans (Cron / Scheduler)
- PDF-Report-Export
- Dark Mode, i18n (DE/EN)

---

## ⚠️ Rechtliche Hinweise

- Nur auf eigenen Systemen einsetzen
- Schriftliche Freigabe des MVZ-Inhabers und Anwalts-Dokumentation vor jedem produktiven Einsatz
- Alle Tests müssen dokumentiert und freigegeben sein
- Report dient ausschließlich der eigenen Absicherung und Verbesserung
- Keine Haftung für unsachgemäße Nutzung

---

## 📜 License

MIT (mit Hinweis auf medizinische Nutzung)
