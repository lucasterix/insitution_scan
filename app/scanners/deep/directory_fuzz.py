"""Directory fuzzer with a curated wordlist.

Runs a 150-path wordlist against the target with SPA-catch-all defense.
Only reports paths that return 200/401/403 AND whose body differs from
the baseline /(and 404 probe).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import httpx

from app.scanners._baseline import fetch_baselines, is_catchall
from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
TIMEOUT = 4.0
MAX_WORKERS = 12

# Curated list — higher signal/noise ratio than SecLists raft-small.
WORDLIST = (
    "admin", "administrator", "admins", "wp-admin", "login", "signin", "signup", "register",
    "account", "accounts", "user", "users", "profile", "dashboard", "panel", "cp", "cpanel",
    "api", "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger", "swagger", "swagger-ui",
    "openapi", "graphql", "graphiql", "gql",
    "config", "conf", "configuration", "settings", "setup", "install", "installation",
    "backup", "backups", "bak", "old", "archive", "archives", "dump", "dumps",
    "db", "database", "sql", "mysql", "postgres", "mongo",
    "dev", "develop", "development", "stage", "staging", "test", "testing", "tests", "qa", "uat",
    "uploads", "upload", "files", "file", "download", "downloads", "media", "assets",
    "docs", "documentation", "help", "support",
    "status", "health", "healthz", "metrics", "prometheus", "grafana", "kibana", "elastic",
    "monitoring", "monitor", "stats", "statistics",
    "phpinfo", "info", "phpmyadmin", "pma", "adminer", "myadmin",
    "git", ".git", "svn", ".svn", "hg", ".hg",
    "logs", "log", "debug", "trace",
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
    "server-status", "server-info",
    "jenkins", "ci", "cd", "build", "deploy",
    "jira", "confluence", "wiki", "wikis",
    "webmin", "plesk",
    "ftp", "sftp", "mail", "webmail", "email", "exchange", "owa",
    "portal", "portals", "patient", "patients", "client", "clients", "customer",
    "internal", "intern", "private",
    "legacy", "old-site", "backup-site",
    "phpMyAdmin", "mysqladmin", "mongoadmin",
    "console", "manage", "management", "control",
    "crm", "erp", "hr",
    "auth", "oauth", "oauth2", "saml", "sso",
    "health-check", "ping",
    "tmp", "temp",
    "vendor", "node_modules",
    "assets/js", "assets/css", "static",
    "rss", "feed", "atom",
    "staging.html", "test.html",
    "index.bak", "index.old",
    "readme", "README",
)

# Paths that, if reachable AND not catch-all, are genuinely interesting.
# Each entry: (severity, explanation of WHY this is dangerous + HOW an attacker exploits it)
FINDING_DETAILS: dict[str, tuple[Severity, str, str]] = {
    "phpmyadmin": (Severity.HIGH,
        "phpMyAdmin ist eine Web-basierte MySQL-Verwaltung. Ein Angreifer kann mit Default-Credentials (root/leer) oder Brute-Force die komplette Datenbank lesen, ändern und exportieren — inklusive Patientendaten, Passwort-Hashes und Abrechnungsdaten.",
        "phpMyAdmin hinter VPN stellen oder komplett entfernen. Zugriff nur über SSH-Tunnel."),
    "pma": (Severity.HIGH,
        "Kurzform-URL für phpMyAdmin. Gleiche Risiken wie /phpmyadmin/.",
        "Entfernen oder hinter Auth/VPN."),
    "adminer": (Severity.HIGH,
        "Adminer ist ein Ein-Datei-Datenbank-Manager. Oft absichtlich für 'schnellen Zugriff' hochgeladen und dann vergessen. Angreifer können sich direkt mit der Datenbank verbinden.",
        "adminer.php vom Server löschen."),
    "phpinfo": (Severity.HIGH,
        "phpinfo() zeigt die komplette PHP-Konfiguration: installierte Module, Dateipfade, Environment-Variablen (oft mit Passwörtern), disabled_functions (zeigt welche Angriffsvektoren offen sind). Ein Angreifer nutzt diese Informationen um gezielte Exploits vorzubereiten.",
        "phpinfo.php und info.php sofort löschen."),
    ".git": (Severity.CRITICAL,
        "Das .git-Verzeichnis enthält den KOMPLETTEN Quellcode + die gesamte Commit-Historie. Ein Angreifer kann mit 'git-dumper' das Repository rekonstruieren und findet darin: Datenbank-Passwörter in Config-Dateien, API-Keys in alten Commits, interne Dokumentation, und den vollständigen Code zur Schwachstellenanalyse. Das ist eines der häufigsten kritischen Findings bei Webseiten.",
        "Webserver-Konfiguration: Zugriff auf .git/ blockieren (nginx: location ~ /\\.git { deny all; })."),
    ".svn": (Severity.HIGH,
        "Subversion-Repository exponiert. Wie .git, aber für SVN — enthält Quellcode, Konfigurationsdateien und kann Credentials in der Historie haben.",
        "Zugriff auf .svn/ in der Webserver-Config blockieren."),
    ".hg": (Severity.HIGH,
        "Mercurial-Repository exponiert. Gleiche Risiken wie .git — vollständiger Quellcode + Historie rekonstruierbar.",
        "Zugriff auf .hg/ blockieren."),
    "graphql": (Severity.MEDIUM,
        "GraphQL-Endpoint gefunden. Wenn Introspection aktiviert ist (separat geprüft), kann ein Angreifer die gesamte API-Struktur einsehen und gezielt nach unsicheren Queries/Mutations suchen.",
        "Introspection in der Produktion deaktivieren."),
    "graphiql": (Severity.HIGH,
        "GraphiQL ist eine interaktive GraphQL-IDE im Browser. Ein Angreifer kann ohne weitere Tools direkt Queries ausführen, das Schema erkunden und Daten extrahieren — alles über die komfortable Browser-Oberfläche.",
        "GraphiQL in der Produktion komplett deaktivieren."),
    "swagger": (Severity.MEDIUM,
        "Swagger-UI macht die API-Dokumentation interaktiv. Ein Angreifer sieht jeden Endpoint, jeden Parameter, jedes Datenmodell — und kann Requests direkt aus der UI senden. Das ist wie eine Bedienungsanleitung für den Angriff.",
        "Swagger-UI in Production deaktivieren (FastAPI: docs_url=None)."),
    "swagger-ui": (Severity.MEDIUM,
        "Swagger-UI Endpoint (alternative Schreibweise). Gleiche Risiken.",
        "In Production deaktivieren."),
    "openapi": (Severity.MEDIUM,
        "OpenAPI-Spezifikation als JSON. Maschinenlesbare API-Dokumentation die direkt in Angriffs-Tools (Postman, Burp, Nuclei) importiert werden kann.",
        "openapi.json in Production nicht öffentlich ausliefern."),
    "grafana": (Severity.HIGH,
        "Grafana Monitoring-Dashboard. Zeigt oft sensible Metriken (Server-Last, Datenbankabfragen, Error-Logs). Default-Credentials: admin/admin. Mit Admin-Zugriff können Data-Sources (Datenbank-Verbindungen) ausgelesen werden — inklusive der darin gespeicherten Passwörter.",
        "Hinter VPN/Auth stellen. Default-Passwort sofort ändern."),
    "kibana": (Severity.HIGH,
        "Kibana ist das Web-Frontend für Elasticsearch. Ohne Authentifizierung kann ein Angreifer alle indexierten Daten durchsuchen — Logs, E-Mails, Patientendaten, je nachdem was in Elasticsearch gespeichert ist.",
        "X-Pack Security oder OpenSearch Security aktivieren. Kibana hinter VPN."),
    "jenkins": (Severity.HIGH,
        "Jenkins CI/CD-Server. Ohne Auth kann ein Angreifer: Build-Logs mit Credentials lesen, neue Build-Jobs anlegen die Shell-Commands ausführen, oder über die Script-Konsole (/script) direkt Groovy-Code auf dem Server ausführen = Remote Code Execution.",
        "Jenkins per Auth schützen (Matrix Authorization) und nicht öffentlich erreichbar machen."),
    "webmin": (Severity.HIGH,
        "Webmin Server-Administration. Bietet eine Web-GUI für Root-Level-Serververwaltung: Dateien bearbeiten, Services starten/stoppen, Benutzer anlegen, Firewall-Regeln ändern. Ein Angreifer mit Zugriff hat de facto Root.",
        "Webmin nur über localhost/VPN erreichbar machen."),
    "plesk": (Severity.HIGH,
        "Plesk Hosting-Panel. Verwaltet Websites, E-Mail-Konten, Datenbanken und DNS für den gesamten Server. Admin-Zugriff = vollständige Kontrolle über alle gehosteten Domains.",
        "Plesk-Port (8443) per Firewall auf Admin-IPs beschränken."),
    "cpanel": (Severity.HIGH,
        "cPanel Hosting-Panel. Wie Plesk — verwaltet den gesamten Hosting-Stack. Brute-Force auf den Login ist trivial wenn kein fail2ban aktiv ist.",
        "cPanel nur über VPN/IP-Whitelist erreichbar machen."),
    "server-status": (Severity.MEDIUM,
        "Apache mod_status zeigt: aktive Verbindungen, angefragte URLs (inklusive Query-Parameter mit Session-Tokens!), Client-IPs, Request-Dauer. Ein Angreifer kann Session-IDs aus den URLs abfangen und Sessions übernehmen.",
        "mod_status deaktivieren oder auf localhost beschränken."),
    "server-info": (Severity.MEDIUM,
        "Apache mod_info zeigt die komplette Server-Konfiguration: alle geladenen Module, Dateipfade, VirtualHosts. Ein Angreifer erfährt exakt welche Module installiert sind und kann gezielt nach Schwachstellen in diesen Modulen suchen.",
        "mod_info deaktivieren."),
}


def _probe(client: httpx.Client, base: str, word: str) -> dict | None:
    url = f"{base}/{word}"
    try:
        r = client.get(url)
    except httpx.HTTPError:
        return None
    if r.status_code in (401, 403):
        return {"path": f"/{word}", "status": r.status_code, "body": "", "ct": r.headers.get("content-type", "")}
    if r.status_code != 200:
        return None
    # Pass the full text so baseline defense can compare against the full
    # homepage fingerprint (SPAs return identical bodies across paths).
    ct = r.headers.get("content-type", "").lower()
    body = r.text if "text" in ct or "json" in ct or not ct else ""
    return {"path": f"/{word}", "status": r.status_code, "body": body, "ct": ct}


def _has_generic_4xx_blanket(client: httpx.Client, base: str) -> set[int]:
    """Detect if the server returns 401/403 for ALL unknown paths.

    Many WAFs (Cloudflare, Sucuri, ModSecurity, SiteGround Security) return
    a blanket 403 for anything they don't recognize. In that mode every
    dir-fuzz wordlist entry hits 403 — regardless of whether phpMyAdmin,
    Jenkins, Grafana etc. actually exist on the server. Emitting dozens
    of "admin panel existiert" findings is then pure noise.

    We probe two different guaranteed-nonexistent paths. Any 4xx status
    that both return identically is treated as a blanket response; later
    we discard all dir-fuzz hits in that status class.
    """
    import hashlib
    probe_a = f"/__mvzscan_nonexistent_{hashlib.md5(base.encode()).hexdigest()[:10]}__"
    probe_b = f"/__mvzscan_random_{hashlib.md5((base + 'x').encode()).hexdigest()[:10]}__"
    blanket: set[int] = set()
    for path in (probe_a, probe_b):
        try:
            r = client.get(f"{base}{path}")
            if r.status_code in (401, 403):
                blanket.add(r.status_code)
        except httpx.HTTPError:
            continue
    return blanket


def check_directory_fuzz(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step(f"Directory Fuzz ({len(WORDLIST)} Pfade)", 74)

    baselines = fetch_baselines(domain)
    if not baselines:
        return

    base = f"https://{domain}"
    hits: list[dict] = []

    with httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        # Detect WAF/CMS blanket 4xx first.
        blanket_block = _has_generic_4xx_blanket(client, base)
        if blanket_block:
            result.metadata.setdefault("directory_fuzz_meta", {})["blanket_block"] = sorted(blanket_block)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = [ex.submit(_probe, client, base, w) for w in WORDLIST]
            for f in as_completed(futures):
                r = f.result()
                if r is None:
                    continue
                # Skip blanket-blocked 401/403 — the server blocks every
                # unknown path with this status, so a match proves nothing.
                if r["status"] in blanket_block:
                    continue
                # Skip catch-all 200 responses.
                body = r.get("body", "")
                if r["status"] == 200 and body and is_catchall(body, baselines):
                    continue
                hits.append(r)

    if not hits:
        return

    result.metadata["directory_fuzz"] = [
        {"path": h["path"], "status": h["status"], "ct": h.get("ct", "")}
        for h in hits
    ]

    # Emit a summary INFO finding with the full list.
    result.add(Finding(
        id="deep.directory_fuzz_summary",
        title=f"Directory-Fuzz fand {len(hits)} zusätzliche Pfade",
        description=(
            "Die nachfolgenden Pfade antworten mit 200/401/403 und unterscheiden sich vom "
            "SPA-Catch-All. Jeder dieser Pfade verdient einen manuellen Blick."
        ),
        severity=Severity.INFO,
        category="Deep Scan",
        evidence={"hits": [{"path": h["path"], "status": h["status"]} for h in hits]},
    ))

    # VCS paths (.git/.svn/.hg): severity depends on HTTP status.
    # 200 = actually dumpable, 401 = auth-gated (still risky), 403 = blocked (good).
    VCS_KEYS = {".git", ".svn", ".hg"}

    # Emit a detailed finding for each known-interesting path.
    for h in hits:
        key = h["path"].strip("/").lower()
        details = FINDING_DETAILS.get(key)
        if not details:
            continue
        sev, explanation, recommendation = details
        status_text = {200: "öffentlich erreichbar", 401: "existiert (Auth-Challenge)", 403: "existiert (Zugriff verweigert)"}.get(h["status"], f"HTTP {h['status']}")

        # Adjust severity + description for VCS paths blocked by server config.
        if key in VCS_KEYS and h["status"] == 403:
            sev = Severity.LOW
            explanation = (
                f"Der Webserver gibt beim Aufruf von /{key}/ ein HTTP 403 zurück — d.h. "
                "das Verzeichnis existiert auf der Platte, wird aber vom Webserver "
                "geblockt. Ein Angreifer kann den Inhalt NICHT herunterladen. "
                "Das ist die korrekte Konfiguration.\n\n"
                "Als letzte Härtung könnte man zusätzlich zu 403 auch Dateien wie "
                f"/{key}/HEAD, /{key}/config, /{key}/logs/HEAD manuell testen — "
                "wenn alle 403/404 liefern, ist die Absicherung dicht. "
                "Wir haben bereits während des Scans geprüft ob einzelne Dateien "
                "durchkommen — wäre das der Fall, hätten wir ein CRITICAL Finding ausgegeben."
            )
            recommendation = (
                "Keine Aktion nötig. Zur Kontrolle: prüfen ob auch /.git/HEAD "
                "und /.git/config 403 liefern."
            )
        elif key in VCS_KEYS and h["status"] == 401:
            sev = Severity.MEDIUM  # auth-gated, but passwords can be brute-forced
            explanation = (
                f"Der Webserver gibt beim Aufruf von /{key}/ ein HTTP 401 zurück — d.h. "
                "der Inhalt ist hinter einer HTTP-Auth-Abfrage versteckt. Das ist besser "
                "als offen zugänglich (200), aber ein Angreifer mit schwachen Credentials "
                f"(Basic-Auth wird oft ohne Rate-Limit gebruteforced) kommt potenziell durch. "
                "Sicherer: Zugriff per Webserver-Config komplett blocken (403/404)."
            )
            recommendation = (
                f"Zugriff auf /{key}/ in der Webserver-Config komplett unterbinden "
                f"(nginx: 'location ~ /\\.{key.lstrip('.')} {{ deny all; }}')."
            )

        result.add(Finding(
            id=f"deep.dir_fuzz.{key}",
            title=f"{h['path']} — {status_text}",
            description=explanation,
            severity=sev,
            category="Deep Scan",
            evidence={"path": h["path"], "status": h["status"], "content_type": h.get("ct")},
            recommendation=recommendation,
        ))
