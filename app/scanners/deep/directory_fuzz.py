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
FINDING_SEVERITY: dict[str, Severity] = {
    "phpmyadmin": Severity.HIGH,
    "pma": Severity.HIGH,
    "adminer": Severity.HIGH,
    "phpinfo": Severity.HIGH,
    ".git": Severity.CRITICAL,
    ".svn": Severity.HIGH,
    ".hg": Severity.HIGH,
    "graphql": Severity.MEDIUM,
    "graphiql": Severity.HIGH,
    "swagger": Severity.MEDIUM,
    "swagger-ui": Severity.MEDIUM,
    "openapi": Severity.MEDIUM,
    "grafana": Severity.HIGH,
    "kibana": Severity.HIGH,
    "jenkins": Severity.HIGH,
    "webmin": Severity.HIGH,
    "plesk": Severity.HIGH,
    "cpanel": Severity.HIGH,
    "server-status": Severity.MEDIUM,
    "server-info": Severity.MEDIUM,
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
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = [ex.submit(_probe, client, base, w) for w in WORDLIST]
            for f in as_completed(futures):
                r = f.result()
                if r is None:
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

    # Emit a separate severity-coded finding for "known-interesting" paths.
    for h in hits:
        key = h["path"].strip("/").lower()
        sev = FINDING_SEVERITY.get(key)
        if sev:
            result.add(Finding(
                id=f"deep.dir_fuzz.{key}",
                title=f"Interessanter Pfad: {h['path']} (HTTP {h['status']})",
                description=(
                    f"Der Pfad {h['path']} antwortet mit HTTP {h['status']} und ist keine "
                    "SPA-Fallback-Antwort. Prüfe manuell, ob der Endpoint öffentlich sein soll."
                ),
                severity=sev,
                category="Deep Scan",
                evidence={"path": h["path"], "status": h["status"], "content_type": h.get("ct")},
                recommendation="Manuell nachschauen und — wenn intern — hinter VPN/Auth stellen.",
            ))
