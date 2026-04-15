"""Probe for sensitive files that should never be publicly reachable.

This is one of the highest-value checks: forgotten backups, .git directories
and .env files are a common root cause of full-repo leaks on MVZ sites.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

# Each entry: (path, severity, label, content_hint_substring or None)
# content_hint is used to reduce false-positives from SPA catch-all 200s —
# we only report the finding when the response actually looks like the expected content.
SENSITIVE_PATHS: list[tuple[str, Severity, str, str | None]] = [
    ("/.git/HEAD", Severity.CRITICAL, ".git Repository exponiert", "ref:"),
    ("/.git/config", Severity.CRITICAL, ".git Repository exponiert", "[core]"),
    ("/.svn/entries", Severity.HIGH, ".svn Repository exponiert", None),
    ("/.hg/hgrc", Severity.HIGH, ".hg Mercurial Repository exponiert", None),
    ("/.env", Severity.CRITICAL, ".env Datei mit Credentials exponiert", "="),
    ("/.env.bak", Severity.CRITICAL, ".env.bak mit Credentials exponiert", "="),
    ("/.env.local", Severity.CRITICAL, ".env.local mit Credentials exponiert", "="),
    ("/.env.production", Severity.CRITICAL, ".env.production mit Credentials exponiert", "="),
    ("/wp-config.php.bak", Severity.CRITICAL, "WordPress Config Backup exponiert", "DB_PASSWORD"),
    ("/wp-config.php~", Severity.CRITICAL, "WordPress Config Backup exponiert", "DB_PASSWORD"),
    ("/wp-config.php.old", Severity.CRITICAL, "WordPress Config Backup exponiert", "DB_PASSWORD"),
    ("/config.php.bak", Severity.CRITICAL, "config.php Backup exponiert", "<?php"),
    ("/config.inc.php.bak", Severity.CRITICAL, "config.inc.php Backup exponiert", "<?php"),
    ("/backup.zip", Severity.HIGH, "Backup-Archiv exponiert", None),
    ("/backup.tar.gz", Severity.HIGH, "Backup-Archiv exponiert", None),
    ("/backup.sql", Severity.CRITICAL, "SQL-Dump exponiert", "INSERT"),
    ("/dump.sql", Severity.CRITICAL, "SQL-Dump exponiert", "INSERT"),
    ("/database.sql", Severity.CRITICAL, "SQL-Dump exponiert", "INSERT"),
    ("/db.sql", Severity.CRITICAL, "SQL-Dump exponiert", "INSERT"),
    ("/site.sql", Severity.CRITICAL, "SQL-Dump exponiert", "INSERT"),
    ("/id_rsa", Severity.CRITICAL, "Privater SSH-Key exponiert", "BEGIN RSA PRIVATE KEY"),
    ("/id_ed25519", Severity.CRITICAL, "Privater SSH-Key exponiert", "BEGIN OPENSSH PRIVATE KEY"),
    ("/.ssh/id_rsa", Severity.CRITICAL, "Privater SSH-Key exponiert", "BEGIN"),
    ("/.DS_Store", Severity.LOW, ".DS_Store verrät Dateistruktur", None),
    ("/.htaccess.bak", Severity.MEDIUM, ".htaccess Backup exponiert", None),
    ("/.htpasswd", Severity.CRITICAL, ".htpasswd mit Hashes exponiert", ":"),
    ("/phpinfo.php", Severity.HIGH, "phpinfo() exponiert", "PHP Version"),
    ("/info.php", Severity.HIGH, "phpinfo() exponiert", "PHP Version"),
    ("/test.php", Severity.LOW, "test.php auffindbar", None),
    ("/server-status", Severity.MEDIUM, "Apache server-status exponiert", "Apache Server Status"),
    ("/server-info", Severity.MEDIUM, "Apache server-info exponiert", "Apache Server Information"),
    ("/phpmyadmin/", Severity.HIGH, "phpMyAdmin erreichbar", "phpMyAdmin"),
    ("/pma/", Severity.HIGH, "phpMyAdmin erreichbar", "phpMyAdmin"),
    ("/adminer.php", Severity.HIGH, "Adminer erreichbar", "Adminer"),
    ("/.well-known/security.txt", Severity.INFO, "security.txt vorhanden", "Contact"),
    ("/composer.json", Severity.LOW, "composer.json öffentlich", "\"require\""),
    ("/composer.lock", Severity.LOW, "composer.lock öffentlich", "\"packages\""),
    ("/package.json", Severity.LOW, "package.json öffentlich", "\"dependencies\""),
    ("/yarn.lock", Severity.LOW, "yarn.lock öffentlich", None),
]

TIMEOUT = 4.0
MAX_WORKERS = 8


def _probe(client: httpx.Client, domain: str, path: str) -> tuple[int, str]:
    try:
        r = client.get(f"https://{domain}{path}")
        # Only peek at first ~2 KB to keep it light.
        body = r.text[:2048] if "text" in r.headers.get("content-type", "") else ""
        return r.status_code, body
    except httpx.HTTPError:
        return 0, ""


def check_exposed_files(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Exposed Files Probe", 84)

    findings_to_add: list[Finding] = []
    exposed_paths: list[dict] = []

    def task(entry: tuple[str, Severity, str, str | None]) -> None:
        path, sev, label, hint = entry
        with httpx.Client(
            timeout=TIMEOUT,
            follow_redirects=False,  # redirects usually mean "not really there"
            headers={"User-Agent": USER_AGENT},
            verify=True,
        ) as client:
            status, body = _probe(client, domain, path)

        if status != 200:
            return
        if hint and hint.lower() not in body.lower():
            return

        finding_id = f"exposed.{path.strip('/').replace('/', '_')}"
        finding = Finding(
            id=finding_id,
            title=label,
            description=f"HTTP 200 auf https://{domain}{path}. Der Inhalt passt zum erwarteten Format — die Datei ist öffentlich abrufbar.",
            severity=sev if path != "/.well-known/security.txt" else Severity.INFO,
            category="Exposed File",
            evidence={"path": path, "status": status, "snippet": body[:300]},
            recommendation=(
                "Datei vom Webserver entfernen oder 404/403 zurückgeben. "
                "Alle Webserver-Regeln auf 'Dot-Files blockieren' prüfen."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (keine Offenlegung technischer Daten)",
        )
        findings_to_add.append(finding)
        exposed_paths.append({"path": path, "severity": sev.value, "label": label})

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(task, e) for e in SENSITIVE_PATHS]
        for f in as_completed(futures):
            f.result()

    for f in findings_to_add:
        result.add(f)

    # Special handling: if /.well-known/security.txt is absent, emit a LOW info finding.
    sectxt_present = any(p["path"] == "/.well-known/security.txt" for p in exposed_paths)
    if not sectxt_present:
        result.add(Finding(
            id="exposed.security_txt_missing",
            title="security.txt fehlt",
            description=(
                "Unter /.well-known/security.txt sollte eine Kontaktadresse für Security-Meldungen stehen. "
                "Fehlt die Datei, haben wohlgesonnene Sicherheitsforscher keinen einfachen Meldeweg."
            ),
            severity=Severity.LOW,
            category="Meta",
            recommendation="Lege eine /.well-known/security.txt an (siehe securitytxt.org).",
        ))

    result.metadata["exposed_files"] = exposed_paths
