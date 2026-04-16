"""Probe for sensitive files that should never be publicly reachable.

This is one of the highest-value checks: forgotten backups, .git directories
and .env files are a common root cause of full-repo leaks on MVZ sites.

False-positive defense is important: most modern MVZ sites are SPAs or CMS
catch-all frontends that return HTTP 200 with the same homepage HTML for any
unknown path. The scanner therefore:

1. Fetches the `/` baseline once and stores its body.
2. For each probed path, discards the response if the body is byte-identical
   to the baseline (pure catch-all).
3. For paths that should never return HTML (e.g. `.zip`, `.sql`, `.env`),
   additionally rejects any response whose body looks like HTML.
4. Applies a per-entry content hint on top of that when provided.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

# Extensions/paths that must NEVER legitimately return HTML.
NON_HTML_PATTERNS = (
    ".git/", ".svn/", ".hg/",
    ".env", ".bak", "~", ".old",
    ".sql", ".zip", ".tar", ".gz",
    "id_rsa", "id_ed25519", ".ssh/",
    ".ds_store", ".htpasswd", ".htaccess",
    ".pem", ".key",
    "composer.lock", "package.json", "composer.json", "yarn.lock",
)

# (path, severity, label, content_hint_substring or None)
SENSITIVE_PATHS: list[tuple[str, Severity, str, str | None]] = [
    ("/.git/HEAD", Severity.CRITICAL, ".git Repository exponiert", "ref:"),
    ("/.git/config", Severity.CRITICAL, ".git Repository exponiert", "[core]"),
    ("/.svn/entries", Severity.HIGH, ".svn Repository exponiert", "dir"),
    ("/.hg/hgrc", Severity.HIGH, ".hg Mercurial Repository exponiert", "["),
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
    ("/.DS_Store", Severity.LOW, ".DS_Store verrät Dateistruktur", "Bud1"),
    ("/.htaccess.bak", Severity.MEDIUM, ".htaccess Backup exponiert", None),
    ("/.htpasswd", Severity.CRITICAL, ".htpasswd mit Hashes exponiert", "$"),
    ("/phpinfo.php", Severity.HIGH, "phpinfo() exponiert", "PHP Version"),
    ("/info.php", Severity.HIGH, "phpinfo() exponiert", "PHP Version"),
    ("/test.php", Severity.LOW, "test.php auffindbar", "<?php"),
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


def _looks_like_html(body: str) -> bool:
    head = body[:500].lower().lstrip()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<body" in head


def _expects_non_html(path: str) -> bool:
    p = path.lower()
    return any(pat in p for pat in NON_HTML_PATTERNS)


def _probe(client: httpx.Client, url: str) -> tuple[int, str, str]:
    try:
        r = client.get(url)
        ct = r.headers.get("content-type", "").lower()
        body = ""
        if r.status_code == 200:
            # Only decode as text when content-type suggests it; binary comparisons use bytes.
            if "text" in ct or "json" in ct or "xml" in ct or not ct:
                body = r.text[:4096]
        return r.status_code, body, ct
    except httpx.HTTPError:
        return 0, "", ""


def check_exposed_files(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Exposed Files Probe", 84)

    findings_to_add: list[Finding] = []
    exposed_paths: list[dict] = []

    # Fetch baseline once so we can detect SPA catch-all 200s.
    with httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    ) as baseline_client:
        baseline_status, baseline_body, baseline_ct = _probe(baseline_client, f"https://{domain}/")
        # A nonsense path to see how the server reacts to unknown URLs.
        _, baseline_404_body, _ = _probe(baseline_client, f"https://{domain}/__mvzscan_404_probe_{hex(abs(hash(domain)) % 0xFFFF)[2:]}__")

    baselines = {baseline_body.strip(), baseline_404_body.strip()}
    baselines.discard("")

    def task(entry: tuple[str, Severity, str, str | None]) -> None:
        path, sev, label, hint = entry
        with httpx.Client(
            timeout=TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            status, body, ct = _probe(client, f"https://{domain}{path}")

        if status != 200:
            return

        # Catch-all SPA defense: if body is identical to root / or the 404 probe, ignore.
        if body.strip() in baselines:
            return

        # Non-HTML paths must not return HTML.
        if _expects_non_html(path) and _looks_like_html(body):
            return

        # For paths that serve real HTML (phpMyAdmin, Adminer, server-status), the hint is
        # stricter — we require it.
        if hint and hint.lower() not in body.lower():
            return

        finding_id = f"exposed.{path.strip('/').replace('/', '_').replace('.', '_')}"
        is_info = path == "/.well-known/security.txt"
        findings_to_add.append(
            Finding(
                id=finding_id,
                title=label,
                description=(
                    f"HTTP 200 auf https://{domain}{path}. Der Inhalt entspricht dem erwarteten "
                    f"Format ({ct or 'unbekannter Content-Type'}) und unterscheidet sich vom SPA-"
                    "Catch-All — die Datei ist öffentlich abrufbar."
                ),
                severity=Severity.INFO if is_info else sev,
                category="Exposed File",
                evidence={"path": path, "status": status, "content_type": ct, "snippet": body[:300]},
                recommendation=(
                    "Datei vom Webserver entfernen oder 404/403 zurückgeben. "
                    "Alle Webserver-Regeln auf 'Dot-Files blockieren' prüfen."
                ),
                kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (keine Offenlegung technischer Daten)",
            )
        )
        exposed_paths.append({"path": path, "severity": sev.value, "label": label})

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(task, e) for e in SENSITIVE_PATHS]
        for f in as_completed(futures):
            f.result()

    for f in findings_to_add:
        result.add(f)

    sectxt_present = any(p["path"] == "/.well-known/security.txt" for p in exposed_paths)
    if not sectxt_present:
        result.add(Finding(
            id="exposed.security_txt_missing",
            title="security.txt fehlt",
            description=(
                "Unter /.well-known/security.txt sollte eine Kontaktadresse für Security-Meldungen stehen. "
                "Fehlt die Datei, haben wohlgesonnene Sicherheitsforscher keinen einfachen Meldeweg."
            ),
            severity=Severity.INFO,
            category="Meta",
            recommendation="Lege eine /.well-known/security.txt an (siehe securitytxt.org).",
        ))

    result.metadata["exposed_files"] = exposed_paths
