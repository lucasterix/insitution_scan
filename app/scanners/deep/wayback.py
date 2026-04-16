"""Wayback Machine historical URL enumeration.

The Internet Archive stores snapshots of almost every public website. Pulling
the list of indexed URLs often reveals:

- Forgotten admin panels that moved elsewhere but still exist
- Old API endpoints with weak auth
- PDFs / SQL dumps that used to be public
- Staging subdomains that point to historical IPs

We pull the list, then probe each historical URL to see which ones still
answer with HTTP 200 on the live site.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from urllib.parse import urlparse

import httpx

from app.scanners._baseline import fetch_baselines, is_catchall
from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
CDX_URL = "https://web.archive.org/cdx/search/cdx"
MAX_PROBES = 30


LEAK_EXTENSIONS = (
    ".sql", ".zip", ".tar", ".tar.gz", ".bak", ".old", ".env",
    ".conf", ".config", ".log", ".csv", ".xls", ".xlsx", ".doc",
    ".docx", ".json", ".xml", ".yml", ".yaml", ".pem", ".key",
)
# Document extensions — we collect these too but don't treat them as leaks;
# they get handed to the pdf_metadata scanner for DSGVO analysis.
DOC_EXTENSIONS = (".pdf",)

INTERESTING_EXTENSIONS = LEAK_EXTENSIONS + DOC_EXTENSIONS


def _fetch_urls(domain: str) -> list[str]:
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": 500,
    }
    try:
        with httpx.Client(timeout=15.0, headers={"User-Agent": USER_AGENT}) as client:
            r = client.get(CDX_URL, params=params)
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError, ValueError):
        return []
    if not data or len(data) < 2:
        return []
    # First row is the header
    return [row[0] for row in data[1:] if row]


def _probe_live(domain: str, url: str, baselines: set[str]) -> dict | None:
    try:
        with httpx.Client(
            timeout=5.0,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            r = client.get(url)
            if r.status_code != 200:
                return None
            body = r.text[:4096] if "text" in r.headers.get("content-type", "").lower() else ""
            if body and is_catchall(body, baselines):
                return None
            return {"url": url, "status": r.status_code, "content_type": r.headers.get("content-type", "")}
    except httpx.HTTPError:
        return None


def check_wayback(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Wayback Machine Historie", 52)

    urls = _fetch_urls(domain)
    if not urls:
        return

    # Filter to interesting extensions and same-host URLs that are NOT already on the homepage
    interesting: list[str] = []
    seen_paths: set[str] = set()
    for u in urls:
        try:
            parsed = urlparse(u)
        except ValueError:
            continue
        if not parsed.netloc.endswith(domain):
            continue
        path = parsed.path or "/"
        if path in seen_paths:
            continue
        seen_paths.add(path)
        low = path.lower()
        if any(low.endswith(ext) for ext in INTERESTING_EXTENSIONS):
            interesting.append(u)
        if len(interesting) >= MAX_PROBES:
            break

    result.metadata.setdefault("wayback", {})["total_indexed"] = len(urls)
    result.metadata["wayback"]["probed"] = interesting

    if not interesting:
        return

    baselines = fetch_baselines(domain)
    live_hits: list[dict] = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_probe_live, domain, url, baselines): url for url in interesting}
        for fut in as_completed(futures):
            hit = fut.result()
            if hit:
                live_hits.append(hit)

    if live_hits:
        result.metadata["wayback"]["live_hits"] = live_hits

        leak_hits = [
            h for h in live_hits
            if any(h["url"].lower().endswith(ext) for ext in LEAK_EXTENSIONS)
        ]
        doc_hits = [
            h for h in live_hits
            if any(h["url"].lower().endswith(ext) for ext in DOC_EXTENSIONS)
        ]

        if leak_hits:
            # Classify by actual danger level
            critical_exts = (".sql", ".env", ".pem", ".key", ".bak")
            high_exts = (".zip", ".tar", ".tar.gz", ".conf", ".config", ".log")

            critical_leaks = [h for h in leak_hits if any(h["url"].lower().endswith(e) for e in critical_exts)]
            high_leaks = [h for h in leak_hits if any(h["url"].lower().endswith(e) for e in high_exts)]
            low_leaks = [h for h in leak_hits if h not in critical_leaks and h not in high_leaks]

            if critical_leaks:
                result.add(Finding(
                    id="deep.wayback_critical_leak",
                    title=f"{len(critical_leaks)} kritische historische Datei(en) noch live (SQL-Dumps, .env, Schlüssel)",
                    description=(
                        "Die Wayback Machine hat URLs indexiert die heute noch antworten und "
                        "deren Dateityp auf hochsensible Inhalte hindeutet:\n\n"
                        + "\n".join(f"  • {h['url']}" for h in critical_leaks[:10])
                        + "\n\nSQL-Dumps enthalten die komplette Datenbank, .env-Dateien "
                        "Passwörter und API-Keys, .pem/.key-Dateien private Schlüssel."
                    ),
                    severity=Severity.HIGH,
                    category="Deep Scan",
                    evidence={"urls": [h["url"] for h in critical_leaks[:20]]},
                    recommendation="SOFORT entfernen oder mit 403 blockieren. Danach: Credentials in der Datei rotieren.",
                    kbv_ref="KBV Anlage 2 (Datenminimierung), DSGVO Art. 32",
                ))

            if high_leaks:
                result.add(Finding(
                    id="deep.wayback_high_leak",
                    title=f"{len(high_leaks)} historische Archiv-/Config-Datei(en) noch live",
                    description=(
                        "Backup-Archive und Konfigurationsdateien aus der Wayback-Machine "
                        "sind noch erreichbar. Diese können sensible Daten enthalten."
                    ),
                    severity=Severity.MEDIUM,
                    category="Deep Scan",
                    evidence={"urls": [h["url"] for h in high_leaks[:20]]},
                    recommendation="Prüfen ob die Dateien noch benötigt werden. Wenn nicht: entfernen.",
                ))

            if low_leaks:
                result.add(Finding(
                    id="deep.wayback_low_leak",
                    title=f"{len(low_leaks)} historische Datei(en) noch live (geringes Risiko)",
                    description="Historische Dateien sind noch erreichbar, aber der Dateityp deutet auf geringes Risiko hin.",
                    severity=Severity.INFO,
                    category="Deep Scan",
                    evidence={"urls": [h["url"] for h in low_leaks[:20]]},
                ))

        if doc_hits:
            # Handed to pdf_metadata at the end of the pipeline.
            result.metadata["wayback"]["historical_live_pdfs"] = [h["url"] for h in doc_hits]
