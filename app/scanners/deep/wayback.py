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


INTERESTING_EXTENSIONS = (
    ".sql", ".zip", ".tar", ".tar.gz", ".bak", ".old", ".env",
    ".conf", ".config", ".log", ".csv", ".xls", ".xlsx", ".doc",
    ".docx", ".json", ".xml", ".yml", ".yaml", ".pem", ".key",
)


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
        result.add(Finding(
            id="deep.wayback_live_leak",
            title=f"{len(live_hits)} historische Datei(en) aus Wayback Machine sind noch live",
            description=(
                "Die Wayback Machine hat historische URLs dieser Domain indexiert, die "
                "heute noch antworten. Typisch sind dies alte SQL-Dumps, Backup-Archive "
                "oder Konfigurationsdateien, die nach einem Rewrite auf der Seite vergessen "
                "wurden — ein klassisches Leak-Einfallstor."
            ),
            severity=Severity.HIGH,
            category="Deep Scan",
            evidence={"urls": [h["url"] for h in live_hits[:20]]},
            recommendation="Jede dieser Dateien prüfen und — wenn nicht mehr gebraucht — entfernen oder mit 404/403 blockieren.",
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (Datenminimierung)",
        ))
