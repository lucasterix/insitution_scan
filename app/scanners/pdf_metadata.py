"""Extract metadata from every PDF linked on the site.

Sources of PDF URLs (in order):
1. app/scanners/site_crawler.py → result.metadata["site_crawl"]["pdfs"]
   (same-domain PDFs discovered via BFS crawl)
2. app/scanners/deep/wayback.py → result.metadata["wayback"]["historical_live_pdfs"]
   (historical PDFs from Internet Archive that are STILL live on the domain)
3. Fallback: regex-scan the homepage HTML if neither source populated data.

For each unique URL we fetch up to MAX_PDF_BYTES, parse /Author /Creator /
Producer via pypdf, and flag personal-name fields as MEDIUM DSGVO findings.
"""
from __future__ import annotations

import io
import re
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
MAX_PDFS = 25
MAX_PDF_BYTES = 2 * 1024 * 1024
PDF_LINK_RE = re.compile(r'href=["\']([^"\']+\.pdf)["\']', re.IGNORECASE)


def _collect_urls(domain: str, result: ScanResult) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    def push(u: str) -> None:
        if u and u not in seen and u.lower().split("?", 1)[0].endswith(".pdf"):
            seen.add(u)
            urls.append(u)

    site_crawl = result.metadata.get("site_crawl") or {}
    for u in site_crawl.get("pdfs") or []:
        push(u)

    wayback = result.metadata.get("wayback") or {}
    for u in wayback.get("historical_live_pdfs") or []:
        push(u)

    if urls:
        return urls

    # Fallback: regex the homepage if no crawler ran (e.g., offline).
    try:
        with httpx.Client(
            timeout=8.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}
        ) as client:
            r = client.get(f"https://{domain}")
            if r.status_code == 200 and "text/html" in r.headers.get("content-type", "").lower():
                for m in PDF_LINK_RE.finditer(r.text[:500_000]):
                    href = m.group(1)
                    if href.startswith("http"):
                        push(href)
                    elif href.startswith("/"):
                        push(f"https://{domain}{href}")
                    else:
                        push(f"https://{domain}/{href}")
    except httpx.HTTPError:
        pass
    return urls


def _fetch_pdf(client: httpx.Client, url: str) -> bytes | None:
    try:
        r = client.get(url)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    ct = r.headers.get("content-type", "").lower()
    if "pdf" not in ct and not url.lower().endswith(".pdf"):
        return None
    if len(r.content) > MAX_PDF_BYTES:
        return None
    return r.content


def _extract_metadata(pdf_bytes: bytes) -> dict | None:
    try:
        from pypdf import PdfReader  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        meta = reader.metadata or {}
        return {k: str(v) for k, v in meta.items()}
    except Exception:  # noqa: BLE001
        return None


def check_pdf_metadata(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("PDF-Metadaten", 92)

    urls = _collect_urls(domain, result)
    if not urls:
        return

    pdfs_checked: list[dict] = []
    sensitive_hits: list[dict] = []
    pdfs_from_wayback = set((result.metadata.get("wayback") or {}).get("historical_live_pdfs") or [])

    with httpx.Client(
        timeout=10.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}
    ) as client:
        for url in urls[:MAX_PDFS]:
            pdf_bytes = _fetch_pdf(client, url)
            if pdf_bytes is None:
                continue
            meta = _extract_metadata(pdf_bytes)
            if meta is None:
                continue
            source = "wayback" if url in pdfs_from_wayback else "site"
            pdfs_checked.append({"url": url, "metadata": meta, "source": source})
            author = meta.get("/Author", "") or ""
            if author and len(author) >= 3 and author.lower() not in ("admin", "user", "root"):
                sensitive_hits.append({"url": url, "key": "Author", "value": author, "source": source})

    if not pdfs_checked:
        return

    result.metadata["pdf_metadata"] = pdfs_checked

    wayback_count = sum(1 for p in pdfs_checked if p.get("source") == "wayback")
    site_count = len(pdfs_checked) - wayback_count

    result.add(Finding(
        id="pdf.metadata_scanned",
        title=f"{len(pdfs_checked)} PDF(s) auf Metadaten geprüft",
        description=(
            f"Site-Crawl: {site_count}, Wayback-Machine (historische): {wayback_count}. "
            "Jede Datei wurde heruntergeladen und ihre interne Metadaten-Struktur analysiert."
        ),
        severity=Severity.INFO,
        category="Metadaten",
        evidence={"pdfs": [{"url": p["url"], "source": p["source"]} for p in pdfs_checked]},
    ))

    if sensitive_hits:
        result.add(Finding(
            id="pdf.author_leaked",
            title=f"PDF-Metadaten enthalten Personennamen ({len(sensitive_hits)} Dokument(e))",
            description=(
                "Öffentlich heruntergeladbare PDFs enthalten Klarnamen im Author-Feld. "
                "Das ist DSGVO-relevant (Beschäftigtendaten) und erleichtert Spear-Phishing, "
                "weil Angreifer so reale Namen in der Praxis identifizieren können."
            ),
            severity=Severity.MEDIUM,
            category="Metadaten",
            evidence={"hits": sensitive_hits},
            recommendation=(
                "Beim PDF-Export Autor-Feld leeren. In Word/LibreOffice: "
                "Datei → Eigenschaften → Benutzerdaten aus Datei entfernen. Historische "
                "Treffer (Wayback) bedeuten: die Datei lag früher online, liegt heute noch — "
                "sollte geprüft und ggf. komplett entfernt werden."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 1 (Datenminimierung) + DSGVO Art. 5/32",
        ))
