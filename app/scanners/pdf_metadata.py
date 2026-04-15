"""Extract metadata from PDFs linked on the site.

MVZ sites often link patient info, price lists, GDPR forms, etc. as PDFs.
PDFs carry a surprising amount of metadata: original author, creation software,
sometimes embedded thumbnail images with EXIF GPS data. This check finds the
first few PDFs linked from the homepage and reports any metadata that looks
sensitive.
"""
from __future__ import annotations

import io
import re
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
MAX_PDFS = 5
MAX_PDF_BYTES = 2 * 1024 * 1024  # 2 MB cap per PDF
PDF_LINK_RE = re.compile(r'href=["\']([^"\']+\.pdf)["\']', re.IGNORECASE)

SENSITIVE_METADATA_KEYS = {
    "/Author", "/Creator", "/Producer", "/Title", "/Subject", "/Keywords",
    "/CreationDate", "/ModDate",
}


def _fetch_pdf(client: httpx.Client, url: str) -> bytes | None:
    try:
        r = client.get(url)
        if r.status_code != 200:
            return None
        ct = r.headers.get("content-type", "").lower()
        if "pdf" not in ct and not url.lower().endswith(".pdf"):
            return None
        content = r.content
        if len(content) > MAX_PDF_BYTES:
            return None
        return content
    except httpx.HTTPError:
        return None


def _extract_metadata(pdf_bytes: bytes) -> dict | None:
    try:
        from pypdf import PdfReader  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        meta = reader.metadata or {}
        return {k: str(v) for k, v in meta.items()}
    except Exception:  # noqa: BLE001 — pypdf can raise on malformed inputs
        return None


def check_pdf_metadata(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("PDF-Metadaten", 92)

    pdfs_checked: list[dict] = []
    sensitive_hits: list[dict] = []

    try:
        with httpx.Client(
            timeout=8.0,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            index = client.get(f"https://{domain}")
            if index.status_code != 200:
                return
            html = index.text[:500_000]

            links: list[str] = []
            for m in PDF_LINK_RE.finditer(html):
                href = m.group(1)
                if href.startswith("http"):
                    links.append(href)
                elif href.startswith("/"):
                    links.append(f"https://{domain}{href}")
                else:
                    links.append(f"https://{domain}/{href}")

            # De-dup, cap
            seen: set[str] = set()
            unique_links: list[str] = []
            for url in links:
                if url not in seen:
                    seen.add(url)
                    unique_links.append(url)
                if len(unique_links) >= MAX_PDFS:
                    break

            if not unique_links:
                return

            for url in unique_links:
                pdf_bytes = _fetch_pdf(client, url)
                if pdf_bytes is None:
                    continue
                meta = _extract_metadata(pdf_bytes)
                if meta is None:
                    continue
                pdfs_checked.append({"url": url, "metadata": meta})
                # Sensitive signals: personal author name, real-name producer (not just LibreOffice)
                author = meta.get("/Author", "") or ""
                if author and len(author) >= 3 and author.lower() not in ("admin", "user", "root"):
                    sensitive_hits.append({"url": url, "key": "Author", "value": author})
    except httpx.HTTPError:
        return

    if not pdfs_checked:
        return

    result.metadata["pdf_metadata"] = pdfs_checked

    # One INFO finding listing what we scanned, plus a more specific finding if authors leaked.
    result.add(Finding(
        id="pdf.metadata_scanned",
        title=f"{len(pdfs_checked)} PDF(s) auf Metadaten geprüft",
        description="Folgende PDFs wurden auf der Startseite verlinkt und analysiert.",
        severity=Severity.INFO,
        category="Metadaten",
        evidence={"pdfs": [p["url"] for p in pdfs_checked]},
    ))

    if sensitive_hits:
        result.add(Finding(
            id="pdf.author_leaked",
            title=f"PDF-Metadaten enthalten Personennamen ({len(sensitive_hits)} Dokument(e))",
            description=(
                "Öffentlich heruntergeladbare PDFs enthalten Klarnamen im Author-Feld. "
                "Das ist DSGVO-relevant (Beschäftigtendaten) und erleichtert Spear-Phishing, "
                "weil Angreifer so reale Namen in der Praxis identifizieren."
            ),
            severity=Severity.MEDIUM,
            category="Metadaten",
            evidence={"hits": sensitive_hits},
            recommendation=(
                "Beim PDF-Export Autor-Feld leeren, Word/LibreOffice: "
                "Datei → Eigenschaften → Benutzerdaten aus Datei entfernen."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (Datenminimierung)",
        ))
