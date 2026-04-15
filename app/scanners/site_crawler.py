"""Light BFS same-domain crawler.

Walks the target site up to MAX_DEPTH links deep and collects:
- pages (text/html responses)
- same-domain image URLs (.jpg/.jpeg/.png/.gif/.webp/.tif)
- same-domain PDF URLs

Downstream scanners (image_metadata, pdf_metadata, ...) read the collected
URL lists from result.metadata["site_crawl"] instead of each doing their
own homepage-only extraction.
"""
from __future__ import annotations

import re
from collections import deque
from typing import Callable
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.base import ScanResult

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
MAX_PAGES = 40
MAX_DEPTH = 2
TIMEOUT = 6.0

HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
SRC_RE = re.compile(r'(?:src|data-src|srcset)=["\']([^"\']+)["\']', re.IGNORECASE)

IMG_EXTS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".tif", ".tiff")
PDF_EXTS = (".pdf",)


def _normalize(base: str, href: str) -> str | None:
    try:
        url = urljoin(base, href)
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    return url.split("#", 1)[0]


def _same_site(url: str, domain: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return host == domain or host.endswith("." + domain)


def _has_ext(url: str, exts: tuple[str, ...]) -> bool:
    clean = url.lower().split("?", 1)[0]
    return any(clean.endswith(ext) for ext in exts)


def crawl_site(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Site-Crawler", 42)

    start = f"https://{domain}/"
    visited: set[str] = set()
    queue: deque = deque([(start, 0)])
    pages: list[str] = []
    images: list[str] = []
    images_seen: set[str] = set()
    pdfs: list[str] = []
    pdfs_seen: set[str] = set()

    with httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        while queue and len(pages) < MAX_PAGES:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            try:
                r = client.get(url)
            except httpx.HTTPError:
                continue
            if r.status_code != 200:
                continue
            if "text/html" not in r.headers.get("content-type", "").lower():
                continue

            pages.append(url)
            html = r.text[:500_000]

            # Hrefs: images, PDFs, deeper links
            for m in HREF_RE.finditer(html):
                resolved = _normalize(url, m.group(1))
                if not resolved or not _same_site(resolved, domain):
                    continue
                if _has_ext(resolved, PDF_EXTS):
                    if resolved not in pdfs_seen:
                        pdfs_seen.add(resolved)
                        pdfs.append(resolved)
                    continue
                if _has_ext(resolved, IMG_EXTS):
                    if resolved not in images_seen:
                        images_seen.add(resolved)
                        images.append(resolved)
                    continue
                if depth < MAX_DEPTH and resolved not in visited:
                    queue.append((resolved, depth + 1))

            # src/srcset: images only
            for m in SRC_RE.finditer(html):
                raw = m.group(1).split(",")[0].strip().split(" ")[0]
                resolved = _normalize(url, raw)
                if not resolved or not _same_site(resolved, domain):
                    continue
                if _has_ext(resolved, IMG_EXTS) and resolved not in images_seen:
                    images_seen.add(resolved)
                    images.append(resolved)

    result.metadata["site_crawl"] = {
        "pages_crawled": pages,
        "pages_count": len(pages),
        "images": images,
        "images_count": len(images),
        "pdfs": pdfs,
        "pdfs_count": len(pdfs),
    }
