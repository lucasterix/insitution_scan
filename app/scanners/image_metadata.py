"""Extract EXIF / metadata from every same-domain image discovered.

Sources of image URLs:
1. app/scanners/site_crawler.py → result.metadata["site_crawl"]["images"]
   (same-domain images via BFS crawl of up to MAX_PAGES pages)
2. Fallback: regex the homepage HTML only if the crawler did not run.

Flags GPS coordinate leaks as HIGH (DSGVO Art. 5/32) and personal-name
EXIF fields (Artist / Author / Copyright / CameraOwnerName) as MEDIUM.
"""
from __future__ import annotations

import io
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
MAX_IMAGES = 30
MAX_IMG_BYTES = 6 * 1024 * 1024

IMG_LINK_RE = re.compile(
    r'(?:src|href)=["\']([^"\']+\.(?:jpg|jpeg|png|tif|tiff))["\']',
    re.IGNORECASE,
)

SENSITIVE_EXIF_KEYS = {
    "Artist", "XPAuthor", "Copyright", "Software", "HostComputer",
    "GPSInfo", "GPSLatitude", "GPSLongitude",
    "DateTimeOriginal", "CameraOwnerName",
}


def _collect_urls(domain: str, result: ScanResult) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    def push(u: str) -> None:
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    site_crawl = result.metadata.get("site_crawl") or {}
    for u in site_crawl.get("images") or []:
        push(u)

    if urls:
        return urls

    # Fallback: homepage-only regex
    try:
        with httpx.Client(
            timeout=8.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}
        ) as client:
            r = client.get(f"https://{domain}")
            if r.status_code == 200 and "text/html" in r.headers.get("content-type", "").lower():
                for m in IMG_LINK_RE.finditer(r.text[:500_000]):
                    href = m.group(1)
                    if href.startswith("http"):
                        push(href)
                    elif href.startswith("//"):
                        push(f"https:{href}")
                    elif href.startswith("/"):
                        push(f"https://{domain}{href}")
                    else:
                        push(f"https://{domain}/{href}")
    except httpx.HTTPError:
        pass
    return urls


def _fetch(url: str) -> bytes | None:
    try:
        with httpx.Client(
            timeout=6.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}
        ) as client:
            r = client.get(url)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    if len(r.content) > MAX_IMG_BYTES:
        return None
    return r.content


def _extract_exif(raw: bytes) -> dict:
    try:
        from PIL import ExifTags, Image  # type: ignore[import-not-found]
    except ImportError:
        return {}
    try:
        with Image.open(io.BytesIO(raw)) as img:
            exif = img.getexif()
            if not exif:
                return {}
            out: dict = {}
            for tag_id, value in exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, f"Tag{tag_id}")
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        value = repr(value)
                if tag_name == "GPSInfo" and isinstance(value, dict):
                    gps_out = {}
                    for gps_id, gps_val in value.items():
                        gps_name = ExifTags.GPSTAGS.get(gps_id, f"GPSTag{gps_id}")
                        gps_out[gps_name] = str(gps_val)
                    out[tag_name] = gps_out
                else:
                    out[tag_name] = str(value)[:300]
            return out
    except Exception:  # noqa: BLE001
        return {}


def check_image_metadata(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Bild-EXIF-Metadaten", 94)

    urls = _collect_urls(domain, result)
    if not urls:
        return

    reports: list[dict] = []
    sensitive_hits: list[dict] = []
    target_urls = urls[:MAX_IMAGES]

    with ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(_fetch, target_urls))

    for url, raw in zip(target_urls, results):
        if raw is None:
            continue
        meta = _extract_exif(raw)
        if not meta:
            continue
        reports.append({"url": url, "exif_keys": list(meta.keys())})
        for key in SENSITIVE_EXIF_KEYS:
            if key in meta:
                sensitive_hits.append({"url": url, "key": key, "value": meta[key]})

    if not reports:
        return

    result.metadata["image_exif"] = {
        "total_candidates": len(urls),
        "analyzed": len(reports),
        "reports": reports,
    }

    result.add(Finding(
        id="image.exif_scanned",
        title=f"{len(reports)} von {len(urls)} Bildern mit EXIF-Metadaten analysiert",
        description=(
            "Der Site-Crawler hat site-weit nach Bildern gesucht (nicht nur auf der Homepage) "
            "und jede Datei mit EXIF-Header analysiert."
        ),
        severity=Severity.INFO,
        category="Metadaten",
        evidence={"images": [r["url"] for r in reports][:20]},
    ))

    gps_hits = [h for h in sensitive_hits if "GPS" in h["key"]]
    personal_hits = [h for h in sensitive_hits if h["key"] in ("Artist", "XPAuthor", "Copyright", "CameraOwnerName")]

    if gps_hits:
        result.add(Finding(
            id="image.exif_gps_leaked",
            title=f"GPS-Koordinaten in {len(gps_hits)} Bild(ern) eingebettet",
            description=(
                "Öffentliche Bilder tragen GPS-Koordinaten in ihren EXIF-Daten. Das erlaubt es "
                "Angreifern, den physischen Standort einer Praxis (oder des Praxisinhabers bei "
                "Home-Office-Fotos) ohne Rückfrage zu ermitteln — ein direktes DSGVO-Problem "
                "und ein Risiko für Doxxing/Stalking."
            ),
            severity=Severity.HIGH,
            category="Metadaten",
            evidence={"hits": gps_hits[:10]},
            recommendation=(
                "Vor dem Upload EXIF strippen (z.B. `exiftool -all= *.jpg` oder "
                "ImageOptim/ImageMagick). Im CMS Upload-Plugin verwenden, das EXIF "
                "automatisch entfernt."
            ),
            kbv_ref="DSGVO Art. 5 (Datenminimierung) + Art. 32 (TOM)",
        ))

    if personal_hits:
        result.add(Finding(
            id="image.exif_personal_leaked",
            title=f"Personenbezogene EXIF-Felder in {len(personal_hits)} Bild(ern)",
            description=(
                "Bilder tragen personenbezogene Felder wie Artist/Author/Copyright/"
                "CameraOwnerName. Das verknüpft Fotos mit realen Personen in der Praxis."
            ),
            severity=Severity.MEDIUM,
            category="Metadaten",
            evidence={"hits": personal_hits[:20]},
            recommendation="EXIF-Autor/Copyright-Felder vor Upload leeren.",
        ))
