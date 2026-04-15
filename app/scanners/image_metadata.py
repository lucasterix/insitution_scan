"""Extract EXIF / metadata from images linked on the homepage.

Practice photos often carry EXIF data with camera model, software name and
sometimes GPS coordinates — the latter is DSGVO-relevant for medical sites
because a "from home office" photo can leak the practice owner's address.
"""
from __future__ import annotations

import io
import re
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
MAX_IMAGES = 10
MAX_IMG_BYTES = 5 * 1024 * 1024

IMG_LINK_RE = re.compile(
    r'(?:src|href)=["\']([^"\']+\.(?:jpg|jpeg|png|tif|tiff))["\']',
    re.IGNORECASE,
)

SENSITIVE_EXIF_KEYS = {
    "Artist", "XPAuthor", "Copyright", "Software", "HostComputer",
    "GPSInfo", "GPSLatitude", "GPSLongitude",
    "DateTimeOriginal", "CameraOwnerName",
}


def _fetch(client: httpx.Client, url: str) -> bytes | None:
    try:
        r = client.get(url)
        if r.status_code != 200:
            return None
        if len(r.content) > MAX_IMG_BYTES:
            return None
        return r.content
    except httpx.HTTPError:
        return None


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
    except Exception:  # noqa: BLE001 — Pillow can raise on anything
        return {}


def check_image_metadata(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Bild-EXIF-Metadaten", 94)

    try:
        with httpx.Client(
            timeout=8.0,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            r = client.get(f"https://{domain}")
            if r.status_code != 200:
                return
            html = r.text[:500_000]

            urls: list[str] = []
            seen: set[str] = set()
            for m in IMG_LINK_RE.finditer(html):
                href = m.group(1)
                if href.startswith("http"):
                    url = href
                elif href.startswith("//"):
                    url = f"https:{href}"
                elif href.startswith("/"):
                    url = f"https://{domain}{href}"
                else:
                    url = f"https://{domain}/{href}"
                if url in seen:
                    continue
                seen.add(url)
                urls.append(url)
                if len(urls) >= MAX_IMAGES:
                    break

            if not urls:
                return

            reports: list[dict] = []
            sensitive_hits: list[dict] = []

            for url in urls:
                raw = _fetch(client, url)
                if raw is None:
                    continue
                meta = _extract_exif(raw)
                if not meta:
                    continue
                reports.append({"url": url, "exif_keys": list(meta.keys())})

                for key in SENSITIVE_EXIF_KEYS:
                    if key in meta:
                        sensitive_hits.append({"url": url, "key": key, "value": meta[key]})
    except httpx.HTTPError:
        return

    if not reports:
        return

    result.metadata["image_exif"] = reports

    result.add(Finding(
        id="image.exif_scanned",
        title=f"{len(reports)} Bild(er) mit EXIF-Metadaten analysiert",
        description=f"Auf {len(reports)} von max. {MAX_IMAGES} geprüften Bildern wurden EXIF-Header gefunden.",
        severity=Severity.INFO,
        category="Metadaten",
        evidence={"images": [r["url"] for r in reports]},
    ))

    # Separate GPS leaks from the other personal hits because GPS is a much stronger signal.
    gps_hits = [h for h in sensitive_hits if "GPS" in h["key"]]
    personal_hits = [h for h in sensitive_hits if h["key"] in ("Artist", "XPAuthor", "Copyright", "CameraOwnerName")]

    if gps_hits:
        result.add(Finding(
            id="image.exif_gps_leaked",
            title=f"GPS-Koordinaten in {len(gps_hits)} Bild(ern) eingebettet",
            description=(
                "Öffentliche Bilder tragen GPS-Koordinaten in ihren EXIF-Daten. "
                "Das erlaubt es Angreifern den physischen Standort einer Praxis (oder "
                "des Praxisinhabers) ohne Rückfrage zu ermitteln — für Home-Office-"
                "Fotos ein DSGVO-Problem."
            ),
            severity=Severity.HIGH,
            category="Metadaten",
            evidence={"hits": gps_hits[:5]},
            recommendation=(
                "Vor dem Upload EXIF-Daten strippen (z.B. über `exiftool -all= *.jpg` "
                "oder ImageOptim/ImageMagick). Im CMS idealerweise Upload-Plugin nutzen, "
                "das EXIF automatisch entfernt."
            ),
            kbv_ref="DSGVO Art. 5 (Datenminimierung) + Art. 32 (Technisch-organisatorische Maßnahmen)",
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
            evidence={"hits": personal_hits[:10]},
            recommendation="EXIF-Autor/Copyright-Felder vor Upload leeren.",
        ))
