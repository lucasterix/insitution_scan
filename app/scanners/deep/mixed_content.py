"""Mixed-content detection.

Parses the homepage HTML for resources loaded over plain http:// while
the page itself is served over https://. Modern browsers block most mixed
active content (scripts, iframes), but mixed passive content (images, fonts,
media) is still loaded with a console warning — and can be tampered with
by a MITM attacker on the same network.

For MVZ sites in clinical networks where MITM is technically possible
(shared Wi-Fi, compromised switch), this is a real vector.
"""
from __future__ import annotations

import re
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

# Match src="http://..." or href="http://..." but NOT "https://"
MIXED_RE = re.compile(
    r'(?:src|href|action|data|poster|srcset)\s*=\s*["\']'
    r'(http://[^"\'>\s]+)["\']',
    re.IGNORECASE,
)

ACTIVE_EXTS = (".js", ".mjs", ".jsx", ".ts")
FRAME_TAGS = ("iframe", "frame", "object", "embed")


def check_mixed_content(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Mixed-Content-Detection", 66)

    # Use site_crawl pages if available, else homepage.
    site_crawl = result.metadata.get("site_crawl") or {}
    pages = site_crawl.get("pages_crawled") or [f"https://{domain}/"]
    pages = pages[:10]  # cap to avoid slow scans

    mixed_active: list[dict] = []
    mixed_passive: list[dict] = []

    with httpx.Client(
        timeout=6.0,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        for page_url in pages:
            if not page_url.startswith("https://"):
                continue
            try:
                r = client.get(page_url)
            except httpx.HTTPError:
                continue
            if r.status_code != 200:
                continue
            if "text/html" not in r.headers.get("content-type", "").lower():
                continue

            html = r.text[:500_000]
            for m in MIXED_RE.finditer(html):
                http_url = m.group(1)
                low = http_url.lower()
                entry = {"page": page_url, "resource": http_url}

                is_active = (
                    any(low.endswith(ext) for ext in ACTIVE_EXTS) or
                    any(f"<{tag}" in html[max(0, m.start()-200):m.start()].lower() for tag in FRAME_TAGS)
                )
                if is_active:
                    mixed_active.append(entry)
                else:
                    mixed_passive.append(entry)

    if not mixed_active and not mixed_passive:
        return

    result.metadata["mixed_content"] = {
        "active": mixed_active[:20],
        "passive": mixed_passive[:20],
    }

    if mixed_active:
        result.add(Finding(
            id="deep.mixed_content_active",
            title=f"Mixed Active Content: {len(mixed_active)} Script(s)/iFrame(s) über HTTP",
            description=(
                "Die HTTPS-Seite lädt Scripts oder iFrames über unverschlüsseltes HTTP. "
                "Moderne Browser blockieren dies, aber ältere Versionen (und manche Praxis-PCs "
                "mit veralteten Browsern) führen den Code aus. Ein MITM-Angreifer im selben "
                "Netzwerk kann beliebigen JavaScript-Code einschleusen."
            ),
            severity=Severity.HIGH,
            category="Deep Scan",
            evidence={"resources": mixed_active[:10]},
            recommendation="Alle Script-/iFrame-Quellen auf https:// umstellen oder protocol-relative URLs (//) verwenden.",
        ))

    if mixed_passive:
        result.add(Finding(
            id="deep.mixed_content_passive",
            title=f"Mixed Passive Content: {len(mixed_passive)} Bild(er)/Font(s) über HTTP",
            description=(
                "Die HTTPS-Seite lädt Bilder, Fonts oder Medien über unverschlüsseltes HTTP. "
                "Browser zeigen eine Warnung, laden die Ressourcen aber trotzdem. Ein MITM-Angreifer "
                "könnte die Bilder manipulieren (z.B. QR-Codes auf Rezept-Seiten)."
            ),
            severity=Severity.LOW,
            category="Deep Scan",
            evidence={"resources": mixed_passive[:10]},
            recommendation="Alle Resource-URLs auf https:// umstellen.",
        ))
