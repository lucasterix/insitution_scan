"""Light-weight tech stack fingerprinting.

Uses data already collected by the HTTP check (response headers) and
additionally parses the root HTML for generator meta tags + obvious
library version strings. No external tools.
"""
from __future__ import annotations

import re

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

META_GENERATOR_RE = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
WORDPRESS_VER_RE = re.compile(r"wordpress[/\s]+([\d.]+)", re.IGNORECASE)
JQUERY_VER_RE = re.compile(r'/jquery[.\-]?([\d.]+)(?:\.min)?\.js', re.IGNORECASE)
BOOTSTRAP_VER_RE = re.compile(r'/bootstrap[.\-/]?([\d.]+)(?:[./][\w.]+)?\.(?:min\.)?(?:css|js)', re.IGNORECASE)
SERVER_VER_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9_\-]*)[/ ]([\d][\d.\w\-]*)")


def _parse_server_header(value: str) -> tuple[str, str] | None:
    if not value:
        return None
    m = SERVER_VER_RE.search(value)
    if not m:
        return None
    return m.group(1).lower(), m.group(2)


def check_tech_fingerprint(domain: str, result: ScanResult, step) -> None:  # type: ignore[no-untyped-def]
    step("Technologie-Fingerprint", 93)

    https_info = (result.metadata.get("http") or {}).get("https") or {}
    headers = https_info.get("headers") or {}
    tech: dict = dict(result.metadata.get("tech") or {})

    # Parse Server header for product + version.
    parsed = _parse_server_header(headers.get("server", ""))
    if parsed:
        product, version = parsed
        tech[f"server.{product}"] = version
        result.add(Finding(
            id="tech.server_version_disclosed",
            title=f"Server-Header verrät Version: {product} {version}",
            description="Genaue Versionsnummern im Server-Header erleichtern Angreifern das Matching bekannter CVEs.",
            severity=Severity.LOW,
            category="Technologie-Offenlegung",
            evidence={"product": product, "version": version},
            recommendation="Version aus dem Server-Header entfernen (z.B. nginx: server_tokens off;).",
        ))

    # Use shared homepage HTML cache from osint.py (saves ~8s redundant HTTP fetch).
    html_text = result.metadata.get("homepage_html", "")
    if not html_text:
        try:
            with httpx.Client(timeout=8.0, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as client:
                r = client.get(f"https://{domain}")
                if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
                    html_text = r.text[:200_000]
        except httpx.HTTPError:
            pass

    if html_text:
        mg = META_GENERATOR_RE.search(html_text)
        if mg:
            generator = mg.group(1).strip()
            tech["generator"] = generator
            result.add(Finding(
                id="tech.generator_disclosed",
                title=f"Generator-Tag verrät Software: {generator}",
                description="Das HTML-Meta-Generator-Tag legt CMS und Version offen.",
                severity=Severity.LOW,
                category="Technologie-Offenlegung",
                evidence={"generator": generator},
                recommendation="<meta name=\"generator\"> entfernen oder leeren.",
            ))

            wp = WORDPRESS_VER_RE.search(generator)
            if wp:
                tech["wordpress"] = wp.group(1)

        for m in JQUERY_VER_RE.finditer(html_text):
            ver = m.group(1)
            tech.setdefault("jquery", ver)
            # jQuery < 3.0 has a bunch of known XSS CVEs
            try:
                major = int(ver.split(".", 1)[0])
                if major < 3:
                    result.add(Finding(
                        id="tech.jquery_outdated",
                        title=f"Veraltete jQuery-Version: {ver}",
                        description=f"jQuery {ver} ist veraltet und hat bekannte XSS-Schwachstellen (CVE-2020-11022, CVE-2020-11023).",
                        severity=Severity.MEDIUM,
                        category="Outdated Libraries",
                        evidence={"version": ver},
                        recommendation="Auf jQuery 3.5+ aktualisieren.",
                    ))
                    break
            except ValueError:
                pass

        for m in BOOTSTRAP_VER_RE.finditer(html_text):
            ver = m.group(1)
            tech.setdefault("bootstrap", ver)
            try:
                major = int(ver.split(".", 1)[0])
                if major < 4:
                    result.add(Finding(
                        id="tech.bootstrap_outdated",
                        title=f"Veraltete Bootstrap-Version: {ver}",
                        description=f"Bootstrap {ver} ist End-of-Life.",
                        severity=Severity.LOW,
                        category="Outdated Libraries",
                        evidence={"version": ver},
                        recommendation="Auf Bootstrap 5.x aktualisieren.",
                    ))
                    break
            except ValueError:
                pass

    if tech:
        result.metadata["tech"] = tech
