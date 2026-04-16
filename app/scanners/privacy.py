"""DSGVO / privacy checks: trackers, cookie flags, impressum completeness.

For medical care centers, these checks have a strong legal dimension:
Google Analytics without explicit prior consent is a DSGVO violation,
and a missing or incomplete impressum can trigger Abmahnungen under TMG/DDG.
"""
from __future__ import annotations

import re
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

# --- Third-party trackers -----------------------------------------------

TRACKER_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (re.compile(r"google-analytics\.com/(?:ga|analytics)\.js", re.IGNORECASE), "Google Analytics (Universal)", Severity.MEDIUM, "Google Analytics ohne explizite Einwilligung ist für MVZ eine DSGVO-Verletzung (Schrems II + BfDI-Leitlinie)."),
    (re.compile(r"googletagmanager\.com/(?:gtag|gtm)", re.IGNORECASE), "Google Tag Manager", Severity.MEDIUM, "GTM lädt typischerweise GA/GAds — ohne Consent DSGVO-relevant."),
    (re.compile(r"connect\.facebook\.net.*?/fbevents\.js", re.IGNORECASE), "Meta/Facebook Pixel", Severity.MEDIUM, "Meta Pixel überträgt Besucherdaten in die USA — ohne Consent DSGVO-Verstoß."),
    (re.compile(r"fbq\s*\(\s*['\"]init", re.IGNORECASE), "Meta/Facebook Pixel (fbq)", Severity.MEDIUM, "Meta Pixel aktiv auf der Seite."),
    (re.compile(r"googleadservices\.com", re.IGNORECASE), "Google Ads Conversion", Severity.MEDIUM, "Google Ads Tracking ohne Consent."),
    (re.compile(r"googlesyndication\.com", re.IGNORECASE), "Google AdSense", Severity.MEDIUM, "Google Werbebausteine ohne Consent."),
    (re.compile(r"static\.hotjar\.com/c/hotjar", re.IGNORECASE), "Hotjar", Severity.MEDIUM, "Hotjar Session Recording — DSGVO-relevant."),
    (re.compile(r"clarity\.ms/tag", re.IGNORECASE), "Microsoft Clarity", Severity.MEDIUM, "Clarity Session Replay — DSGVO-relevant."),
    (re.compile(r"analytics\.tiktok\.com", re.IGNORECASE), "TikTok Pixel", Severity.MEDIUM, "TikTok Tracking — DSGVO + CN-Datenübertragung."),
    (re.compile(r"px\.ads\.linkedin\.com", re.IGNORECASE), "LinkedIn Insight Tag", Severity.MEDIUM, "LinkedIn Tracking ohne Consent."),
    (re.compile(r"snap\.licdn\.com", re.IGNORECASE), "LinkedIn Insight Tag", Severity.MEDIUM, "LinkedIn Tracking."),
    (re.compile(r"twitter\.com/i/adsct", re.IGNORECASE), "X/Twitter Pixel", Severity.MEDIUM, "X/Twitter Conversion Tracking."),
    (re.compile(r"cdn\.matomo\.cloud", re.IGNORECASE), "Matomo Cloud", Severity.LOW, "Matomo Cloud — DSGVO-freundlicher, aber Consent weiterhin nötig."),
    (re.compile(r"/matomo\.php|/piwik\.php", re.IGNORECASE), "Matomo (self-hosted)", Severity.INFO, "Matomo selbst-gehostet — DSGVO-freundlichste Option."),
]

# --- Impressum required fields -----------------------------------------

IMPRESSUM_PATHS = ("/impressum", "/impressum/", "/imprint", "/impressum.html")

IMPRESSUM_REQUIRED = [
    (re.compile(r"(?:stra(?:ß|ss)e|stra(?:ß|ss)e\.)", re.IGNORECASE), "Anschrift (Straße)"),
    (re.compile(r"\b\d{5}\b"), "Anschrift (PLZ)"),
    (re.compile(r"(?:tel(?:efon)?|fon)[.:\s]*", re.IGNORECASE), "Telefon"),
    (re.compile(r"@[\w.-]+\.[a-z]{2,}", re.IGNORECASE), "E-Mail"),
    (re.compile(r"(?:ärztekammer|aerztekammer|kassenärztliche\s+vereinigung)", re.IGNORECASE), "Ärztekammer / Kassenärztliche Vereinigung"),
    (re.compile(r"berufsbezeichnung|approbation", re.IGNORECASE), "Berufsbezeichnung / Approbation"),
]


def _check_trackers(html_text: str, domain: str, result: ScanResult) -> None:
    hits: list[dict] = []
    for pattern, name, sev, rationale in TRACKER_PATTERNS:
        if pattern.search(html_text):
            hits.append({"name": name, "severity": sev.value, "rationale": rationale})

    if not hits:
        return

    result.metadata["trackers"] = hits

    # Deduplicate by name, pick highest severity per tracker.
    worst: dict[str, tuple[Severity, str]] = {}
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for h in hits:
        sev_obj = Severity(h["severity"])
        cur = worst.get(h["name"])
        if cur is None or sev_order[sev_obj.value] > sev_order[cur[0].value]:
            worst[h["name"]] = (sev_obj, h["rationale"])

    for name, (sev, rationale) in worst.items():
        result.add(Finding(
            id=f"privacy.tracker.{name.lower().replace(' ', '_').replace('/', '_')}",
            title=f"Tracker erkannt: {name}",
            description=(
                f"{rationale}\n\n"
                "Für MVZ/Arztpraxen gilt: Tracking-Tools dürfen nur nach aktiver "
                "Einwilligung (Consent-Banner-Opt-In) geladen werden. Bloßes "
                "Cookie-Banner reicht nicht — die Scripte dürfen vor dem Opt-In "
                "gar nicht im HTML auftauchen."
            ),
            severity=sev,
            category="DSGVO",
            evidence={"tracker": name},
            recommendation=(
                "Scripts komplett aus dem Quellcode entfernen wenn kein Consent-"
                "Management-System (z.B. Usercentrics, Cookiebot, Consentmanager) "
                "das Laden nach Opt-In steuert. Bei MVZ besser auf DSGVO-"
                "freundliche Alternativen wie Matomo self-hosted wechseln."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 1 (Datenminimierung)",
        ))


def _check_cookies(headers: dict, result: ScanResult) -> None:
    # Collect Set-Cookie values. httpx exposes them via headers.get_list but this scanner
    # only sees the already-parsed dict — so we re-parse from raw header bytes if available.
    raw = headers.get("set-cookie", "")
    if not raw:
        return

    cookies = raw.split(", ") if "," in raw else [raw]
    weak: list[dict] = []
    for cookie in cookies:
        parts = [p.strip().lower() for p in cookie.split(";")]
        name = parts[0].split("=", 1)[0] if parts else ""
        if not name:
            continue
        has_secure = "secure" in parts
        has_httponly = "httponly" in parts
        has_samesite = any(p.startswith("samesite=") for p in parts)
        if not (has_secure and has_httponly and has_samesite):
            weak.append(
                {
                    "name": name,
                    "secure": has_secure,
                    "httponly": has_httponly,
                    "samesite": has_samesite,
                }
            )

    if weak:
        result.metadata["cookie_security"] = weak
        missing_flags = set()
        for w in weak:
            if not w["secure"]:
                missing_flags.add("Secure")
            if not w["httponly"]:
                missing_flags.add("HttpOnly")
            if not w["samesite"]:
                missing_flags.add("SameSite")

        result.add(Finding(
            id="privacy.cookie_flags_missing",
            title=f"Cookies ohne Security-Flags ({', '.join(sorted(missing_flags))})",
            description=(
                f"Insgesamt {len(weak)} Cookie(s) werden ohne mindestens eines der "
                "Security-Flags gesetzt. Das erleichtert XSS, CSRF und MITM-Angriffe."
            ),
            severity=Severity.MEDIUM,
            category="Security Headers",
            evidence={"cookies": weak},
            recommendation=(
                "Alle Cookies auf Secure + HttpOnly + SameSite=Lax/Strict setzen. "
                "Bei Session-Cookies zwingend alle drei."
            ),
        ))


def _check_impressum(domain: str, result: ScanResult) -> None:
    # Use the browser UA that worked for the homepage pre-fetch (some WAFs
    # block unknown bots). Fallback to our UA.
    cached_ua = result.metadata.get("homepage_ua_used") or USER_AGENT

    def _try(client: httpx.Client, scheme: str) -> tuple[str, str] | None:
        for path in IMPRESSUM_PATHS:
            try:
                r = client.get(f"{scheme}://{domain}{path}")
                if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
                    return r.text, f"{scheme}://{domain}{path}"
            except httpx.HTTPError:
                continue
        return None

    impressum_html = ""
    impressum_url: str | None = None
    for ua in (cached_ua, USER_AGENT):
        for scheme in ("https", "http"):
            try:
                with httpx.Client(
                    timeout=10.0, follow_redirects=True,
                    headers={"User-Agent": ua}, verify=False,
                ) as client:
                    found = _try(client, scheme)
                if found:
                    impressum_html, impressum_url = found
                    break
            except httpx.HTTPError:
                continue
        if impressum_html:
            break

    if not impressum_html:
        result.add(Finding(
            id="privacy.impressum_missing",
            title="Impressum nicht gefunden",
            description=(
                "Unter den üblichen Pfaden (/impressum, /imprint) ist kein Impressum "
                "erreichbar. §5 DDG (früher TMG) verpflichtet jede gewerbliche Website "
                "zu einem vollständigen Impressum — fehlt es, drohen Abmahnungen."
            ),
            severity=Severity.MEDIUM,
            category="DSGVO",
            recommendation="Impressum unter /impressum anlegen mit allen nach §5 DDG + HWG erforderlichen Angaben.",
        ))
        return

    result.metadata["impressum"] = {"url": impressum_url}

    missing: list[str] = []
    for pattern, label in IMPRESSUM_REQUIRED:
        if not pattern.search(impressum_html):
            missing.append(label)

    if missing:
        # Compliance finding — significant risk of Abmahnung but no system-access impact.
        severity = Severity.MEDIUM if len(missing) >= 3 else Severity.LOW
        result.add(Finding(
            id="privacy.impressum_incomplete",
            title=f"Impressum unvollständig ({len(missing)} Pflichtangaben fehlen)",
            description=(
                "Im Impressum konnten folgende für Ärzte/MVZ üblicherweise erforderliche "
                f"Angaben nicht gefunden werden: {', '.join(missing)}. §5 DDG + HWG + "
                "Musterberufsordnung verlangen vollständige Angaben inkl. Ärztekammer, "
                "Aufsichtsbehörde und Berufsbezeichnung."
            ),
            severity=severity,
            category="DSGVO",
            evidence={"url": impressum_url, "missing": missing},
            recommendation=(
                "Impressum um die fehlenden Pflichtangaben ergänzen. "
                "Empfehlung: eRecht24- oder Kanzlei-Generator nutzen und von der "
                "zuständigen Ärztekammer gegenlesen lassen."
            ),
        ))


def check_privacy(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("DSGVO / Tracker / Impressum", 40)

    https_info = (result.metadata.get("http") or {}).get("https") or {}
    headers = https_info.get("headers") or {}

    # Reuse the homepage HTML + Set-Cookie list captured by osint.py (saves ~8s).
    html_text = result.metadata.get("homepage_html", "") or ""
    raw_cookies = result.metadata.get("homepage_cookies_raw")

    if not html_text or raw_cookies is None:
        # Fallback fetch when called outside the standard pipeline.
        try:
            with httpx.Client(
                timeout=8.0,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                r = client.get(f"https://{domain}")
                if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
                    if not html_text:
                        html_text = r.text[:500_000]
                    if raw_cookies is None:
                        raw_cookies = []
                        if hasattr(r.headers, "multi_items"):
                            for k, v in r.headers.multi_items():
                                if k.lower() == "set-cookie":
                                    raw_cookies.append(v)
        except httpx.HTTPError:
            pass

    if raw_cookies:
        headers = dict(headers)
        headers["set-cookie"] = ", ".join(raw_cookies)

    if html_text:
        _check_trackers(html_text, domain, result)
    _check_cookies(headers, result)
    _check_impressum(domain, result)
