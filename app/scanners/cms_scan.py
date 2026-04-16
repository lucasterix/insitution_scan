"""CMS fingerprinting + WordPress plugin/theme enumeration.

For German MVZ sites WordPress dominates — the #1 attack vector is an outdated
plugin with a known unauthenticated RCE. This scanner:

1. Detects WordPress / Drupal / TYPO3 / Joomla from HTML + headers.
2. Extracts the WordPress version from meta generator, readme.html and
   wp-embed.js ?ver= query.
3. Enumerates all /wp-content/plugins/* and /wp-content/themes/* references
   including version numbers from ?ver= query parameters.
4. Runs the detected plugins through a hard-coded "known-dangerous-if-outdated"
   list (CVE-2020-25213 wp-file-manager, CVE-2020-35489 Contact Form 7, etc.).
5. Probes user enumeration endpoints (/wp-json/wp/v2/users, /?author=1..3).
6. Checks /xmlrpc.php and /readme.html.
7. Feeds WordPress + plugin versions into result.metadata["tech"] so the
   downstream CVE scanner (NVD + KEV + EPSS) picks them up automatically.
"""
from __future__ import annotations

import re
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
TIMEOUT = 6.0

META_GEN_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
WP_PLUGIN_RE = re.compile(
    r'/wp-content/plugins/([a-zA-Z0-9_\-]+)/[^\s\'">]*?(?:\?ver=([\w.\-]+))?["\'\s>]',
    re.IGNORECASE,
)
WP_THEME_RE = re.compile(
    r'/wp-content/themes/([a-zA-Z0-9_\-]+)/[^\s\'">]*?(?:\?ver=([\w.\-]+))?["\'\s>]',
    re.IGNORECASE,
)
WP_EMBED_VER_RE = re.compile(r'wp-embed(?:\.min)?\.js\?ver=([\d.]+)', re.IGNORECASE)
WP_READMES_VER_RE = re.compile(r'Version\s+([\d.]+)', re.IGNORECASE)

DRUPAL_VER_RE = re.compile(r'Drupal\s+([\d.]+)', re.IGNORECASE)
TYPO3_VER_RE = re.compile(r'TYPO3\s*(?:CMS)?\s*([\d.]+)?', re.IGNORECASE)
JOOMLA_VER_RE = re.compile(r'Joomla!?\s*([\d.]+)?', re.IGNORECASE)

# (plugin_slug, min_safe_version, severity, description_of_cve)
KNOWN_BAD_PLUGINS: list[tuple[str, str, Severity, str]] = [
    ("wp-file-manager", "7.0",
     Severity.CRITICAL, "CVE-2020-25213 — unauthenticated RCE, massenhaft ausgenutzt"),
    ("file-manager", "7.0",
     Severity.CRITICAL, "CVE-2020-25213 — unauthenticated RCE"),
    ("contact-form-7", "5.3.2",
     Severity.HIGH, "CVE-2020-35489 — unrestricted file upload"),
    ("elementor", "3.5.0",
     Severity.HIGH, "CVE-2022-1329 — auth bypass"),
    ("elementor-pro", "3.11.7",
     Severity.CRITICAL, "CVE-2023-3096 — broken access control, RCE in Form Submissions"),
    ("essential-addons-for-elementor-lite", "5.7.2",
     Severity.CRITICAL, "CVE-2023-32243 — unauthenticated privilege escalation"),
    ("ultimate-member", "2.6.7",
     Severity.CRITICAL, "CVE-2023-3460 — unauthenticated admin-account creation"),
    ("all-in-one-wp-migration", "7.78",
     Severity.HIGH, "CVE-2023-40004 — auth bypass"),
    ("backup-migration", "1.3.8",
     Severity.CRITICAL, "CVE-2023-6553 — unauthenticated RCE (BackupBuddy)"),
    ("wpdiscuz", "7.0.5",
     Severity.CRITICAL, "CVE-2020-24186 — unauthenticated RCE via avatar upload"),
    ("duplicator", "1.5.7.1",
     Severity.HIGH, "CVE-2023-xxx — path traversal"),
    ("better-search-replace", "1.4.5",
     Severity.HIGH, "CVE-2023-6933 — PHP object injection"),
    ("wp-statistics", "13.2.9",
     Severity.HIGH, "CVE-2022-25609 — SQL injection"),
    ("loginizer", "1.6.4",
     Severity.HIGH, "CVE-2020-27615 — SQL injection in login"),
    ("royal-elementor-addons", "1.3.79",
     Severity.HIGH, "CVE-2023-5360 — file upload auth bypass"),
    ("forminator", "1.24.6",
     Severity.HIGH, "CVE-2023-5821 — arbitrary file upload"),
    ("really-simple-ssl", "7.0.6",
     Severity.CRITICAL, "CVE-2023-6875 — authentication bypass"),
]


def _detect_cms_signals(html: str, headers: dict) -> dict:
    signals: dict = {}
    html_lower = html.lower()
    if "wp-content" in html_lower or "wp-includes" in html_lower or "wp-json" in html_lower:
        signals["wordpress"] = True
    if "sites/default/files" in html_lower or "drupal.js" in html_lower:
        signals["drupal"] = True
    if "typo3conf" in html_lower or "typo3temp" in html_lower:
        signals["typo3"] = True
    if "components/com_" in html_lower or "/modules/mod_" in html_lower:
        signals["joomla"] = True
    # Headers
    powered = headers.get("x-powered-by", "").lower()
    if "wordpress" in powered:
        signals["wordpress"] = True
    return signals


def _extract_wp_version(html: str, client: httpx.Client, domain: str) -> str | None:
    # 1. Meta generator
    gen = META_GEN_RE.search(html)
    if gen:
        m = re.search(r"WordPress\s+([\d.]+)", gen.group(1), re.IGNORECASE)
        if m:
            return m.group(1)
    # 2. wp-embed ?ver=
    m = WP_EMBED_VER_RE.search(html)
    if m:
        return m.group(1)
    # 3. readme.html
    try:
        r = client.get(f"https://{domain}/readme.html")
        if r.status_code == 200:
            m = WP_READMES_VER_RE.search(r.text[:800])
            if m:
                return m.group(1)
    except httpx.HTTPError:
        pass
    return None


def _extract_plugins_and_themes(html: str) -> tuple[dict[str, str | None], dict[str, str | None]]:
    """Parse /wp-content/plugins/<slug>/... and themes — return {slug: best_version}."""
    plugins: dict[str, str | None] = {}
    themes: dict[str, str | None] = {}

    # Plugin regex matches slug + optional version
    for m in WP_PLUGIN_RE.finditer(html):
        slug = m.group(1)
        version = m.group(2)
        if slug not in plugins or (version and not plugins[slug]):
            plugins[slug] = version

    for m in WP_THEME_RE.finditer(html):
        slug = m.group(1)
        version = m.group(2)
        if slug not in themes or (version and not themes[slug]):
            themes[slug] = version

    return plugins, themes


def _check_user_enum_wp_json(client: httpx.Client, domain: str, result: ScanResult) -> None:
    try:
        r = client.get(f"https://{domain}/wp-json/wp/v2/users")
    except httpx.HTTPError:
        return
    if r.status_code != 200:
        return
    if "application/json" not in r.headers.get("content-type", "").lower():
        return
    try:
        users = r.json()
    except ValueError:
        return
    if not isinstance(users, list) or not users:
        return
    usernames = [
        (u.get("slug") or u.get("name", "")) for u in users if isinstance(u, dict)
    ]
    usernames = [u for u in usernames if u]
    if not usernames:
        return
    result.metadata.setdefault("wordpress", {})["users_enumerated"] = usernames
    result.add(
        Finding(
            id="wp.user_enum_wp_json",
            title=f"WordPress: {len(usernames)} Benutzernamen über /wp-json/wp/v2/users auslesbar",
            description=(
                "Die WordPress REST-API gibt die Liste aller Autoren ohne Authentifizierung "
                "an jeden Besucher heraus. Angreifer kennen damit jeden Login-Namen und können "
                "gezielt Brute-Force bzw. Credential-Stuffing ausführen. Für MVZ-Sites "
                "der häufigste Vorstufen-Exploit vor einem Komplettübernahme-Angriff."
            ),
            # Usernames alone don't compromise anything — they're input for brute-force
            # that still needs to succeed against rate-limiting + password strength.
            severity=Severity.MEDIUM,
            category="WordPress",
            evidence={"usernames": usernames[:20]},
            recommendation=(
                "wp-json/wp/v2/users per Security-Plugin (Wordfence, iThemes Security) oder "
                ".htaccess sperren. Alternativ in functions.php die REST-Users-Route auf "
                "capability_type 'edit_users' einschränken."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (Zugriffskontrolle)",
        )
    )


def _check_author_enum(client: httpx.Client, domain: str, result: ScanResult) -> None:
    leaked: list[str] = []
    for author_id in (1, 2, 3):
        try:
            r = client.get(f"https://{domain}/?author={author_id}", follow_redirects=False)
        except httpx.HTTPError:
            continue
        if r.status_code in (301, 302, 303):
            location = r.headers.get("location", "")
            m = re.search(r"/author/([^/?]+)", location)
            if m:
                leaked.append(m.group(1))
    if leaked:
        result.metadata.setdefault("wordpress", {})["author_enum"] = leaked
        result.add(
            Finding(
                id="wp.author_enum",
                title=f"WordPress: Autor-Enumeration via ?author= leakt Logins ({len(leaked)})",
                description=(
                    "Die URL /?author=<id> redirected zu /author/<username>/ und verrät "
                    "den tatsächlichen Login-Namen. Klassische Vorstufe für Brute-Force."
                ),
                severity=Severity.MEDIUM,
                category="WordPress",
                evidence={"leaked_usernames": leaked},
                recommendation="Autor-Archive deaktivieren oder in functions.php 'author=' abfangen.",
            )
        )


def _check_xmlrpc(client: httpx.Client, domain: str, result: ScanResult) -> None:
    try:
        r = client.get(f"https://{domain}/xmlrpc.php")
    except httpx.HTTPError:
        return
    status = r.status_code
    body_start = (r.text or "")[:400]
    is_xmlrpc = status == 405 or ("XML-RPC" in body_start) or ("xmlrpc" in body_start.lower())
    if not is_xmlrpc:
        return
    result.metadata.setdefault("wordpress", {})["xmlrpc"] = True
    result.add(
        Finding(
            id="wp.xmlrpc_enabled",
            title="WordPress xmlrpc.php erreichbar — Brute-Force-Amplifier",
            description=(
                "xmlrpc.php ist von außen ansprechbar. Die system.multicall-Methode erlaubt "
                "es Angreifern, hunderte Login-Versuche pro HTTP-Request zu bündeln und "
                "damit Rate-Limit und WAF zu umgehen. Pingback-Methoden lassen sich außerdem "
                "als DDoS-Amplifier missbrauchen."
            ),
            severity=Severity.MEDIUM,
            category="WordPress",
            recommendation=(
                "xmlrpc.php per .htaccess oder nginx-location-Block auf 403 setzen. "
                "Wenn Jetpack / mobile App nicht genutzt werden, einfach komplett sperren."
            ),
        )
    )


def _check_readme(client: httpx.Client, domain: str, result: ScanResult) -> None:
    try:
        r = client.get(f"https://{domain}/readme.html")
    except httpx.HTTPError:
        return
    if r.status_code != 200:
        return
    if "WordPress" not in r.text[:500]:
        return
    result.add(
        Finding(
            id="wp.readme_exposed",
            title="WordPress readme.html öffentlich erreichbar",
            description=(
                "readme.html enthält in den ersten Zeilen die exakte WordPress-Version — "
                "erste Amtshandlung jedes Scan-Bots. Außerdem entsteht ein eindeutiger Fingerprint "
                "der CMS-Plattform, selbst wenn das Meta-Generator-Tag entfernt wurde."
            ),
            severity=Severity.LOW,
            category="WordPress",
            recommendation="readme.html löschen oder per .htaccess/nginx auf 403 setzen.",
        )
    )


def _check_known_bad_plugins(plugins: dict[str, str | None], result: ScanResult) -> None:
    try:
        from packaging.version import Version
    except ImportError:  # pragma: no cover
        return

    for slug, min_safe, sev, cve_desc in KNOWN_BAD_PLUGINS:
        if slug not in plugins:
            continue
        version = plugins[slug]
        if version is None:
            result.add(
                Finding(
                    id=f"wp.plugin.{slug}.version_unknown",
                    title=f"WP-Plugin {slug} aktiv, Version unbekannt",
                    description=(
                        f"Das Plugin '{slug}' wird geladen, die Version lässt sich nicht aus "
                        f"der HTML-Ausgabe ablesen. Historisch hatte dieses Plugin kritische "
                        f"Lücken: {cve_desc}. Bitte manuell Version prüfen."
                    ),
                    severity=Severity.INFO,
                    category="WordPress",
                    evidence={"plugin": slug, "known_cve": cve_desc},
                )
            )
            continue
        try:
            if Version(version) < Version(min_safe):
                result.add(
                    Finding(
                        id=f"wp.plugin.{slug}.outdated",
                        title=f"WP-Plugin {slug} {version} ist verwundbar",
                        description=(
                            f"Detektierte Version: {version}. Mindestens sichere Version: {min_safe}.\n"
                            f"Bekannte Schwachstelle: {cve_desc}.\n"
                            "Diese Lücke wird massenhaft durch automatisierte Bot-Netze "
                            "ausgenutzt — für MVZ-Websites eines der Haupteinfallstore."
                        ),
                        severity=sev,
                        category="WordPress",
                        evidence={"plugin": slug, "version": version, "min_safe": min_safe, "cve": cve_desc},
                        recommendation=f"Plugin sofort auf >= {min_safe} aktualisieren oder deaktivieren.",
                        kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (Patch-Management)",
                    )
                )
        except Exception:  # noqa: BLE001 — Version.parse can raise on odd version strings
            continue


def check_cms(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("CMS & Plugin Scanner", 93)

    try:
        with httpx.Client(
            timeout=TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            r = client.get(f"https://{domain}")
            if r.status_code != 200 or "text/html" not in r.headers.get("content-type", "").lower():
                return
            html = r.text[:500_000]
            headers_dict = {k.lower(): v for k, v in r.headers.items()}

            signals = _detect_cms_signals(html, headers_dict)
            if not signals:
                return

            cms_data = result.metadata.setdefault("cms", {})
            cms_data["signals"] = sorted(signals.keys())

            if signals.get("wordpress"):
                wp_version = _extract_wp_version(html, client, domain)
                if wp_version:
                    cms_data["wordpress_version"] = wp_version
                    result.metadata.setdefault("tech", {})["wordpress"] = wp_version
                    result.add(
                        Finding(
                            id="wp.version_detected",
                            title=f"WordPress {wp_version} erkannt",
                            description=(
                                f"WordPress-Version {wp_version} wird auf der Website offengelegt. "
                                "Der CVE-Scanner dieser Pipeline prüft automatisch NVD + CISA KEV + "
                                "EPSS für diese Version."
                            ),
                            severity=Severity.LOW,
                            category="WordPress",
                            evidence={"version": wp_version},
                            recommendation=(
                                "Generator-Tag entfernen, readme.html löschen, 'WP Hide & "
                                "Security Enhancer' oder vergleichbares Plugin nutzen."
                            ),
                        )
                    )

                plugins, themes = _extract_plugins_and_themes(html)
                cms_data["plugins"] = plugins
                cms_data["themes"] = themes

                tech = result.metadata.setdefault("tech", {})
                for slug, v in plugins.items():
                    if v:
                        tech[f"wp_plugin.{slug}"] = v
                for slug, v in themes.items():
                    if v:
                        tech[f"wp_theme.{slug}"] = v

                if plugins:
                    summary_items = [f"{k}@{v or '?'}" for k, v in list(plugins.items())[:12]]
                    result.add(
                        Finding(
                            id="wp.plugins_detected",
                            title=f"WordPress: {len(plugins)} Plugin(s), {len(themes)} Theme(s) erkannt",
                            description=(
                                "Im HTML referenzierte Plugins (mit Version wo lesbar):\n"
                                + ", ".join(summary_items)
                            ),
                            severity=Severity.INFO,
                            category="WordPress",
                            evidence={"plugins": plugins, "themes": themes},
                        )
                    )

                _check_known_bad_plugins(plugins, result)
                _check_user_enum_wp_json(client, domain, result)
                _check_author_enum(client, domain, result)
                _check_xmlrpc(client, domain, result)
                _check_readme(client, domain, result)

            if signals.get("drupal"):
                gen = META_GEN_RE.search(html)
                version = None
                if gen:
                    m = DRUPAL_VER_RE.search(gen.group(1))
                    if m:
                        version = m.group(1)
                if version:
                    result.metadata.setdefault("tech", {})["drupal"] = version
                cms_data["drupal_version"] = version
                result.add(
                    Finding(
                        id="cms.drupal_detected",
                        title=f"Drupal CMS erkannt{' v' + version if version else ''}",
                        description="Drupal: CHANGELOG.txt manuell prüfen, Security-Advisories abonnieren.",
                        severity=Severity.INFO,
                        category="CMS",
                    )
                )

            if signals.get("typo3"):
                m = TYPO3_VER_RE.search(html)
                version = m.group(1) if (m and m.group(1)) else None
                if version:
                    result.metadata.setdefault("tech", {})["typo3"] = version
                cms_data["typo3_version"] = version
                result.add(
                    Finding(
                        id="cms.typo3_detected",
                        title=f"TYPO3 CMS erkannt{' v' + version if version else ''}",
                        description=(
                            "TYPO3 ist im deutschen Mittelstand weit verbreitet. "
                            "Aktuelle Security Advisories unter typo3.org/help/security-advisories."
                        ),
                        severity=Severity.INFO,
                        category="CMS",
                    )
                )

            if signals.get("joomla"):
                gen = META_GEN_RE.search(html)
                version = None
                if gen:
                    m = JOOMLA_VER_RE.search(gen.group(1))
                    if m and m.group(1):
                        version = m.group(1)
                if version:
                    result.metadata.setdefault("tech", {})["joomla"] = version
                cms_data["joomla_version"] = version
                result.add(
                    Finding(
                        id="cms.joomla_detected",
                        title=f"Joomla CMS erkannt{' v' + version if version else ''}",
                        description="Joomla-Extensions sind die Haupt-Lückenquelle — alle Extensions aktuell halten.",
                        severity=Severity.INFO,
                        category="CMS",
                    )
                )
    except httpx.HTTPError:
        return
