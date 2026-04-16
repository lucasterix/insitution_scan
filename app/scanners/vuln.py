"""Vulnerability scanner.

Takes the tech fingerprint (Server/Generator/jQuery/Bootstrap versions already
parsed by `tech_fingerprint`), converts them to CPE strings, queries NVD for
matching CVEs, enriches with CISA KEV + EPSS, and emits severity-weighted
findings.

Results from NVD are cached in Redis for 24h to respect the public API's
rate limit (5 req / 30s without key; 50 req / 30s with key).
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable

from app.config import get_settings
from app.integrations.threat_intel import KEVCatalog, fetch_epss, fetch_nvd_cves_for_cpe
from app.queue import redis_conn
from app.scanners.base import Finding, ScanResult, Severity

CACHE_TTL_SECONDS = 24 * 3600

# Per-request delay so we stay well under NVD's rate limit.
_NVD_DELAY_NO_KEY = 6.5  # 5 req / 30s + margin
_NVD_DELAY_WITH_KEY = 0.7  # 50 req / 30s + margin


# Mapping of fingerprint keys (as written by tech_fingerprint.py) to a list of
# CPE vendor/product pairs. Multiple variants are merged (NVD historically
# published nginx under `nginx:nginx`; modern entries live under `f5:nginx`).
CPE_MAP: dict[str, list[tuple[str, str]]] = {
    "server.nginx": [("f5", "nginx"), ("nginx", "nginx")],
    "server.apache": [("apache", "http_server")],
    "server.apache-coyote": [("apache", "tomcat")],
    "server.iis": [("microsoft", "internet_information_services")],
    "server.caddy": [("caddyserver", "caddy")],
    "server.openresty": [("openresty", "openresty")],
    "wordpress": [("wordpress", "wordpress")],
    "jquery": [("jquery", "jquery")],
    "bootstrap": [("getbootstrap", "bootstrap")],
    # --- Banner-grab extractions from banner_grab.py ---
    "banner.openssh": [("openbsd", "openssh")],
    "banner.dropbear": [("dropbear_ssh_project", "dropbear_ssh"), ("matt_johnston", "dropbear_ssh")],
    "banner.proftpd": [("proftpd", "proftpd")],
    "banner.vsftpd": [("beasts", "vsftpd")],
    "banner.filezilla": [("filezilla-project", "filezilla_server")],
    "banner.sendmail": [("sendmail", "sendmail")],
    "banner.exim": [("exim", "exim")],
    "banner.dovecot": [("dovecot", "dovecot")],
    "banner.iis": [("microsoft", "internet_information_services")],
    "banner.apache_banner": [("apache", "http_server")],
    "banner.nginx_banner": [("f5", "nginx"), ("nginx", "nginx")],
    "banner.mariadb": [("mariadb", "mariadb")],
    "banner.mysql": [("oracle", "mysql"), ("mysql", "mysql")],
    # --- CMS core products ---
    "drupal": [("drupal", "drupal")],
    "typo3": [("typo3", "typo3")],
    "joomla": [("joomla", "joomla!"), ("joomla", "joomla")],
    # --- Popular WordPress plugins — CPE vendor/product varies in NVD ---
    "wp_plugin.contact-form-7": [("rocklobster", "contact_form_7"), ("takayukister", "contact_form_7")],
    "wp_plugin.woocommerce": [("woocommerce", "woocommerce"), ("automattic", "woocommerce")],
    "wp_plugin.elementor": [("elementor", "website_builder"), ("elementor", "elementor")],
    "wp_plugin.elementor-pro": [("elementor", "elementor_pro")],
    "wp_plugin.yoast-seo": [("yoast", "yoast_seo"), ("yoast", "wordpress_seo")],
    "wp_plugin.wordpress-seo": [("yoast", "yoast_seo")],
    "wp_plugin.wordfence": [("wordfence", "wordfence")],
    "wp_plugin.akismet": [("automattic", "akismet")],
    "wp_plugin.jetpack": [("automattic", "jetpack")],
    "wp_plugin.classic-editor": [("wordpress", "classic_editor")],
    "wp_plugin.wp-file-manager": [("webdesi9", "file_manager")],
    "wp_plugin.wp-super-cache": [("automattic", "wp_super_cache")],
    "wp_plugin.wp-rocket": [("wp-rocket", "wp_rocket")],
    "wp_plugin.updraftplus": [("updraftplus", "updraftplus")],
    "wp_plugin.duplicator": [("snapcreek", "duplicator")],
    "wp_plugin.ultimate-member": [("ultimatemember", "ultimate_member")],
    "wp_plugin.really-simple-ssl": [("really-simple-plugins", "really_simple_ssl")],
    "wp_plugin.essential-addons-for-elementor-lite": [("wpdeveloper", "essential_addons_for_elementor")],
}


def _cpe(vendor: str, product: str, version: str) -> str:
    """Build a CPE 2.3 string. NVD expects lowercase vendor/product."""
    return f"cpe:2.3:a:{vendor.lower()}:{product.lower()}:{version}:*:*:*:*:*:*:*"


def _cache_key(cpe: str) -> str:
    h = hashlib.sha1(cpe.encode()).hexdigest()[:16]
    return f"nvd:cpe:{h}"


def _cached_lookup(cpe: str) -> list[dict] | None:
    try:
        raw = redis_conn.get(_cache_key(cpe))
    except Exception:  # noqa: BLE001 — cache is best-effort
        return None
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _cache_store(cpe: str, cves: list[dict]) -> None:
    try:
        redis_conn.setex(_cache_key(cpe), CACHE_TTL_SECONDS, json.dumps(cves))
    except Exception:  # noqa: BLE001
        pass


def _severity_from(cve: dict, kev_entry: Any, epss_score: float | None) -> Severity:
    """Map CVSS score + KEV flag + EPSS score to our severity levels."""
    # KEV always means CRITICAL — CISA lists these because they are known to be exploited.
    if kev_entry:
        return Severity.CRITICAL

    score = cve.get("cvss_score")
    # EPSS > 0.5 means more than 50% likely to be exploited in the wild within 30 days.
    high_epss = epss_score is not None and epss_score >= 0.5

    if score is None:
        return Severity.MEDIUM if high_epss else Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL if high_epss else Severity.HIGH
    if score >= 7.0:
        return Severity.HIGH if high_epss else Severity.MEDIUM
    if score >= 4.0:
        return Severity.MEDIUM if high_epss else Severity.LOW
    return Severity.INFO if not high_epss else Severity.LOW


def _build_exploit_context(cve: dict, kev_entry: Any, epss_info: dict, component: str) -> str:
    """Build a rich exploit-context description for a CVE finding."""
    parts: list[str] = []
    cve_id = cve.get("id", "")
    cvss = cve.get("cvss_score")
    epss = epss_info.get("epss")
    desc_lower = (cve.get("description") or "").lower()

    # KEV status
    if kev_entry:
        parts.append(
            f"🔥 CISA KEV: Diese Schwachstelle wird AKTIV AUSGENUTZT "
            f"(gelistet seit {kev_entry.date_added})."
        )
        if kev_entry.known_ransomware_use:
            parts.append("⚠️ Bekanntermaßen in Ransomware-Kampagnen eingesetzt.")

    # EPSS context
    if epss is not None:
        pct = float(epss) * 100
        if pct >= 50:
            parts.append(
                f"📊 EPSS: {pct:.1f}% Wahrscheinlichkeit, dass diese Schwachstelle "
                "innerhalb der nächsten 30 Tage in freier Wildbahn ausgenutzt wird. "
                "Das ist extrem hoch — sofortiges Patchen ist geboten."
            )
        elif pct >= 10:
            parts.append(f"📊 EPSS: {pct:.1f}% Exploit-Wahrscheinlichkeit in 30 Tagen — erhöhtes Risiko.")
        else:
            parts.append(f"📊 EPSS: {pct:.1f}% Exploit-Wahrscheinlichkeit in 30 Tagen.")

    # Exploit type classification from description keywords
    attack_type = None
    if any(kw in desc_lower for kw in ("remote code execution", "rce", "arbitrary code")):
        attack_type = "Remote Code Execution (RCE)"
        parts.append(
            f"🎯 Angriffstyp: {attack_type} — ein Angreifer kann aus der Ferne "
            f"beliebigen Code auf dem Server ausführen. Bei {component} bedeutet das: "
            "voller Systemzugriff, Datenexfiltration, Ransomware-Deployment."
        )
    elif any(kw in desc_lower for kw in ("authentication bypass", "auth bypass", "bypass authentication")):
        attack_type = "Authentication Bypass"
        parts.append(
            f"🎯 Angriffstyp: {attack_type} — ein Angreifer umgeht die Login-Prüfung "
            f"und erhält Zugriff auf geschützte Bereiche von {component} ohne gültige Credentials."
        )
    elif any(kw in desc_lower for kw in ("privilege escalation", "escalation of privilege")):
        attack_type = "Privilege Escalation"
        parts.append(
            f"🎯 Angriffstyp: {attack_type} — ein Angreifer mit niedrigen Rechten "
            "kann sich zum Administrator/Root hochstufen."
        )
    elif any(kw in desc_lower for kw in ("sql injection", "sqli")):
        attack_type = "SQL Injection"
        parts.append(
            f"🎯 Angriffstyp: {attack_type} — ein Angreifer kann SQL-Befehle einschleusen "
            "und die Datenbank auslesen, ändern oder löschen."
        )
    elif any(kw in desc_lower for kw in ("denial of service", "dos ", " dos,", "crash")):
        attack_type = "Denial of Service"
        parts.append(
            f"🎯 Angriffstyp: Denial of Service — ein Angreifer kann {component} "
            "zum Absturz bringen oder unbrauchbar machen."
        )
    elif any(kw in desc_lower for kw in ("information disclosure", "information leak", "sensitive information")):
        attack_type = "Information Disclosure"
        parts.append(
            f"🎯 Angriffstyp: {attack_type} — ein Angreifer kann vertrauliche "
            "Informationen (Konfiguration, Schlüssel, Patientendaten) auslesen."
        )
    elif any(kw in desc_lower for kw in ("path traversal", "directory traversal", "file read")):
        attack_type = "Path Traversal / Arbitrary File Read"
        parts.append(
            f"🎯 Angriffstyp: {attack_type} — ein Angreifer kann beliebige Dateien "
            "vom Server lesen (/etc/passwd, Konfigurationsdateien, private Schlüssel)."
        )
    elif any(kw in desc_lower for kw in ("cross-site scripting", "xss")):
        attack_type = "Cross-Site Scripting (XSS)"
        parts.append(
            f"🎯 Angriffstyp: {attack_type} — ein Angreifer kann JavaScript im "
            "Browser anderer Nutzer ausführen (Session-Hijacking, Credential-Theft)."
        )

    # Tooling hint based on CVSS severity
    if cvss and cvss >= 9.0:
        parts.append(
            "🔧 Exploitation: Bei CVSS ≥ 9.0 existieren typischerweise fertige "
            "Exploit-Module in Metasploit/ExploitDB. Automatisierte Scanner wie "
            "Shodan markieren verwundbare Systeme innerhalb von Stunden nach "
            "CVE-Veröffentlichung."
        )
    elif cvss and cvss >= 7.0:
        parts.append(
            "🔧 Exploitation: Proof-of-Concept-Code ist für CVSS ≥ 7.0 häufig "
            "auf GitHub/ExploitDB verfügbar. Angreifer passen PoCs an und "
            "integrieren sie in automatisierte Scan-/Exploit-Toolkits."
        )

    return "\n\n".join([""] + parts) if parts else ""


def check_known_vulns(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    tech = result.metadata.get("tech") or {}
    if not tech:
        return

    # Build (key, display_product, version, [cpe_variants]) list.
    candidates: list[tuple[str, str, str, list[str]]] = []
    for key, version in tech.items():
        if not isinstance(version, str) or not version:
            continue

        # Strategy 1: Use CPE_MAP for manually mapped products.
        variants = CPE_MAP.get(key)
        if variants:
            display_product = variants[0][1]
            cpe_variants = [_cpe(v, p, version) for v, p in variants]
            candidates.append((key, display_product, version, cpe_variants))
            continue

        # Strategy 2: nmap_cpe.* keys contain product names extracted from nmap
        # XML CPE data. Build CPE strings automatically from the key name.
        if key.startswith("nmap_cpe."):
            product_name = key[len("nmap_cpe."):]
            # Common vendor guesses for well-known products
            vendor_guesses = [
                (product_name, product_name),
                ("apache", product_name) if "apache" in product_name.lower() else None,
                ("openbsd", product_name) if "openssh" in product_name.lower() else None,
                ("f5", product_name) if "nginx" in product_name.lower() else None,
            ]
            cpe_variants = [
                _cpe(v, p, version)
                for pair in vendor_guesses if pair
                for v, p in [pair]
            ]
            candidates.append((key, product_name, version, cpe_variants))
            continue

        # Strategy 3: nmap.* keys from nmap service detection
        if key.startswith("nmap."):
            product_name = key[len("nmap."):]
            cpe_variants = [_cpe(product_name, product_name, version)]
            candidates.append((key, product_name, version, cpe_variants))

    if not candidates:
        return

    step("Known CVE Lookup (NVD/KEV/EPSS)", 98)

    settings = get_settings()
    delay = _NVD_DELAY_WITH_KEY if settings.nvd_api_key else _NVD_DELAY_NO_KEY

    all_cves: dict[str, dict] = {}
    per_component: dict[str, list[str]] = {}

    queries_done = 0
    total_queries = sum(len(c[3]) for c in candidates)

    # Filter threshold: ignore CVEs published before this year unless they're
    # in CISA KEV. Older NVD entries often have overly broad CPE ranges that
    # produce false positives on modern software versions.
    CVE_MIN_YEAR = "2019"

    for key, display_product, version, cpe_variants in candidates:
        component_label = f"{display_product} {version}"
        merged_cves: dict[str, dict] = {}

        for cpe in cpe_variants:
            cached = _cached_lookup(cpe)
            if cached is not None:
                cves = cached
            else:
                cves = fetch_nvd_cves_for_cpe(cpe, limit=50)
                _cache_store(cpe, cves)
                queries_done += 1
                if queries_done < total_queries:
                    time.sleep(delay)

            for c in cves:
                # Skip very old CVEs unless they're in CISA KEV (actively exploited).
                published = c.get("published") or ""
                pub_year = published[:4]
                if pub_year and pub_year < CVE_MIN_YEAR:
                    kev_entry = KEVCatalog.lookup(c["id"])
                    if not kev_entry:
                        continue
                merged_cves[c["id"]] = c

        if not merged_cves:
            continue

        per_component[component_label] = list(merged_cves.keys())
        all_cves.update(merged_cves)

    if not all_cves:
        result.metadata["vuln_scan"] = {"components_checked": len(candidates), "cves_found": 0}
        return

    # Enrichment: KEV + EPSS in one go.
    kev = KEVCatalog.get()
    epss_map = fetch_epss(list(all_cves.keys()))

    # Keep only the top 10 worst per component to avoid drowning the report.
    MAX_PER_COMPONENT = 10
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for component, cve_ids in per_component.items():
        scored: list[tuple[Severity, dict]] = []
        for cid in cve_ids:
            cve = all_cves[cid]
            kev_entry = kev.get(cid.upper())
            epss_info = epss_map.get(cid.upper()) or {}
            epss_score = epss_info.get("epss")
            sev = _severity_from(cve, kev_entry, epss_score)
            scored.append((sev, cve))
        scored.sort(key=lambda x: (sev_order.get(x[0].value, 0), x[1].get("cvss_score") or 0), reverse=True)

        for sev, cve in scored[:MAX_PER_COMPONENT]:
            kev_entry = kev.get(cve["id"].upper())
            epss_info = epss_map.get(cve["id"].upper()) or {}
            evidence = {
                "cve_id": cve["id"],
                "component": component,
                "cvss_score": cve.get("cvss_score"),
                "cvss_severity": cve.get("cvss_severity"),
                "published": cve.get("published"),
                "in_kev": kev_entry is not None,
                "kev_ransomware": kev_entry.known_ransomware_use if kev_entry else False,
                "epss": epss_info.get("epss"),
                "epss_percentile": epss_info.get("percentile"),
            }

            prefix = "🔥 " if kev_entry else ""
            title = f"{prefix}{cve['id']} betrifft {component}"
            if cve.get("cvss_score") is not None:
                title += f" (CVSS {cve['cvss_score']})"

            description = cve.get("description") or "Keine Beschreibung verfügbar."

            # Add exploit context based on CVSS + EPSS + KEV
            exploit_context = _build_exploit_context(cve, kev_entry, epss_info, component)
            if exploit_context:
                description += exploit_context

            result.add(Finding(
                id=f"vuln.{cve['id']}",
                title=title,
                description=description,
                severity=sev,
                category="Known CVE",
                evidence=evidence,
                recommendation=f"{component} auf eine Version aktualisieren, die nicht mehr von {cve['id']} betroffen ist.",
                kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 3 (Patch-Management)",
            ))

    result.metadata["vuln_scan"] = {
        "components_checked": len(candidates),
        "components_with_cves": len(per_component),
        "total_cves_found": len(all_cves),
    }
