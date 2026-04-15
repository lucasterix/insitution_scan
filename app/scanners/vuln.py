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


# Mapping of fingerprint keys (as written by tech_fingerprint.py) to
# CPE vendor/product pairs. Extend this as new detections are added.
CPE_MAP: dict[str, tuple[str, str]] = {
    "server.nginx": ("nginx", "nginx"),
    "server.apache": ("apache", "http_server"),
    "server.apache-coyote": ("apache", "tomcat"),
    "server.iis": ("microsoft", "internet_information_services"),
    "server.caddy": ("caddyserver", "caddy"),
    "server.openresty": ("openresty", "openresty"),
    "wordpress": ("wordpress", "wordpress"),
    "jquery": ("jquery", "jquery"),
    "bootstrap": ("getbootstrap", "bootstrap"),
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


def check_known_vulns(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    tech = result.metadata.get("tech") or {}
    if not tech:
        return

    # Build (key, vendor, product, version) list for detected components.
    candidates: list[tuple[str, str, str, str]] = []
    for key, version in tech.items():
        if not isinstance(version, str) or not version:
            continue
        mapping = CPE_MAP.get(key)
        if not mapping:
            continue
        vendor, product = mapping
        candidates.append((key, vendor, product, version))

    if not candidates:
        return

    step("Known CVE Lookup (NVD/KEV/EPSS)", 98)

    settings = get_settings()
    delay = _NVD_DELAY_WITH_KEY if settings.nvd_api_key else _NVD_DELAY_NO_KEY

    all_cves: dict[str, dict] = {}
    per_component: dict[str, list[str]] = {}

    for idx, (key, vendor, product, version) in enumerate(candidates):
        cpe = _cpe(vendor, product, version)

        cached = _cached_lookup(cpe)
        if cached is not None:
            cves = cached
        else:
            cves = fetch_nvd_cves_for_cpe(cpe, limit=50)
            _cache_store(cpe, cves)
            if idx < len(candidates) - 1:
                time.sleep(delay)

        if not cves:
            continue

        per_component[f"{product} {version}"] = [c["id"] for c in cves]
        for c in cves:
            all_cves[c["id"]] = c

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
            if kev_entry:
                description += f"\n\nCISA KEV: in der Liste aktiv ausgenutzter Schwachstellen seit {kev_entry.date_added}."
                if kev_entry.known_ransomware_use:
                    description += " Wird bekanntermaßen in Ransomware-Kampagnen eingesetzt."
            if epss_info.get("epss") is not None:
                description += f"\n\nEPSS: {float(epss_info['epss']) * 100:.1f}% Exploit-Wahrscheinlichkeit innerhalb 30 Tagen."

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
