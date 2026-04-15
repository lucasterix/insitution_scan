"""Threat-intel helpers: CISA KEV, EPSS, NVD.

All three sources are free and require no key (NVD has an optional key
for higher rate limits — we pass it in the header when configured).

The KEV catalog is ~1500 rows, so we fetch it on demand and cache in memory.
EPSS and NVD are queried per CVE.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import get_settings

USER_AGENT = "MVZ-SelfScan/1.0"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class KEVEntry:
    cve_id: str
    vendor: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_use: bool


class KEVCatalog:
    """In-process cache of CISA's Known Exploited Vulnerabilities catalog."""

    _cache: dict[str, KEVEntry] | None = None
    _fetched_at: float = 0.0
    TTL_SECONDS = 6 * 3600  # refresh every 6h

    @classmethod
    def _fetch(cls) -> dict[str, KEVEntry] | None:
        try:
            r = httpx.get(KEV_URL, timeout=20.0, headers={"User-Agent": USER_AGENT})
            r.raise_for_status()
            data = r.json()
        except (httpx.HTTPError, ValueError):
            return None

        out: dict[str, KEVEntry] = {}
        for v in data.get("vulnerabilities", []):
            cve = v.get("cveID", "").upper()
            if not cve:
                continue
            out[cve] = KEVEntry(
                cve_id=cve,
                vendor=v.get("vendorProject", ""),
                product=v.get("product", ""),
                vulnerability_name=v.get("vulnerabilityName", ""),
                date_added=v.get("dateAdded", ""),
                short_description=v.get("shortDescription", ""),
                required_action=v.get("requiredAction", ""),
                due_date=v.get("dueDate", ""),
                known_ransomware_use=str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            )
        return out

    @classmethod
    def get(cls) -> dict[str, KEVEntry]:
        now = time.monotonic()
        if cls._cache is None or (now - cls._fetched_at) > cls.TTL_SECONDS:
            fetched = cls._fetch()
            if fetched is not None:
                cls._cache = fetched
                cls._fetched_at = now
        return cls._cache or {}

    @classmethod
    def lookup(cls, cve_id: str) -> KEVEntry | None:
        return cls.get().get(cve_id.upper())


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """Return {cve_id: {epss, percentile, date}} for the given CVEs."""
    if not cve_ids:
        return {}
    out: dict[str, dict] = {}
    # EPSS accepts comma-separated, up to ~100 at once
    for i in range(0, len(cve_ids), 80):
        batch = cve_ids[i : i + 80]
        try:
            r = httpx.get(
                EPSS_URL,
                params={"cve": ",".join(batch)},
                timeout=15.0,
                headers={"User-Agent": USER_AGENT},
            )
            r.raise_for_status()
            data = r.json()
        except (httpx.HTTPError, ValueError):
            continue
        for row in data.get("data", []):
            cve = row.get("cve")
            if not cve:
                continue
            out[cve] = {
                "epss": float(row.get("epss", 0)),
                "percentile": float(row.get("percentile", 0)),
                "date": row.get("date"),
            }
    return out


def fetch_nvd_cve(cve_id: str) -> dict | None:
    """Fetch detailed CVE metadata from NVD. Uses API key if configured."""
    settings = get_settings()
    headers = {"User-Agent": USER_AGENT}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    try:
        r = httpx.get(
            NVD_URL,
            params={"cveId": cve_id},
            timeout=15.0,
            headers=headers,
        )
        r.raise_for_status()
        data = r.json()
    except (httpx.HTTPError, ValueError):
        return None
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    return vulns[0].get("cve")


def enrich_cves(cve_ids: list[str]) -> dict[str, dict[str, Any]]:
    """One-shot enrichment: for each CVE return KEV flag + EPSS score.

    This is the function the vuln scanner module will call once we start
    detecting actual CVEs from service banners / software versions.
    """
    if not cve_ids:
        return {}
    kev = KEVCatalog.get()
    epss = fetch_epss(cve_ids)
    out: dict[str, dict[str, Any]] = {}
    for cve in cve_ids:
        cve_u = cve.upper()
        entry = kev.get(cve_u)
        out[cve_u] = {
            "in_kev": entry is not None,
            "kev_ransomware": entry.known_ransomware_use if entry else False,
            "kev_due_date": entry.due_date if entry else None,
            "epss": epss.get(cve_u, {}).get("epss"),
            "epss_percentile": epss.get(cve_u, {}).get("percentile"),
        }
    return out
