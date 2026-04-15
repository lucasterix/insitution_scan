"""Walk discovered subdomains and flag sensitive ones.

Input: `result.metadata["subdomains"]` (populated by the crt.sh check).
Output: per-subdomain alive/tech info + findings for sensitive subdomains.

Sensitive = contains keywords that typically indicate staging/admin/internal
systems that should never be public.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
HEAD_TIMEOUT = 5.0
MAX_SUBDOMAINS = 25
MAX_WORKERS = 10

SENSITIVE_KEYWORDS = {
    "staging": Severity.HIGH,
    "stage": Severity.HIGH,
    "dev": Severity.HIGH,
    "develop": Severity.HIGH,
    "test": Severity.MEDIUM,
    "qa": Severity.MEDIUM,
    "old": Severity.MEDIUM,
    "backup": Severity.HIGH,
    "archive": Severity.MEDIUM,
    "preview": Severity.MEDIUM,
    "beta": Severity.MEDIUM,
    "internal": Severity.HIGH,
    "intern": Severity.HIGH,
    "private": Severity.HIGH,
    "phpmyadmin": Severity.CRITICAL,
    "pma": Severity.CRITICAL,
    "admin": Severity.HIGH,
    "administrator": Severity.HIGH,
    "grafana": Severity.HIGH,
    "kibana": Severity.HIGH,
    "prometheus": Severity.HIGH,
    "jenkins": Severity.HIGH,
    "gitlab": Severity.HIGH,
    "git": Severity.HIGH,
    "bitbucket": Severity.HIGH,
    "jira": Severity.MEDIUM,
    "confluence": Severity.MEDIUM,
    "portainer": Severity.CRITICAL,
    "rancher": Severity.HIGH,
    "traefik": Severity.MEDIUM,
    "elastic": Severity.HIGH,
    "splunk": Severity.HIGH,
    "vpn": Severity.MEDIUM,
    "remote": Severity.MEDIUM,
    "rdp": Severity.CRITICAL,
    "exchange": Severity.MEDIUM,
    "owa": Severity.MEDIUM,
    "webmail": Severity.LOW,
    "mail": Severity.LOW,
    "cpanel": Severity.HIGH,
    "plesk": Severity.HIGH,
    "webdisk": Severity.HIGH,
    "ftp": Severity.MEDIUM,
    "sftp": Severity.LOW,
    "mysql": Severity.HIGH,
    "mariadb": Severity.HIGH,
    "mongo": Severity.HIGH,
    "mongodb": Severity.HIGH,
    "redis": Severity.HIGH,
    "db": Severity.MEDIUM,
    "database": Severity.MEDIUM,
    "old-site": Severity.HIGH,
    "alt": Severity.LOW,
    "tmp": Severity.MEDIUM,
    "temp": Severity.MEDIUM,
}


def _check_one(sub: str) -> dict | None:
    urls = (f"https://{sub}", f"http://{sub}")
    for url in urls:
        try:
            with httpx.Client(
                timeout=HEAD_TIMEOUT,
                follow_redirects=True,
                verify=False,  # sub-certs often mismatched / self-signed — we still want the info
                headers={"User-Agent": USER_AGENT},
            ) as client:
                # Some servers reject HEAD; fall back to GET.
                try:
                    r = client.head(url)
                    if r.status_code == 405:
                        r = client.get(url)
                except httpx.HTTPError:
                    r = client.get(url)
                return {
                    "scheme": url.split(":", 1)[0],
                    "status": r.status_code,
                    "server": r.headers.get("server", ""),
                    "final_url": str(r.url),
                    "title_hint": r.headers.get("x-powered-by", ""),
                    "content_length": r.headers.get("content-length"),
                }
        except httpx.HTTPError:
            continue
    return None


def _sensitivity(subdomain: str, domain: str) -> tuple[Severity | None, list[str]]:
    """Return (highest severity, matched keywords) for a subdomain name."""
    local = subdomain
    if local.endswith(domain):
        local = local[: -len(domain)].rstrip(".")
    tokens = [t for t in local.replace("-", ".").split(".") if t]
    matches: list[str] = []
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    worst: Severity | None = None
    for token in tokens:
        if token.lower() in SENSITIVE_KEYWORDS:
            sev = SENSITIVE_KEYWORDS[token.lower()]
            matches.append(token.lower())
            if worst is None or sev_order[sev.value] > sev_order[worst.value]:
                worst = sev
    return worst, matches


def walk_subdomains(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    subs = result.metadata.get("subdomains") or []
    if not subs:
        return

    unique = [s for s in dict.fromkeys(subs) if "*" not in s and s != domain]
    if not unique:
        return

    step(f"Subdomain-Walk ({min(len(unique), MAX_SUBDOMAINS)})", 78)

    to_check = unique[:MAX_SUBDOMAINS]
    alive: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(_check_one, s): s for s in to_check}
        for fut in as_completed(futures):
            sub = futures[fut]
            info = fut.result()
            if info is not None:
                alive[sub] = info

    result.metadata["subdomain_walk"] = {
        "checked": len(to_check),
        "alive": len(alive),
        "results": alive,
    }

    for sub, info in alive.items():
        sev, matches = _sensitivity(sub, domain)
        if sev is None:
            continue
        result.add(Finding(
            id=f"subdomain.sensitive.{sub}",
            title=f"Sensible Subdomain öffentlich erreichbar: {sub}",
            description=(
                f"HTTP {info['status']} auf {sub} (reachable via {info['scheme']}). "
                f"Die Benennung ({', '.join(matches)}) weist auf ein internes/Entwicklungs-/Admin-System hin. "
                "Solche Subdomains sind ein klassischer Einstiegspunkt für Angreifer, weil sie oft veraltete "
                "Software, schwache Credentials oder Debug-Endpunkte enthalten."
            ),
            severity=sev,
            category="Subdomain Exposure",
            evidence={
                "subdomain": sub,
                "status": info["status"],
                "server": info.get("server"),
                "matched_keywords": matches,
            },
            recommendation=(
                "Entweder hinter VPN/IP-Whitelist stellen, mit HTTP-Basic-Auth schützen, "
                "oder komplett offline nehmen. Kein direkter Internet-Zugriff."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 3 (Netzwerk-Segmentierung)",
        ))
