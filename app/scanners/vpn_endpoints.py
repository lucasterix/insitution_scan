"""VPN / SSL-Gateway endpoint detection.

Probes a curated list of well-known SSL-VPN and remote-access portal login
pages. MVZs with an IT service provider often run Fortinet, Pulse Secure
(now Ivanti), Palo Alto GlobalProtect, F5 Big-IP, Cisco ASA, SonicWall or
Check Point appliances. All of these have had critical zero-days in the
last 24 months — detecting their presence is step one.

Every probe uses SPA-catch-all defense via the shared baseline helper.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import httpx

from app.scanners._baseline import fetch_baselines, is_catchall
from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
TIMEOUT = 6.0
MAX_WORKERS = 6

# (path, content_hints, vendor, notable_cves)
VPN_PROBES: list[tuple[str, tuple[str, ...], str, str]] = [
    ("/remote/login", ("fortinet", "fortigate", "ssl vpn"), "Fortinet FortiGate SSL VPN",
     "CVE-2022-40684 (auth bypass), CVE-2023-27997 (pre-auth RCE), CVE-2018-13379 (path traversal)"),
    ("/remote/logincheck", ("fortinet", "fortigate"), "Fortinet FortiGate SSL VPN",
     "CVE-2022-40684, CVE-2023-27997"),
    ("/global-protect/login.esp", ("globalprotect", "palo alto"), "Palo Alto GlobalProtect",
     "CVE-2024-3400 (pre-auth RCE), CVE-2020-2021 (SAML auth bypass)"),
    ("/dana-na/auth/url_default/welcome.cgi", ("pulse", "ivanti"), "Pulse Secure / Ivanti Connect Secure",
     "CVE-2019-11510 (pre-auth file read), CVE-2023-46805 + CVE-2024-21887 (Ivanti zero-day chain)"),
    ("/my.policy", ("big-ip", "f5"), "F5 Big-IP APM / Edge Gateway",
     "CVE-2022-1388 (iControl auth bypass), CVE-2023-46747"),
    ("/+CSCOE+/logon.html", ("cisco", "anyconnect", "asa"), "Cisco ASA / AnyConnect",
     "CVE-2020-3580 (XSS), CVE-2018-0101 (RCE)"),
    ("/+CSCOT+/help.html", ("cisco",), "Cisco ASA",
     "—"),
    ("/sslvpn/portal.cgi", ("sslvpn",), "Generic SSL VPN Portal", "—"),
    ("/sonicwall", ("sonicwall",), "SonicWall SSL-VPN / NetExtender",
     "CVE-2021-20016 (SMA 100 zero-day), CVE-2024-40766"),
    ("/prx/000/http/localh/welcome.html", ("check point", "mobile access"), "Check Point Mobile Access",
     "CVE-2024-24919 (pre-auth file read)"),
    ("/vpn/index.html", ("citrix", "netscaler", "gateway"), "Citrix NetScaler / ADC",
     "CVE-2019-19781 (pre-auth RCE), CVE-2023-3519 (pre-auth RCE), CVE-2023-4966 Citrix Bleed"),
    ("/vpn/", ("citrix", "netscaler"), "Citrix NetScaler",
     "CVE-2023-4966 Citrix Bleed"),
    ("/logon/LogonPoint/tmindex.html", ("citrix", "logonpoint"), "Citrix Gateway (Logon Point)",
     "CVE-2023-4966"),
    ("/Citrix/XenApp/", ("citrix",), "Citrix XenApp / Gateway", "—"),
    ("/admin/login.do", ("watchguard",), "WatchGuard Fireware", "—"),
    ("/nsecure/login.php", ("arcsight",), "ArcSight / SSL VPN", "—"),
    ("/rap/auth/login", ("aruba", "clearpass"), "Aruba ClearPass", "—"),
]


def _probe(client: httpx.Client, domain: str, entry: tuple) -> dict | None:
    path, hints, vendor, cves = entry
    try:
        r = client.get(f"https://{domain}{path}")
    except httpx.HTTPError:
        return None
    if r.status_code not in (200, 401, 403):
        return None
    body = ""
    if "text" in r.headers.get("content-type", "").lower():
        body = r.text[:8192]
    return {
        "path": path,
        "status": r.status_code,
        "vendor": vendor,
        "cves": cves,
        "hints": hints,
        "body": body,
        "server": r.headers.get("server", ""),
    }


def check_vpn_endpoints(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("VPN-Endpoint-Detection", 88)

    baselines = fetch_baselines(domain)

    hits: list[dict] = []
    with httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = [ex.submit(_probe, client, domain, e) for e in VPN_PROBES]
            for f in as_completed(futures):
                h = f.result()
                if not h:
                    continue
                # 401/403 means the device exists (auth challenge) — accept without hint.
                if h["status"] in (401, 403):
                    hits.append(h)
                    continue
                # 200: must pass baseline + have at least one content hint.
                body_lower = h["body"].lower()
                if is_catchall(h["body"], baselines):
                    continue
                if not any(hint in body_lower for hint in h["hints"]):
                    continue
                hits.append(h)

    if not hits:
        return

    # Dedupe by vendor
    seen_vendors: set[str] = set()
    unique_hits = []
    for h in hits:
        if h["vendor"] in seen_vendors:
            continue
        seen_vendors.add(h["vendor"])
        unique_hits.append(h)

    result.metadata["vpn_endpoints"] = [
        {"vendor": h["vendor"], "path": h["path"], "status": h["status"], "cves": h["cves"]}
        for h in unique_hits
    ]

    for h in unique_hits:
        result.add(Finding(
            id=f"vpn.endpoint.{h['vendor'].lower().replace(' ', '_').replace('/', '_')}",
            title=f"VPN-Gateway öffentlich erreichbar: {h['vendor']}",
            description=(
                f"Unter https://{domain}{h['path']} antwortet ein {h['vendor']}-Login "
                f"(HTTP {h['status']}). VPN-Gateways sind das wertvollste Ziel in jedem "
                "MVZ — sie öffnen direkten Zugang zum internen Netz, wenn eine Schwachstelle "
                "vorliegt. Alle großen Vendors hatten in den letzten 24 Monaten Pre-Auth-"
                f"Zero-Days.\n\nBekannte CVEs für {h['vendor']}: {h['cves']}"
            ),
            severity=Severity.HIGH,
            category="VPN / Remote Access",
            evidence={
                "vendor": h["vendor"],
                "path": h["path"],
                "status": h["status"],
                "server": h.get("server", ""),
                "known_cves": h["cves"],
            },
            recommendation=(
                f"1. Firmware-Version des {h['vendor']}-Systems sofort verifizieren und auf "
                "den aktuellsten Patch-Level bringen. "
                "2. Zugang auf IP-Whitelist der Praxis-Standorte beschränken wenn möglich. "
                "3. MFA erzwingen (TOTP oder Hardware-Token). "
                "4. SAML-Logs auf Brute-Force überwachen."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 3 (Remote-Zugänge)",
        ))
