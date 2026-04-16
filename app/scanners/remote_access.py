"""Remote access and management tool detection.

Scans for exposed remote desktop software, RMM platforms, and out-of-band
management interfaces. These are the #1 attack vector for MVZ/Praxis
environments because:

1. IT service providers install TeamViewer/AnyDesk on every Praxis-PC
   and often leave default passwords or unattended-access enabled.
2. RMM tools (ConnectWise ScreenConnect, Datto) are high-value targets —
   a single compromised RMM account controls hundreds of endpoints.
3. IPMI/iLO/iDRAC management interfaces often have factory default
   credentials and provide pre-boot hardware-level access.

Detection methods:
- HTTP path probing for web-based tools (Guacamole, ScreenConnect, Horizon)
- Port scanning for remote desktop protocols (additional ports beyond
  the standard 16)
- HTML/header fingerprinting for tool identification
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import httpx

from app.scanners._baseline import fetch_baselines, is_catchall
from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
TIMEOUT = 5.0

# --- Web-based remote access tools ---
# (path, content_hints, tool_name, severity, description, known_cves)
import re

# Version extraction patterns for remote access tools
VERSION_PATTERNS: dict[str, list[re.Pattern]] = {
    "Apache Guacamole": [re.compile(r"guacamole[/-]([\d.]+)", re.IGNORECASE)],
    "ConnectWise ScreenConnect": [
        re.compile(r"ScreenConnect[/ ]([\d.]+)", re.IGNORECASE),
        re.compile(r"version[\"':= ]+([\d.]+)", re.IGNORECASE),
    ],
    "Citrix StoreFront": [re.compile(r"Citrix[/ ]([\d.]+)", re.IGNORECASE)],
    "VMware Horizon": [re.compile(r"Horizon[/ ]([\d.]+)", re.IGNORECASE)],
    "VMware vSphere Client": [re.compile(r"vSphere[/ ]([\d.]+)", re.IGNORECASE)],
    "MeshCentral": [re.compile(r"MeshCentral[/ v]([\d.]+)", re.IGNORECASE)],
    "Microsoft RD Web Access": [re.compile(r"RDWeb[/ ]([\d.]+)", re.IGNORECASE)],
}

REMOTE_ACCESS_PATHS: list[tuple[str, tuple[str, ...], str, Severity, str, str]] = [
    ("/guacamole/", ("guacamole", "apache guacamole"), "Apache Guacamole",
     Severity.HIGH, "Web-basierter Remote-Desktop-Gateway — erlaubt RDP/SSH/VNC über den Browser.",
     "CVE-2020-9498 (RCE), CVE-2023-43826 (SSRF)"),
    ("/rdweb/", ("rdweb", "remote desktop", "rd web access"), "Microsoft RD Web Access",
     Severity.HIGH, "Windows Remote Desktop Web Access — Zugang zu veröffentlichten Apps/Desktops.",
     "CVE-2019-0708 (BlueKeep), CVE-2019-1181/1182 (DejaBlue)"),
    ("/Citrix/StoreWeb/", ("citrix", "storefront", "storeweb"), "Citrix StoreFront",
     Severity.HIGH, "Citrix Workspace/StoreFront — virtualisierte Desktops und Apps.",
     "CVE-2023-4966 (Citrix Bleed), CVE-2023-3519 (RCE)"),
    ("/vmware/", ("vmware", "horizon"), "VMware Horizon",
     Severity.HIGH, "VMware Horizon VDI Portal.",
     "CVE-2021-44228 (Log4Shell in Horizon), CVE-2022-22954 (RCE)"),
    ("/portal/webclient/", ("vmware", "vsphere"), "VMware vSphere Client",
     Severity.CRITICAL, "vSphere Management — voller Zugriff auf die Virtualisierungsplattform.",
     "CVE-2021-21985 (RCE), CVE-2021-22005 (File Upload)"),
    ("/screenconnect/", ("screenconnect", "connectwise"), "ConnectWise ScreenConnect",
     Severity.CRITICAL, "ScreenConnect RMM — ein kompromittierter Account = Zugriff auf alle verwalteten Endpoints.",
     "CVE-2024-1709 (Auth Bypass CRITICAL), CVE-2024-1708 (Path Traversal)"),
    ("/ScreenConnect/", ("screenconnect", "connectwise"), "ConnectWise ScreenConnect",
     Severity.CRITICAL, "ScreenConnect RMM (alternative Pfad-Schreibweise).",
     "CVE-2024-1709 (Auth Bypass)"),
    ("/meshcentral/", ("meshcentral",), "MeshCentral",
     Severity.HIGH, "Open-Source Remote-Management-Plattform.",
     ""),
    ("/RDWeb/Pages/", ("rdweb", "remote desktop"), "Microsoft RD Web Access",
     Severity.HIGH, "Windows Remote Desktop Web Access (alternativer Pfad).",
     ""),
    ("/remote/", ("anydesk", "remote support"), "AnyDesk Web Client",
     Severity.MEDIUM, "Möglicher AnyDesk Web-Client oder Remote-Support-Portal.",
     "CVE-2020-13160 (AnyDesk Buffer Overflow)"),
]

# --- Additional management/remote ports ---
# These are NOT in the standard port_scan CRITICAL_PORTS list.
MANAGEMENT_PORTS: list[tuple[int, Severity, str, str]] = [
    (623, Severity.CRITICAL, "IPMI",
     "Intelligent Platform Management Interface — Hardware-Level-Zugriff, oft mit Default-Credentials (admin/admin, ADMIN/ADMIN). Ermöglicht Pre-Boot-Kontrolle, KVM-Zugriff und Firmware-Updates."),
    (5985, Severity.HIGH, "WinRM HTTP",
     "Windows Remote Management — PowerShell-Remoting über HTTP. Erlaubt Kommandoausführung auf Windows-Servern."),
    (5986, Severity.HIGH, "WinRM HTTPS",
     "Windows Remote Management über HTTPS. Gleiche Funktionalität wie WinRM HTTP, aber verschlüsselt."),
    (8443, Severity.HIGH, "HTTPS-Management",
     "Alternativer HTTPS-Port — oft verwendet für iDRAC, iLO, Firewall-Admin, Konnektor-Web-UI."),
    (9090, Severity.MEDIUM, "Cockpit/Webmin",
     "Linux Cockpit oder Webmin Web-Management-Interface."),
    (2222, Severity.MEDIUM, "Alternativer SSH",
     "Nicht-Standard SSH-Port — oft von Honeypots oder Container-Management genutzt."),
    (4443, Severity.MEDIUM, "Alternative HTTPS",
     "Oft genutzt für SonicWall SSL-VPN, Sophos, oder alternative Admin-Panels."),
    (10000, Severity.MEDIUM, "Webmin",
     "Webmin Server-Administration — Web-UI mit Root-Zugriff."),
    (8291, Severity.HIGH, "MikroTik Winbox",
     "MikroTik RouterOS Winbox — Netzwerkgeräte-Management. CVE-2018-14847 (Creds Leak)."),
    (161, Severity.MEDIUM, "SNMP",
     "Simple Network Management Protocol — Community Strings sind oft 'public'. Informationsleck über Netzwerkinfrastruktur."),
]

# --- Remote desktop tool detection in HTML ---
REMOTE_TOOL_SIGNATURES = [
    (r"teamviewer", "TeamViewer", Severity.MEDIUM,
     "TeamViewer-Referenz auf der Website gefunden. Wenn TeamViewer auf Praxis-PCs läuft: Unattended-Access prüfen, starkes Passwort erzwingen, Allowlist aktivieren."),
    (r"anydesk", "AnyDesk", Severity.MEDIUM,
     "AnyDesk-Referenz auf der Website gefunden. AnyDesk mit unbeaufsichtigtem Zugriff und schwachem Passwort ist ein häufiger Ransomware-Einstiegspunkt bei MVZ."),
    (r"rustdesk", "RustDesk", Severity.LOW,
     "RustDesk-Referenz gefunden. Open-Source Remote-Desktop — prüfen ob selbst-gehosteter Relay-Server sicher konfiguriert ist."),
    (r"splashtop", "Splashtop", Severity.MEDIUM,
     "Splashtop Remote-Desktop-Referenz gefunden."),
]


def _probe_port(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            return True
    except (OSError, socket.timeout):
        return False


def check_remote_access(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Fernwartung + Management-Ports", 86)

    baselines = fetch_baselines(domain)

    # --- 1. Web-based remote access tools (parallelized) ---
    def _probe_web(host_and_spec: tuple) -> dict | None:
        host, spec = host_and_spec
        path, hints, tool, sev, desc, cves = spec
        try:
            with httpx.Client(
                timeout=TIMEOUT, follow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                try:
                    r = client.get(f"https://{host}{path}")
                except httpx.HTTPError:
                    try:
                        r = client.get(f"http://{host}{path}")
                    except httpx.HTTPError:
                        return None
        except httpx.HTTPError:
            return None

        if r.status_code not in (200, 401, 403):
            return None

        if r.status_code in (401, 403):
            return {"host": host, "path": path, "tool": tool, "status": r.status_code,
                    "sev": sev, "desc": desc, "cves": cves}

        body = r.text[:8192] if "text" in r.headers.get("content-type", "").lower() else ""
        if is_catchall(body, baselines):
            return None
        if not any(h in body.lower() for h in hints):
            return None

        return {"host": host, "path": path, "tool": tool, "status": r.status_code,
                "sev": sev, "desc": desc, "cves": cves,
                "body": body, "server": r.headers.get("server", "")}

    # Probe main domain for ALL paths + alive subdomains for CRITICAL/HIGH paths.
    targets: list[tuple[str, tuple]] = [(domain, spec) for spec in REMOTE_ACCESS_PATHS]
    alive_subs = list((result.metadata.get("subdomain_walk") or {}).get("results") or {})
    high_value_paths = [s for s in REMOTE_ACCESS_PATHS if s[3] in (Severity.CRITICAL, Severity.HIGH)]
    for sub in alive_subs[:10]:
        for spec in high_value_paths:
            targets.append((sub, spec))

    web_hits: list[dict] = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        for hit in ex.map(_probe_web, targets):
            if hit:
                web_hits.append(hit)

    # Deduplicate by (host, tool) so a tool on a subdomain is still reported separately.
    seen_tools: set[tuple[str, str]] = set()
    for hit in web_hits:
        key = (hit.get("host", domain), hit["tool"])
        if key in seen_tools:
            continue
        seen_tools.add(key)

        # --- Version extraction from response body + headers ---
        detected_version = None
        body_for_version = hit.get("body", "")
        if hit["tool"] in VERSION_PATTERNS:
            for pat in VERSION_PATTERNS[hit["tool"]]:
                m = pat.search(body_for_version)
                if m:
                    detected_version = m.group(1)
                    break
        # Also check Server/X-Powered-By headers
        if not detected_version and hit.get("server"):
            for pat_list in VERSION_PATTERNS.values():
                for pat in pat_list:
                    m = pat.search(hit["server"])
                    if m:
                        detected_version = m.group(1)
                        break

        if detected_version:
            hit["version"] = detected_version
            # Feed version into tech metadata for CVE scanner
            tech_key = f"remote.{hit['tool'].lower().replace(' ', '_')}"
            result.metadata.setdefault("tech", {})[tech_key] = detected_version

        version_text = f" Version {detected_version}" if detected_version else ""
        host = hit.get("host", domain)
        host_suffix = "" if host == domain else f" (Subdomain: {host})"
        id_host = host.replace(".", "_")

        result.add(Finding(
            id=f"remote.web.{id_host}.{hit['tool'].lower().replace(' ', '_')}",
            title=f"Fernwartungstool öffentlich erreichbar: {hit['tool']}{version_text}{host_suffix}",
            description=(
                f"{hit['desc']}\n\n"
                f"Host: {host}\n"
                f"Pfad: {hit['path']} (HTTP {hit['status']})\n"
                + (f"Bekannte CVEs: {hit['cves']}" if hit["cves"] else "")
                + "\n\nFernwartungstools aus dem Internet sind eines der häufigsten "
                "Einfallstore bei Angriffen auf Arztpraxen und MVZ. IT-Dienstleister "
                "installieren oft TeamViewer/AnyDesk/ScreenConnect auf jedem PC mit "
                "schwachem oder wiederverwendetem Passwort."
            ),
            severity=hit["sev"],
            category="Fernwartung",
            evidence={"tool": hit["tool"], "host": host, "path": hit["path"], "status": hit["status"], "cves": hit["cves"]},
            recommendation=(
                f"1. Prüfen ob {hit['tool']} tatsächlich benötigt wird.\n"
                "2. Zugriff per IP-Whitelist/VPN einschränken.\n"
                "3. MFA erzwingen.\n"
                "4. Default-Credentials sofort ändern.\n"
                "5. Software auf aktuellste Version patchen."
            ),
            kbv_ref="KBV Anlage 3 (Remote-Zugänge), DSGVO Art. 32",
        ))

    # --- 2. Management ports ---
    ips = (result.metadata.get("dns") or {}).get("A") or []
    if not ips:
        # For IP scans, the target itself is the IP
        is_ip = result.metadata.get("target_type") == "ip"
        if is_ip:
            ips = [domain]

    mgmt_findings: list[dict] = []

    if ips:
        ip = ips[0]
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {
                ex.submit(_probe_port, ip, port): (port, sev, label, desc)
                for port, sev, label, desc in MANAGEMENT_PORTS
            }
            for f in as_completed(futures):
                port, sev, label, desc = futures[f]
                if f.result():
                    mgmt_findings.append({"ip": ip, "port": port, "service": label, "sev": sev, "desc": desc})

    for mf in mgmt_findings:
        result.add(Finding(
            id=f"remote.mgmt.{mf['ip'].replace('.', '_')}.{mf['port']}",
            title=f"Management-Port {mf['port']} ({mf['service']}) offen auf {mf['ip']}",
            description=(
                f"{mf['desc']}\n\n"
                "Management-Interfaces wie IPMI, iLO, iDRAC und WinRM sind "
                "für die Server-Administration gedacht und gehören NICHT ins "
                "öffentliche Internet. Sie bieten oft Hardware-Level-Zugriff "
                "der über das Betriebssystem hinausgeht."
            ),
            severity=mf["sev"],
            category="Fernwartung",
            evidence={"ip": mf["ip"], "port": mf["port"], "service": mf["service"]},
            recommendation=(
                f"Port {mf['port']} ({mf['service']}) per Firewall auf VPN/Management-VLAN beschränken. "
                "Bei IPMI: Default-Passwort sofort ändern (Factory: ADMIN/ADMIN)."
            ),
            kbv_ref="KBV Anlage 3 (Netzwerk-Segmentierung), BSI SYS.1.1",
        ))

    # --- 3. Scan homepage HTML for remote tool references ---
    import re
    html = result.metadata.get("homepage_html") or ""
    if html:
        for pattern, tool_name, sev, advice in REMOTE_TOOL_SIGNATURES:
            if re.search(pattern, html, re.IGNORECASE):
                result.add(Finding(
                    id=f"remote.html_ref.{tool_name.lower().replace(' ', '_')}",
                    title=f"Hinweis auf {tool_name} in Website-HTML",
                    description=(
                        f"Im HTML-Quelltext der Website wurde eine Referenz auf {tool_name} "
                        f"gefunden. {advice}"
                    ),
                    severity=sev,
                    category="Fernwartung",
                    evidence={"tool": tool_name},
                ))

    result.metadata["remote_access"] = {
        "web_tools": [h["tool"] for h in web_hits],
        "management_ports": [(m["port"], m["service"]) for m in mgmt_findings],
    }
