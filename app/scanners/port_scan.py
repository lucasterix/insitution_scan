"""Lightweight active port scan.

Unlike Shodan (which returns cached data), this check actually connects to the
target from the scanner host. It is deliberately narrow: 15 MVZ-critical ports
with a 2-second socket timeout, run in parallel. No nmap, no packet crafting —
a plain TCP connect check.

The target must be the IP(s) from the domain's A records, which we already
resolved in the DNS step.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from app.scanners.base import Finding, ScanResult, Severity

TIMEOUT = 2.0

# (port, severity, label)
CRITICAL_PORTS: list[tuple[int, Severity, str]] = [
    (21, Severity.HIGH, "FTP (unverschlüsselt)"),
    (22, Severity.LOW, "SSH"),
    (23, Severity.CRITICAL, "Telnet"),
    (25, Severity.INFO, "SMTP"),
    (110, Severity.MEDIUM, "POP3 (unverschlüsselt)"),
    (143, Severity.MEDIUM, "IMAP (unverschlüsselt)"),
    (445, Severity.CRITICAL, "SMB/CIFS"),
    (1433, Severity.HIGH, "MSSQL"),
    (3306, Severity.HIGH, "MySQL"),
    (3389, Severity.CRITICAL, "RDP"),
    (5432, Severity.HIGH, "PostgreSQL"),
    (5900, Severity.CRITICAL, "VNC"),
    (6379, Severity.HIGH, "Redis"),
    (8080, Severity.LOW, "HTTP Alternative"),
    (9200, Severity.HIGH, "Elasticsearch"),
    (27017, Severity.HIGH, "MongoDB"),
    (11211, Severity.HIGH, "Memcached"),
]


def _probe(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            return True
    except (OSError, socket.timeout):
        return False


def active_port_scan(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    ips = (result.metadata.get("dns") or {}).get("A") or []
    if not ips:
        return

    step("Active Port Scan", 86)

    # Cap to 3 IPs to avoid slow scans with round-robin DNS.
    targets = ips[:3]
    reports: dict[str, dict] = {}

    for ip in targets:
        open_ports: list[int] = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(_probe, ip, p[0]): p for p in CRITICAL_PORTS}
            for f in as_completed(futures):
                port, sev, label = futures[f]
                if f.result():
                    open_ports.append(port)
                    # Port 22 SSH and port 25 SMTP are low/info noise — we still record them.
                    if sev.value not in ("info",):
                        finding_id = f"port.{ip}.{port}"
                        # RDP/Telnet/VNC/SMB go straight to critical with a strong message.
                        is_urgent = sev == Severity.CRITICAL
                        description = f"TCP-Port {port} ({label}) ist von außen auf {ip} erreichbar."
                        if is_urgent:
                            description += (
                                " Das ist für MVZs de facto ein Kompromittierungsindikator. "
                                "Bitte sofort hinter Firewall/VPN stellen."
                            )
                        result.add(Finding(
                            id=finding_id,
                            title=f"Port {port} ({label}) öffentlich erreichbar auf {ip}",
                            description=description,
                            severity=sev,
                            category="Network Exposure",
                            evidence={"ip": ip, "port": port, "service": label},
                            recommendation=(
                                f"Port {port} ausschließlich über VPN oder IP-Whitelist erreichbar machen."
                                if is_urgent
                                else f"Prüfen ob Port {port} notwendig ist; falls nein, Firewall-Regel anlegen."
                            ),
                            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 3 (Netzwerk-Härtung)",
                        ))
        reports[ip] = {"open_ports": sorted(open_ports)}

    result.metadata["active_port_scan"] = reports
