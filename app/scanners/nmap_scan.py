"""nmap service version detection.

Runs `nmap -sT -sV --top-ports 100` against the target IP(s) discovered
in the DNS step. Parses XML output for accurate service/version identification
that's significantly better than our regex-based banner grab.

nmap -sT (TCP connect) works without root privileges — the container runs
as appuser. -sV probes each open port with protocol-specific handshakes
to identify the exact product and version.
"""
from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import Callable

from app.scanners.base import Finding, ScanResult, Severity

NMAP_TIMEOUT = 120


def _nmap_available() -> bool:
    try:
        r = subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _parse_xml(xml_str: str) -> list[dict]:
    """Parse nmap XML output into a list of service dicts."""
    services: list[dict] = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return services

    for host in root.findall(".//host"):
        addr_el = host.find("address")
        ip = addr_el.get("addr", "") if addr_el is not None else ""

        for port_el in host.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            portid = port_el.get("portid", "")
            protocol = port_el.get("protocol", "tcp")

            svc: dict = {
                "ip": ip,
                "port": int(portid) if portid.isdigit() else 0,
                "protocol": protocol,
                "state": "open",
            }
            if service_el is not None:
                svc["service"] = service_el.get("name", "")
                svc["product"] = service_el.get("product", "")
                svc["version"] = service_el.get("version", "")
                svc["extrainfo"] = service_el.get("extrainfo", "")
                svc["ostype"] = service_el.get("ostype", "")
                svc["cpe"] = service_el.get("servicefp", "")
                # nmap often includes CPE in <cpe> child elements
                cpe_els = service_el.findall("cpe")
                if cpe_els:
                    svc["cpe_list"] = [c.text for c in cpe_els if c.text]

            services.append(svc)
    return services


def check_nmap(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    if not _nmap_available():
        result.metadata.setdefault("nmap", {})["available"] = False
        return

    ips = (result.metadata.get("dns") or {}).get("A") or []
    if not ips:
        return

    step("nmap Service-Detection", 79)
    target_ip = ips[0]

    cmd = [
        "nmap", "-sT", "-sV",
        "--top-ports", "100",
        "-T3",
        "--open",
        "-oX", "-",
        "--no-stylesheet",
        target_ip,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=NMAP_TIMEOUT,
            text=True,
        )
    except subprocess.TimeoutExpired:
        result.metadata.setdefault("nmap", {})["timeout"] = True
        return
    except FileNotFoundError:
        return

    if proc.returncode not in (0, 1):
        result.metadata.setdefault("nmap", {})["error"] = proc.stderr[:500]
        return

    services = _parse_xml(proc.stdout)

    result.metadata["nmap"] = {
        "available": True,
        "ip": target_ip,
        "services_found": len(services),
        "services": services,
    }

    # Feed discovered versions into tech metadata for CVE scanner.
    tech = result.metadata.setdefault("tech", {})
    for svc in services:
        product = svc.get("product", "").lower()
        version = svc.get("version", "")
        port = svc.get("port", 0)
        if not product or not version:
            continue

        tech_key = f"nmap.{product.replace(' ', '_')}"
        if tech_key not in tech:
            tech[tech_key] = version

        result.add(Finding(
            id=f"nmap.service.{target_ip.replace('.', '_')}.{port}",
            title=f"nmap: {svc.get('product', '')} {version} auf Port {port}",
            description=(
                f"nmap Service-Detection identifiziert {svc.get('product', '')} {version} "
                f"auf {target_ip}:{port} ({svc.get('service', 'unknown')}). "
                f"Zusatzinfo: {svc.get('extrainfo', '-')}."
                "\n\nnmap's Probing ist genauer als passives Banner-Grabbing, weil es "
                "protokollspezifische Handshakes durchführt."
            ),
            severity=Severity.INFO,
            category="nmap",
            evidence=svc,
        ))

    if not services:
        return

    # Summary finding
    result.add(Finding(
        id="nmap.summary",
        title=f"nmap: {len(services)} offene Services auf {target_ip}",
        description=(
            f"nmap TCP Connect Scan (-sT) + Service Version Detection (-sV) auf den "
            f"Top-100-Ports von {target_ip}. Gefundene Services werden automatisch "
            "für den CVE-Abgleich via NVD/KEV/EPSS herangezogen."
        ),
        severity=Severity.INFO,
        category="nmap",
        evidence={"ip": target_ip, "services": [f"{s['port']}/{s.get('service','')} {s.get('product','')} {s.get('version','')}" for s in services]},
    ))
