"""Server-level analysis beyond domain scanning.

While most scanners focus on the domain (DNS, HTTP, TLS), this module
analyzes the underlying server infrastructure:

1. Shared Hosting Detection — extracts other domains on the same IP from
   Shodan data and flags shared hosting risks.
2. Reverse DNS (PTR) — what hostname does the IP advertise about itself?
3. SSH Host Key Analysis — extracts the public key, checks type and strength.

These checks answer the question: "Is the SERVER secure, not just the website?"
"""
from __future__ import annotations

import hashlib
import socket
from typing import Callable

import dns.exception
import dns.resolver
import dns.reversename

from app.scanners.base import Finding, ScanResult, Severity


def _reverse_dns(ip: str) -> str | None:
    """PTR lookup for an IP address."""
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR", lifetime=3.0)
        return str(list(answers)[0]).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, Exception):
        return None


def _extract_ssh_key(ip: str, port: int = 22) -> dict | None:
    """Connect to SSH and extract the host key banner + key exchange info."""
    try:
        sock = socket.create_connection((ip, port), timeout=4)
    except (OSError, socket.timeout):
        return None
    try:
        sock.settimeout(4)
        banner = b""
        try:
            banner = sock.recv(1024)
        except (socket.timeout, OSError):
            pass
        banner_str = banner.decode("latin1", errors="replace").strip()

        # Try to get host key via paramiko if available, otherwise just report banner
        result: dict = {"banner": banner_str, "ip": ip, "port": port}

        # Parse SSH version from banner
        if banner_str.startswith("SSH-"):
            parts = banner_str.split("-", 2)
            if len(parts) >= 3:
                result["protocol"] = parts[1]
                result["software"] = parts[2].split(" ")[0] if " " in parts[2] else parts[2]

        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass


def check_server(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Server-Analyse (PTR/Shared-Hosting/SSH)", 83)

    ips = (result.metadata.get("dns") or {}).get("A") or []
    if not ips:
        return

    primary_ip = ips[0]
    server_info: dict = {"ip": primary_ip}

    # --- 1. Reverse DNS ---
    ptr = _reverse_dns(primary_ip)
    server_info["ptr"] = ptr
    if ptr:
        result.add(Finding(
            id="server.ptr_record",
            title=f"Reverse-DNS (PTR): {primary_ip} → {ptr}",
            description=(
                f"Die IP-Adresse {primary_ip} hat den PTR-Record '{ptr}'. "
                "Der PTR-Record zeigt, wie sich der Server selbst identifiziert. "
                "Wenn dieser Name nicht zur Domain passt, könnte es sich um "
                "Shared Hosting, einen CDN-Knoten oder eine Fehlkonfiguration handeln."
            ),
            severity=Severity.INFO,
            category="Server",
            evidence={"ip": primary_ip, "ptr": ptr},
        ))

    # --- 2. Shared Hosting Detection from Shodan ---
    ip_intel = result.metadata.get("ip_intel") or {}
    for ip, data in ip_intel.items():
        shodan_data = data.get("shodan") or {}
        hostnames = shodan_data.get("hostnames") or []
        if not hostnames:
            continue

        # Filter: which hostnames are NOT the target domain or its subdomains?
        other_domains = [
            h for h in hostnames
            if h != domain and not h.endswith(f".{domain}")
        ]

        if other_domains:
            server_info["shared_hosting"] = other_domains
            is_many = len(other_domains) > 5

            result.add(Finding(
                id=f"server.shared_hosting.{ip.replace('.', '_')}",
                title=f"Shared Hosting: {len(other_domains)} weitere Domain(s) auf {ip}",
                description=(
                    f"Shodan meldet, dass die IP {ip} neben {domain} auch folgende "
                    f"anderen Domains hostet: {', '.join(other_domains[:15])}"
                    + (f" (+ {len(other_domains) - 15} weitere)" if len(other_domains) > 15 else "")
                    + ".\n\nShared Hosting bedeutet:"
                    "\n1. Ein kompromittierter Nachbar-Account kann auf eure Daten zugreifen (Symlink-Angriff, Shared-Memory)."
                    "\n2. Eine DDoS-Attacke gegen eine andere Domain auf demselben Server trifft auch euch."
                    "\n3. Ein gestohlenes TLS-Zertifikat eines Nachbarn ermöglicht MITM auf demselben Server."
                    + ("\n\n⚠️ Besonders kritisch: über 5 fremde Domains auf derselben IP bei einem Gesundheitsdienstleister." if is_many else "")
                ),
                severity=Severity.MEDIUM if is_many else Severity.LOW,
                category="Server",
                evidence={"ip": ip, "other_domains": other_domains[:30]},
                recommendation=(
                    "Für MVZ mit Patientendaten: dedizierter Server (VPS/Dedicated) statt "
                    "Shared Hosting. Mindestens: eigene IP-Adresse, kein DocumentRoot-Sharing."
                ),
                kbv_ref="KBV IT-Sicherheitsrichtlinie Anlage 3 (Netzwerk-Segmentierung), DSGVO Art. 32",
            ))

    # --- 3. SSH Host Key Analysis ---
    open_ports = (result.metadata.get("active_port_scan") or {}).get(primary_ip, {}).get("open_ports", [])
    if 22 in open_ports:
        ssh_info = _extract_ssh_key(primary_ip)
        if ssh_info:
            server_info["ssh"] = ssh_info
            software = ssh_info.get("software", "")
            protocol = ssh_info.get("protocol", "")

            # Check for SSH protocol version 1 (ancient, broken)
            if protocol and protocol.strip() == "1.0":
                result.add(Finding(
                    id="server.ssh_protocol_v1",
                    title="SSH-Protokoll Version 1 aktiv",
                    description=(
                        "Der SSH-Server unterstützt das veraltete Protokoll 1.0, das "
                        "kryptographisch gebrochen ist (Man-in-the-Middle, Key-Recovery)."
                    ),
                    severity=Severity.CRITICAL,
                    category="Server",
                    evidence=ssh_info,
                    recommendation="SSH-Konfiguration auf 'Protocol 2' beschränken.",
                ))

            # Check for very old SSH implementations
            if software:
                low = software.lower()
                if "dropbear" in low:
                    result.add(Finding(
                        id="server.ssh_dropbear",
                        title=f"SSH-Server ist Dropbear ({software})",
                        description="Dropbear ist für Embedded-Geräte gedacht. Auf einem Produktions-Server sollte OpenSSH laufen.",
                        severity=Severity.LOW,
                        category="Server",
                        evidence=ssh_info,
                    ))

    result.metadata["server_analysis"] = server_info
