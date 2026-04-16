"""OS/Distribution detection + EOL check + SSH auth method analysis.

Extracts the operating system from three sources:
1. SSH banner package suffix (e.g., "Ubuntu-3ubuntu13.15" → Ubuntu 24.04)
2. nmap service ostype field (e.g., "Linux", "Windows")
3. HTTP Server header hints (e.g., "(Ubuntu)", "(Debian)", "(Win64)")

Then checks against an EOL database to flag unsupported OS/software versions.

SSH auth methods are probed via paramiko's transport layer to determine
whether password authentication is enabled (brute-force risk).
"""
from __future__ import annotations

import re
import socket
from datetime import date
from typing import Callable

from app.scanners.base import Finding, ScanResult, Severity

# --- OS detection from SSH banner ---
# SSH banners follow: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.15
# The package suffix maps to specific OS releases:
UBUNTU_PKG_MAP: dict[str, str] = {
    "ubuntu0.14": "Ubuntu 14.04", "ubuntu0.16": "Ubuntu 16.04",
    "ubuntu0.18": "Ubuntu 18.04", "ubuntu0.20": "Ubuntu 20.04",
    "ubuntu0.22": "Ubuntu 22.04", "ubuntu0.24": "Ubuntu 24.04",
    "ubuntu1": "Ubuntu (unknown)", "ubuntu2": "Ubuntu (unknown)",
    "ubuntu3": "Ubuntu (unknown)", "ubuntu4": "Ubuntu (unknown)",
    "ubuntu5": "Ubuntu (unknown)", "ubuntu10": "Ubuntu (unknown)",
    "ubuntu11": "Ubuntu (unknown)", "ubuntu12": "Ubuntu (unknown)",
    "ubuntu13": "Ubuntu 24.04",
}
DEBIAN_PKG_MAP: dict[str, str] = {
    "deb7": "Debian 7 (Wheezy)", "deb8": "Debian 8 (Jessie)",
    "deb9": "Debian 9 (Stretch)", "deb10": "Debian 10 (Buster)",
    "deb11": "Debian 11 (Bullseye)", "deb12": "Debian 12 (Bookworm)",
}

# --- EOL database ---
# (product_pattern, version_regex, eol_date, display_name)
# Checked against result.metadata["tech"] keys + SSH/nmap data.
EOL_DATABASE: list[tuple[str, str, str, str]] = [
    # Ubuntu LTS releases
    ("Ubuntu 14.04", "", "2019-04-01", "Ubuntu 14.04 LTS (Trusty)"),
    ("Ubuntu 16.04", "", "2021-04-30", "Ubuntu 16.04 LTS (Xenial)"),
    ("Ubuntu 18.04", "", "2023-05-31", "Ubuntu 18.04 LTS (Bionic)"),
    ("Ubuntu 20.04", "", "2025-04-02", "Ubuntu 20.04 LTS (Focal)"),
    # Debian
    ("Debian 7", "", "2016-04-26", "Debian 7 (Wheezy)"),
    ("Debian 8", "", "2018-06-17", "Debian 8 (Jessie)"),
    ("Debian 9", "", "2020-07-06", "Debian 9 (Stretch)"),
    ("Debian 10", "", "2022-09-10", "Debian 10 (Buster)"),
    ("Debian 11", "", "2026-08-15", "Debian 11 (Bullseye)"),
    # Windows Server
    ("Windows Server 2008", "", "2020-01-14", "Windows Server 2008/2008 R2"),
    ("Windows Server 2012", "", "2023-10-10", "Windows Server 2012/2012 R2"),
    ("Windows Server 2016", "", "2027-01-12", "Windows Server 2016"),
    # CentOS
    ("CentOS 6", "", "2020-11-30", "CentOS 6"),
    ("CentOS 7", "", "2024-06-30", "CentOS 7"),
    ("CentOS 8", "", "2021-12-31", "CentOS 8 (nicht Stream)"),
]

# Software EOL: (tech_key_prefix, version_compare, eol_date, label)
SOFTWARE_EOL: list[tuple[str, str, str, str]] = [
    # OpenSSH — versions that are ancient
    ("openssh", "7.0", "2020-01-01", "OpenSSH < 7.0"),
    ("openssh", "7.4", "2021-01-01", "OpenSSH < 7.4"),
    ("openssh", "8.0", "2022-06-01", "OpenSSH < 8.0"),
    # nginx
    ("nginx", "1.18", "2022-01-01", "nginx < 1.18 (Mainline EOL)"),
    ("nginx", "1.20", "2023-01-01", "nginx < 1.20"),
    # Apache
    ("apache", "2.2", "2018-01-01", "Apache 2.2 (EOL since 2018)"),
    ("apache", "2.4.0", "2019-01-01", "Apache 2.4.0-2.4.9 (sehr alt)"),
    # PHP
    ("php", "7.4", "2022-11-28", "PHP 7.4 (EOL)"),
    ("php", "8.0", "2023-11-26", "PHP 8.0 (EOL)"),
    ("php", "8.1", "2025-12-31", "PHP 8.1 (EOL bald)"),
    # MySQL
    ("mysql", "5.7", "2023-10-21", "MySQL 5.7 (EOL)"),
    ("mysql", "5.6", "2021-02-01", "MySQL 5.6 (EOL)"),
    # MariaDB
    ("mariadb", "10.3", "2023-05-25", "MariaDB 10.3 (EOL)"),
    ("mariadb", "10.4", "2024-06-18", "MariaDB 10.4 (EOL)"),
    # PostgreSQL
    ("postgresql", "11", "2023-11-09", "PostgreSQL 11 (EOL)"),
    ("postgresql", "12", "2024-11-14", "PostgreSQL 12 (EOL)"),
]

SSH_BANNER_OS_RE = re.compile(
    r"SSH-\d\.\d-OpenSSH_[\d.]+(?:p\d+)?\s+(.*)", re.IGNORECASE
)
WINDOWS_HINTS = re.compile(r"windows|win32|win64|microsoft|iis", re.IGNORECASE)


def _detect_os_from_ssh(banners: dict) -> list[dict]:
    """Parse SSH banners for OS information."""
    results: list[dict] = []
    for ip, ports in banners.items():
        for port, banner in ports.items():
            if not banner.startswith("SSH-"):
                continue
            m = SSH_BANNER_OS_RE.search(banner)
            if not m:
                continue
            suffix = m.group(1).strip()
            os_name = None
            if "Ubuntu" in suffix or "ubuntu" in suffix:
                for pkg_hint, os_label in UBUNTU_PKG_MAP.items():
                    if pkg_hint in suffix.lower():
                        os_name = os_label
                        break
                if not os_name:
                    os_name = "Ubuntu (Version unbekannt)"
            elif "Debian" in suffix or "deb" in suffix.lower():
                for pkg_hint, os_label in DEBIAN_PKG_MAP.items():
                    if pkg_hint in suffix.lower():
                        os_name = os_label
                        break
                if not os_name:
                    os_name = "Debian (Version unbekannt)"
            elif "el6" in suffix or "el7" in suffix or "el8" in suffix or "el9" in suffix:
                ver = suffix.split("el")[1][0]
                os_name = f"RHEL/CentOS {ver}"
            if os_name:
                results.append({"ip": ip, "os": os_name, "source": "ssh_banner", "raw": suffix})
    return results


def _detect_os_from_nmap(nmap_data: dict) -> list[dict]:
    """Extract OS hints from nmap service data."""
    results: list[dict] = []
    services = nmap_data.get("services") or []
    for svc in services:
        ostype = svc.get("ostype", "")
        product = svc.get("product", "")
        extrainfo = svc.get("extrainfo", "")
        combined = f"{ostype} {product} {extrainfo}".strip()
        if not combined:
            continue
        if WINDOWS_HINTS.search(combined):
            results.append({"os": "Windows", "source": "nmap", "raw": combined})
        elif "linux" in combined.lower() or "ubuntu" in combined.lower():
            if "ubuntu" in combined.lower():
                results.append({"os": "Ubuntu Linux", "source": "nmap", "raw": combined})
            else:
                results.append({"os": "Linux", "source": "nmap", "raw": combined})
    return results


def _detect_os_from_headers(headers: dict) -> list[dict]:
    """Extract OS hints from HTTP headers like Server: nginx/1.24.0 (Ubuntu)."""
    results: list[dict] = []
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    combined = f"{server} {powered}"
    if "(Ubuntu)" in combined:
        results.append({"os": "Ubuntu Linux", "source": "http_header", "raw": combined})
    elif "(Debian)" in combined:
        results.append({"os": "Debian Linux", "source": "http_header", "raw": combined})
    elif "(CentOS)" in combined or "(Red Hat)" in combined:
        results.append({"os": "RHEL/CentOS", "source": "http_header", "raw": combined})
    elif "(Win64)" in combined or "(Win32)" in combined or "Microsoft" in combined:
        results.append({"os": "Windows", "source": "http_header", "raw": combined})
    return results


def _check_eol(os_name: str) -> tuple[bool, str, str] | None:
    """Check if an OS version is end-of-life. Returns (is_eol, eol_date, label)."""
    today = date.today().isoformat()
    for pattern, _, eol_date, label in EOL_DATABASE:
        if pattern.lower() in os_name.lower():
            return eol_date < today, eol_date, label
    return None


def _check_software_eol(tech: dict, result: ScanResult) -> None:
    """Check server software versions against EOL database."""
    try:
        from packaging.version import Version
    except ImportError:
        return

    checked: set[str] = set()
    for tech_key, version_str in tech.items():
        if not isinstance(version_str, str) or not version_str:
            continue
        for eol_prefix, min_version, eol_date, label in SOFTWARE_EOL:
            if eol_prefix not in tech_key.lower():
                continue
            key = f"{eol_prefix}:{min_version}"
            if key in checked:
                continue
            try:
                if Version(version_str) < Version(min_version):
                    checked.add(key)
                    is_eol = eol_date < date.today().isoformat()
                    if is_eol:
                        result.add(Finding(
                            id=f"eol.software.{eol_prefix}.{version_str}",
                            title=f"Veraltete Software: {eol_prefix} {version_str} (EOL seit {eol_date})",
                            description=(
                                f"Die eingesetzte Version {eol_prefix} {version_str} ist seit {eol_date} "
                                f"End-of-Life ({label}). Es werden keine Sicherheits-Updates mehr "
                                "veröffentlicht — bekannte und zukünftige CVEs bleiben ungepatcht."
                            ),
                            severity=Severity.HIGH,
                            category="EOL Software",
                            evidence={"software": eol_prefix, "version": version_str, "eol_date": eol_date},
                            recommendation=f"Auf eine aktuell unterstützte Version von {eol_prefix} upgraden.",
                            kbv_ref="KBV Anlage 2+3 (Patch-Management), BSI OPS.1.1.3",
                        ))
                    break
            except Exception:
                continue


def _check_ssh_auth_methods(ip: str, port: int, result: ScanResult) -> None:
    """Use paramiko to detect SSH authentication methods offered by the server."""
    try:
        import paramiko
    except ImportError:
        return

    transport = None
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        transport = paramiko.Transport(sock)
        transport.connect()

        # Try auth with a nonexistent user — the server will reject but
        # reveal which auth methods are allowed.
        try:
            transport.auth_none("mvzscan_probe_user")
        except paramiko.BadAuthenticationType as e:
            allowed = list(e.allowed_types)
        except paramiko.AuthenticationException:
            allowed = ["unknown"]
        else:
            # auth_none succeeded → CRITICAL: server allows login without any auth
            allowed = ["none"]
            result.add(Finding(
                id=f"access.ssh_no_auth.{ip.replace('.', '_')}",
                title=f"SSH auf {ip}:{port} erlaubt Login OHNE Authentifizierung",
                description="SSH auth_none wurde akzeptiert — der Server erlaubt Verbindungen ohne jede Authentifizierung.",
                severity=Severity.CRITICAL,
                category="Default Access",
                evidence={"ip": ip, "port": port, "auth_methods": ["none"]},
                recommendation="SSH-Konfiguration sofort prüfen: PermitEmptyPasswords no, PermitRootLogin no.",
            ))

        result.metadata.setdefault("ssh_auth", {})[ip] = {
            "port": port,
            "methods": allowed,
        }

        password_enabled = "password" in allowed
        keyboard_interactive = "keyboard-interactive" in allowed
        publickey = "publickey" in allowed

        if password_enabled:
            result.add(Finding(
                id=f"access.ssh_password_auth.{ip.replace('.', '_')}",
                title=f"SSH auf {ip}:{port} erlaubt Passwort-Authentifizierung",
                description=(
                    "Der SSH-Server akzeptiert Passwort-basierte Logins. Das ermöglicht "
                    "Brute-Force-Angriffe mit Tools wie hydra, medusa oder ncrack. "
                    "Best Practice ist ausschließlich Key-basierte Authentifizierung "
                    "(PasswordAuthentication no in sshd_config)."
                    + ("\n\nAuch keyboard-interactive ist aktiviert — eine weitere Brute-Force-Fläche." if keyboard_interactive else "")
                ),
                severity=Severity.MEDIUM,
                category="Default Access",
                evidence={"ip": ip, "port": port, "auth_methods": allowed},
                recommendation=(
                    "In /etc/ssh/sshd_config setzen:\n"
                    "  PasswordAuthentication no\n"
                    "  ChallengeResponseAuthentication no\n"
                    "  PermitRootLogin prohibit-password\n"
                    "Dann: systemctl restart sshd"
                ),
                kbv_ref="KBV Anlage 2 (Zugriffskontrolle), BSI IT-Grundschutz SYS.1.1",
            ))
        elif publickey and not password_enabled:
            result.add(Finding(
                id=f"access.ssh_key_only.{ip.replace('.', '_')}",
                title=f"SSH auf {ip}:{port}: nur Key-Authentifizierung (gut)",
                description="Der SSH-Server erlaubt ausschließlich Public-Key-Auth. Brute-Force ist damit praktisch unmöglich.",
                severity=Severity.INFO,
                category="Default Access",
                evidence={"ip": ip, "port": port, "auth_methods": allowed},
            ))

    except Exception:
        pass
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass


def check_os_and_eol(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("OS-Detection + EOL + SSH-Auth", 84)

    os_detections: list[dict] = []

    # 1. From SSH banners
    banners = result.metadata.get("banners") or {}
    os_detections.extend(_detect_os_from_ssh(banners))

    # 2. From nmap data
    nmap = result.metadata.get("nmap") or {}
    os_detections.extend(_detect_os_from_nmap(nmap))

    # 3. From HTTP headers
    headers = result.metadata.get("homepage_headers") or {}
    os_detections.extend(_detect_os_from_headers(headers))

    # Deduplicate by OS name
    seen_os: set[str] = set()
    unique: list[dict] = []
    for d in os_detections:
        if d["os"] not in seen_os:
            seen_os.add(d["os"])
            unique.append(d)

    if unique:
        result.metadata["os_detection"] = unique
        os_names = ", ".join(d["os"] for d in unique)
        result.add(Finding(
            id="os.detected",
            title=f"Betriebssystem erkannt: {os_names}",
            description=(
                "Das Betriebssystem des Servers wurde aus SSH-Banner, nmap-Daten "
                "und/oder HTTP-Headern abgeleitet."
            ),
            severity=Severity.INFO,
            category="Server",
            evidence={"detections": unique},
        ))

        # EOL check for each detected OS
        for d in unique:
            eol = _check_eol(d["os"])
            if eol and eol[0]:
                result.add(Finding(
                    id=f"eol.os.{d['os'].lower().replace(' ', '_')}",
                    title=f"Betriebssystem End-of-Life: {eol[2]}",
                    description=(
                        f"Das erkannte Betriebssystem ({d['os']}) hat seit {eol[1]} "
                        "keinen Support mehr. Es werden keine Sicherheitspatches mehr "
                        "veröffentlicht — jede neu entdeckte Schwachstelle bleibt "
                        "dauerhaft offen. Für ein MVZ mit Patientendaten ist das ein "
                        "schwerwiegender Verstoß gegen den Stand der Technik."
                    ),
                    severity=Severity.CRITICAL,
                    category="EOL Software",
                    evidence={"os": d["os"], "eol_date": eol[1], "source": d["source"]},
                    recommendation=f"Betriebssystem auf eine aktuell unterstützte Version upgraden.",
                    kbv_ref="KBV Anlage 2+3, DSGVO Art. 32 (Stand der Technik), BSI OPS.1.1.3",
                ))

    # 4. Software EOL checks
    tech = result.metadata.get("tech") or {}
    _check_software_eol(tech, result)

    # 5. SSH auth method detection
    port_scan = result.metadata.get("active_port_scan") or {}
    for ip, data in port_scan.items():
        if 22 in set(data.get("open_ports", [])):
            _check_ssh_auth_methods(ip, 22, result)

    # 6. Use nmap CPE data directly for CVE lookup
    if nmap.get("services"):
        for svc in nmap["services"]:
            cpe_list = svc.get("cpe_list") or []
            for cpe in cpe_list:
                if cpe and cpe.startswith("cpe:/"):
                    # Convert CPE 2.2 to tech key for vuln scanner
                    parts = cpe.split(":")
                    if len(parts) >= 4:
                        product = parts[2].lstrip("/").replace("_", " ")
                        version = parts[3] if len(parts) > 3 else ""
                        if product and version:
                            tech_key = f"nmap_cpe.{product.replace(' ', '_')}"
                            result.metadata.setdefault("tech", {})[tech_key] = version
