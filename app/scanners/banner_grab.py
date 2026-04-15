"""Banner-grab open ports and extract service versions.

Runs against the IPs + open ports discovered by the active port scanner.
For each reachable port, reads (and optionally sends) a probe, then regexes
the banner for product + version strings.

Extracted versions are written to result.metadata["tech"] under banner.* keys,
which the vuln scanner picks up via CPE_MAP to trigger NVD + KEV + EPSS
enrichment in the same run.
"""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from app.scanners.base import Finding, ScanResult, Severity

TIMEOUT = 4.0

# HTTP probe payload for ports 80/8080. HTTPS needs TLS wrapping → skipped
# because the HTTPS Server header is already captured by check_http.
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: mvzscan.local\r\nUser-Agent: MVZ-SelfScan/1.0\r\n\r\n"

# port → probe bytes (or None to passively read banner)
PROBES: dict[int, bytes | None] = {
    21: None,    # FTP
    22: None,    # SSH
    23: None,    # Telnet
    25: None,    # SMTP
    110: None,   # POP3
    143: None,   # IMAP
    3306: None,  # MySQL handshake contains version
    5432: None,  # PostgreSQL startup — silent until startup packet, skip regex
    80: HTTP_PROBE,
    8080: HTTP_PROBE,
}

# (regex, tech_key_suffix, friendly_label)
# tech_key_suffix matches entries in vuln.CPE_MAP as "banner.{suffix}".
VERSION_RULES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"SSH-\d\.\d-OpenSSH_([\d.]+(?:p\d+)?)", re.IGNORECASE), "openssh", "OpenSSH"),
    (re.compile(r"SSH-\d\.\d-dropbear[_\s]?([\d.]+)?", re.IGNORECASE), "dropbear", "Dropbear"),
    (re.compile(r"ProFTPD\s+([\d.]+)", re.IGNORECASE), "proftpd", "ProFTPD"),
    (re.compile(r"vsftpd\s+([\d.]+)", re.IGNORECASE), "vsftpd", "vsftpd"),
    (re.compile(r"Pure-FTPd"), "pureftpd", "Pure-FTPd"),
    (re.compile(r"FileZilla Server (?:version )?([\d.]+)", re.IGNORECASE), "filezilla", "FileZilla Server"),
    (re.compile(r"Sendmail\s+([\d.]+)", re.IGNORECASE), "sendmail", "Sendmail"),
    (re.compile(r"Exim\s+([\d.]+)", re.IGNORECASE), "exim", "Exim"),
    (re.compile(r"Dovecot\s+([\d.]+)", re.IGNORECASE), "dovecot", "Dovecot"),
    (re.compile(r"Microsoft-IIS/([\d.]+)"), "iis", "Microsoft IIS"),
    (re.compile(r"Server:\s*Apache/([\d.]+)", re.IGNORECASE), "apache_banner", "Apache httpd"),
    (re.compile(r"Server:\s*nginx/([\d.]+)", re.IGNORECASE), "nginx_banner", "nginx"),
    (re.compile(r"([\d]+\.[\d]+\.[\d]+)-MariaDB", re.IGNORECASE), "mariadb", "MariaDB"),
    (re.compile(r"\x00([\d]+\.[\d]+\.[\d]+)-log"), "mysql", "MySQL"),
    (re.compile(r"Courier-IMAP ready"), "courier", "Courier-IMAP"),
]


def _grab(ip: str, port: int) -> str | None:
    probe = PROBES.get(port)
    try:
        sock = socket.create_connection((ip, port), timeout=TIMEOUT)
    except (OSError, socket.timeout):
        return None
    try:
        sock.settimeout(TIMEOUT)
        if probe:
            try:
                sock.sendall(probe)
            except OSError:
                return None
        data = b""
        try:
            while len(data) < 2048:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
                if len(data) >= 512:
                    break
        except (socket.timeout, OSError):
            pass
        return data.decode("latin1", errors="replace") if data else None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def check_banners(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    port_scan = result.metadata.get("active_port_scan") or {}
    targets: list[tuple[str, int]] = []
    for ip, info in port_scan.items():
        for port in info.get("open_ports", []):
            if port in PROBES:
                targets.append((ip, port))

    if not targets:
        return

    step(f"Banner-Grab ({len(targets)} Ports)", 87)

    banners_by_ip: dict[str, dict[int, str]] = {}

    def task(entry: tuple[str, int]) -> None:
        ip, port = entry
        banner = _grab(ip, port)
        if not banner:
            return
        banner_trimmed = banner[:400]
        banners_by_ip.setdefault(ip, {})[port] = banner_trimmed

        for pattern, tech_key, label in VERSION_RULES:
            m = pattern.search(banner)
            if not m:
                continue
            version = m.group(1) if m.lastindex and m.group(1) else ""
            if not version:
                # Product detected but no parseable version — still useful for Shodan/tech metadata.
                result.metadata.setdefault("tech", {})[f"banner.{tech_key}_present"] = "unknown"
                continue
            tech = result.metadata.setdefault("tech", {})
            tech[f"banner.{tech_key}"] = version
            result.add(
                Finding(
                    id=f"banner.version.{ip.replace('.', '_')}.{port}.{tech_key}",
                    title=f"{label} {version} auf {ip}:{port} via Banner offengelegt",
                    description=(
                        f"Der Dienst auf {ip}:{port} liefert seinen Produktnamen und die genaue "
                        f"Version im Banner aus: \"{banner_trimmed[:180]}\". Das ist doppelt kritisch: "
                        "Angreifer brauchen nicht zu raten welche Software läuft, und der nachfolgende "
                        "CVE-Scan in dieser Pipeline nutzt die Versionsnummer automatisch für den "
                        "NVD-Abgleich."
                    ),
                    severity=Severity.LOW,
                    category="Banner Grab",
                    evidence={
                        "ip": ip,
                        "port": port,
                        "banner": banner_trimmed[:300],
                        "product": label,
                        "version": version,
                    },
                    recommendation=(
                        "Banner-Verschleierung im Dienst aktivieren (Apache: `ServerTokens Prod`, "
                        "nginx: `server_tokens off`, Postfix: `smtpd_banner`) und Dienst auf aktuelle "
                        "Version patchen."
                    ),
                )
            )
            break

    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = [ex.submit(task, t) for t in targets]
        for f in as_completed(futures):
            f.result()

    if banners_by_ip:
        result.metadata["banners"] = banners_by_ip
