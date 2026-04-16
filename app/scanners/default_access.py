"""Test for unauthenticated / default access to discovered services.

When the port scanner finds open database/cache/FTP ports, this module
attempts anonymous or unauthenticated connections to verify if they're
actually protected.

These are among the most critical findings possible:
- Redis without AUTH → direct data read/write, often RCE via SLAVEOF
- Anonymous FTP → file system access, often leads to webshell upload
- Elasticsearch without X-Pack → read/modify all indexed data
- MongoDB without auth → dump every collection
- MySQL with root:empty → full database access

We DON'T brute-force passwords — we only test for NO authentication
or well-known anonymous access methods.
"""
from __future__ import annotations

import socket
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

TIMEOUT = 4.0


def _tcp_connect(ip: str, port: int) -> socket.socket | None:
    try:
        sock = socket.create_connection((ip, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        return sock
    except (OSError, socket.timeout):
        return None


def _check_redis(ip: str, result: ScanResult) -> None:
    """Redis without AUTH: PING → +PONG means no password required."""
    sock = _tcp_connect(ip, 6379)
    if not sock:
        return
    try:
        sock.sendall(b"PING\r\n")
        response = b""
        try:
            response = sock.recv(1024)
        except (socket.timeout, OSError):
            pass
        resp_str = response.decode("latin1", errors="replace").strip()

        if "+PONG" in resp_str:
            # Try to get server info
            sock.sendall(b"INFO server\r\n")
            info = b""
            try:
                info = sock.recv(4096)
            except (socket.timeout, OSError):
                pass
            info_str = info.decode("latin1", errors="replace")

            version = ""
            for line in info_str.split("\n"):
                if line.startswith("redis_version:"):
                    version = line.split(":", 1)[1].strip()
                    break

            result.add(Finding(
                id=f"access.redis_no_auth.{ip.replace('.', '_')}",
                title=f"Redis auf {ip}:6379 OHNE Authentifizierung erreichbar",
                description=(
                    f"Der Redis-Server auf {ip}:6379 antwortet auf PING ohne AUTH-Befehl. "
                    f"{'Version: ' + version + '. ' if version else ''}"
                    "Ein Angreifer kann:\n"
                    "1. Alle gespeicherten Daten lesen (Keys, Sessions, Cache)\n"
                    "2. Daten überschreiben oder löschen\n"
                    "3. Via SLAVEOF + MODULE LOAD Remote Code Execution erreichen\n"
                    "4. SSH-Keys in authorized_keys schreiben → Root-Zugriff\n\n"
                    "Redis ohne Auth aus dem Internet ist einer der häufigsten Wege "
                    "zu einem vollständigen Server-Kompromittierung."
                ),
                severity=Severity.CRITICAL,
                category="Default Access",
                evidence={"ip": ip, "port": 6379, "ping_response": resp_str, "version": version},
                recommendation=(
                    "Sofort: Redis per Firewall vom Internet abschotten (bind 127.0.0.1). "
                    "Dann: requirepass in redis.conf setzen. Prüfen ob bereits Fremd-Keys "
                    "in /root/.ssh/authorized_keys stehen."
                ),
                kbv_ref="KBV IT-Sicherheitsrichtlinie Anlage 3 (Zugriffskontrolle), DSGVO Art. 32",
            ))
            result.metadata.setdefault("default_access", {})["redis_open"] = True

        elif "-NOAUTH" in resp_str or "-ERR" in resp_str:
            # Auth required → good
            pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _check_ftp_anonymous(ip: str, result: ScanResult) -> None:
    """FTP anonymous login: USER anonymous + PASS → 230 = access granted."""
    sock = _tcp_connect(ip, 21)
    if not sock:
        return
    try:
        # Read banner
        banner = b""
        try:
            banner = sock.recv(1024)
        except (socket.timeout, OSError):
            pass

        sock.sendall(b"USER anonymous\r\n")
        user_resp = b""
        try:
            user_resp = sock.recv(1024)
        except (socket.timeout, OSError):
            pass

        sock.sendall(b"PASS anonymous@scan.zdkg.de\r\n")
        pass_resp = b""
        try:
            pass_resp = sock.recv(1024)
        except (socket.timeout, OSError):
            pass

        pass_str = pass_resp.decode("latin1", errors="replace").strip()

        if pass_str.startswith("230"):
            result.add(Finding(
                id=f"access.ftp_anonymous.{ip.replace('.', '_')}",
                title=f"FTP auf {ip}:21 erlaubt anonymen Zugriff",
                description=(
                    f"Der FTP-Server auf {ip}:21 akzeptiert anonyme Logins (USER anonymous). "
                    "Ein Angreifer kann:\n"
                    "1. Dateien auf dem Server lesen (Konfigurationen, Backups, Patientendaten)\n"
                    "2. Dateien hochladen (Webshells, Malware)\n"
                    "3. Den FTP-Server als Staging-Area für weitere Angriffe nutzen\n\n"
                    "Anonymes FTP aus dem Internet ist in einem MVZ-Kontext inakzeptabel."
                ),
                severity=Severity.CRITICAL,
                category="Default Access",
                evidence={
                    "ip": ip, "port": 21,
                    "banner": banner.decode("latin1", errors="replace")[:200],
                    "login_response": pass_str[:200],
                },
                recommendation="Anonymen FTP-Zugang sofort deaktivieren. FTP generell durch SFTP ersetzen.",
                kbv_ref="KBV Anlage 3 (Zugriffskontrolle), DSGVO Art. 32",
            ))
            result.metadata.setdefault("default_access", {})["ftp_anonymous"] = True

        sock.sendall(b"QUIT\r\n")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _check_elasticsearch(ip: str, result: ScanResult) -> None:
    """Elasticsearch without X-Pack auth: GET / returns cluster info."""
    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            r = client.get(f"http://{ip}:9200/")
            if r.status_code != 200:
                return
            try:
                data = r.json()
            except ValueError:
                return

            if not data.get("cluster_name") and not data.get("version"):
                return

            cluster = data.get("cluster_name", "")
            version = (data.get("version") or {}).get("number", "")

            # Try to access indices
            try:
                cat = client.get(f"http://{ip}:9200/_cat/indices?format=json")
                indices = cat.json() if cat.status_code == 200 else []
            except Exception:
                indices = []

            result.add(Finding(
                id=f"access.elasticsearch_no_auth.{ip.replace('.', '_')}",
                title=f"Elasticsearch auf {ip}:9200 OHNE Authentifizierung",
                description=(
                    f"Elasticsearch {version} (Cluster: {cluster}) auf {ip}:9200 "
                    f"antwortet ohne Authentifizierung. "
                    f"{'Es sind ' + str(len(indices)) + ' Indices vorhanden. ' if indices else ''}"
                    "Ein Angreifer kann:\n"
                    "1. Alle indexierten Daten lesen (Logs, Patientendaten, E-Mails)\n"
                    "2. Indices löschen oder manipulieren\n"
                    "3. Via Script-Queries Remote Code Execution erreichen (ältere Versionen)\n"
                    "4. Snapshot-Repositories anlegen → komplette Datenexfiltration"
                ),
                severity=Severity.CRITICAL,
                category="Default Access",
                evidence={
                    "ip": ip, "port": 9200,
                    "cluster": cluster, "version": version,
                    "indices_count": len(indices),
                    "indices_sample": [i.get("index") for i in indices[:10]] if isinstance(indices, list) else [],
                },
                recommendation=(
                    "X-Pack Security oder OpenSearch Security Plugin aktivieren. "
                    "Bis dahin: Elasticsearch per Firewall vom Internet abschotten (bind localhost)."
                ),
                kbv_ref="KBV Anlage 3, DSGVO Art. 32 (Zugriffskontrolle)",
            ))
            result.metadata.setdefault("default_access", {})["elasticsearch_open"] = True
    except httpx.HTTPError:
        pass


def _check_mongodb(ip: str, result: ScanResult) -> None:
    """MongoDB without auth: send a simple ismaster command."""
    sock = _tcp_connect(ip, 27017)
    if not sock:
        return
    try:
        # MongoDB wire protocol: send an OP_MSG with ismaster command.
        # Simplified: just check if the port accepts and responds.
        # A locked-down MongoDB closes the connection or sends auth error.
        import struct

        # Minimal ismaster query (legacy OP_QUERY format)
        # This is a well-formed MongoDB wire protocol message
        query_doc = b'\x21\x00\x00\x00'  # doc length
        query_doc += b'\x10ismaster\x00\x01\x00\x00\x00'  # ismaster: 1
        query_doc += b'\x00'  # end of doc

        # OP_QUERY header
        request_id = 1
        msg = struct.pack('<i', 0)  # message length placeholder
        msg += struct.pack('<i', request_id)
        msg += struct.pack('<i', 0)  # responseTo
        msg += struct.pack('<i', 2004)  # opCode: OP_QUERY
        msg += struct.pack('<i', 0)  # flags
        msg += b'admin.$cmd\x00'  # fullCollectionName
        msg += struct.pack('<i', 0)  # numberToSkip
        msg += struct.pack('<i', 1)  # numberToReturn
        msg += query_doc

        # Fix message length
        msg = struct.pack('<i', len(msg)) + msg[4:]

        sock.sendall(msg)
        response = b""
        try:
            response = sock.recv(4096)
        except (socket.timeout, OSError):
            pass

        if len(response) > 36 and b"ismaster" in response:
            result.add(Finding(
                id=f"access.mongodb_no_auth.{ip.replace('.', '_')}",
                title=f"MongoDB auf {ip}:27017 akzeptiert Verbindungen ohne Auth",
                description=(
                    "MongoDB antwortet auf eine ismaster-Query ohne Authentifizierung. "
                    "Ein Angreifer kann alle Datenbanken und Collections auslesen, "
                    "Daten löschen oder Ransomware-Notes hinterlassen "
                    "(bekanntes Muster seit 2017 'MongoDB Apocalypse')."
                ),
                severity=Severity.CRITICAL,
                category="Default Access",
                evidence={"ip": ip, "port": 27017},
                recommendation="MongoDB Auth aktivieren (--auth Flag oder security.authorization: enabled in mongod.conf).",
                kbv_ref="KBV Anlage 3, DSGVO Art. 32",
            ))
            result.metadata.setdefault("default_access", {})["mongodb_open"] = True
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def check_default_access(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    """Test unauthenticated access on every open port found by port scanner."""
    step("Default-Access-Test (Root/Anon)", 85)

    port_scan = result.metadata.get("active_port_scan") or {}

    for ip, data in port_scan.items():
        open_ports = set(data.get("open_ports", []))

        if 6379 in open_ports:
            _check_redis(ip, result)

        if 21 in open_ports:
            _check_ftp_anonymous(ip, result)

        if 9200 in open_ports:
            _check_elasticsearch(ip, result)

        if 27017 in open_ports:
            _check_mongodb(ip, result)
