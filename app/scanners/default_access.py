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


def _check_mysql_exposed(ip: str, result: ScanResult) -> None:
    """MySQL: check if the handshake accepts a connection. We DON'T send credentials."""
    sock = _tcp_connect(ip, 3306)
    if not sock:
        return
    try:
        banner = b""
        try:
            banner = sock.recv(1024)
        except (socket.timeout, OSError):
            pass
        if not banner or len(banner) < 5:
            return
        # MySQL handshake: byte 4 = protocol version, then null-terminated version string
        banner_str = banner.decode("latin1", errors="replace")
        # Check for "access denied" immediately (auth required = good)
        if "access denied" in banner_str.lower():
            return
        # MySQL server sent a greeting → accepting connections from the internet
        # We DON'T try to auth — just flag that MySQL is reachable and listening
        result.add(Finding(
            id=f"access.mysql_exposed.{ip.replace('.', '_')}",
            title=f"MySQL auf {ip}:3306 akzeptiert Verbindungen aus dem Internet",
            description=(
                "Der MySQL-Server sendet ein Handshake-Paket an jeden Client der sich verbindet. "
                "Ob ein Passwort konfiguriert ist, wurde NICHT getestet (keine Credentials gesendet). "
                "Aber: MySQL aus dem Internet erreichbar = Brute-Force auf root/admin-Accounts möglich."
            ),
            severity=Severity.HIGH,
            category="Default Access",
            evidence={"ip": ip, "port": 3306, "banner": banner_str[:200]},
            recommendation="MySQL per Firewall auf localhost beschränken (bind-address = 127.0.0.1).",
        ))
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _check_memcached(ip: str, result: ScanResult) -> None:
    """Memcached without auth: 'stats' command should return server info."""
    sock = _tcp_connect(ip, 11211)
    if not sock:
        return
    try:
        sock.sendall(b"stats\r\n")
        resp = b""
        try:
            resp = sock.recv(4096)
        except (socket.timeout, OSError):
            pass
        resp_str = resp.decode("latin1", errors="replace")

        if "STAT" in resp_str:
            result.add(Finding(
                id=f"access.memcached_no_auth.{ip.replace('.', '_')}",
                title=f"Memcached auf {ip}:11211 OHNE Authentifizierung",
                description=(
                    "Memcached antwortet auf den 'stats'-Befehl ohne Auth. "
                    "Angreifer können alle gecachten Daten auslesen (Sessions, Tokens, "
                    "Nutzer-Objekte) und Memcached als DDoS-Amplifier missbrauchen "
                    "(UDP-Reflection, bekannt seit 2018 mit Verstärkungsfaktor 51.000x)."
                ),
                severity=Severity.CRITICAL,
                category="Default Access",
                evidence={"ip": ip, "port": 11211, "response_snippet": resp_str[:300]},
                recommendation="Memcached per Firewall auf localhost beschränken oder SASL-Auth aktivieren.",
                kbv_ref="KBV Anlage 3, DSGVO Art. 32",
            ))
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _check_smtp_open_relay(ip: str, result: ScanResult) -> None:
    """SMTP open relay: try MAIL FROM + RCPT TO to an external address."""
    sock = _tcp_connect(ip, 25)
    if not sock:
        return
    try:
        banner = b""
        try:
            banner = sock.recv(1024)
        except (socket.timeout, OSError):
            pass
        sock.sendall(b"EHLO mvzscan.local\r\n")
        try:
            sock.recv(2048)
        except (socket.timeout, OSError):
            pass
        sock.sendall(b"MAIL FROM:<test@mvzscan.local>\r\n")
        mail_resp = b""
        try:
            mail_resp = sock.recv(1024)
        except (socket.timeout, OSError):
            pass
        if not mail_resp or b"250" not in mail_resp:
            sock.sendall(b"QUIT\r\n")
            return
        sock.sendall(b"RCPT TO:<relay-test@example.invalid>\r\n")
        rcpt_resp = b""
        try:
            rcpt_resp = sock.recv(1024)
        except (socket.timeout, OSError):
            pass
        sock.sendall(b"QUIT\r\n")

        rcpt_str = rcpt_resp.decode("latin1", errors="replace")
        if rcpt_str.startswith("250"):
            result.add(Finding(
                id=f"access.smtp_open_relay.{ip.replace('.', '_')}",
                title=f"SMTP Open Relay auf {ip}:25",
                description=(
                    "Der SMTP-Server akzeptiert RCPT TO an eine externe Domain ohne Auth. "
                    "Das ist ein offenes Mail-Relay: Angreifer können über diesen Server "
                    "Spam und Phishing-Mails versenden, was zur Blacklistung der IP führt."
                ),
                severity=Severity.HIGH,
                category="Default Access",
                evidence={"ip": ip, "port": 25, "rcpt_response": rcpt_str[:200]},
                recommendation="SMTP-Relay nur für authentisierte Benutzer erlauben (Postfix: smtpd_relay_restrictions).",
            ))
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _assess_brute_force_risk(ip: str, open_ports: set, result: ScanResult) -> None:
    """Assess how easy brute-forcing would be for each exposed service.

    We DON'T perform actual brute-force — we calculate a risk score based on:
    - Is the service exposed to the internet? (yes, since port is open)
    - Does the service have built-in rate limiting? (known per protocol)
    - Is there a WAF/fail2ban visible? (from firewall_test metadata)
    - Can multi-try attacks bypass limits? (xmlrpc system.multicall etc.)
    """
    firewall = result.metadata.get("firewall_test") or {}
    # firewall_test runs inside the deep scan which happens AFTER this check in
    # the pipeline. "firewall_known" distinguishes "we didn't run the test" from
    # "we ran it and there was no WAF".
    firewall_known = bool(firewall)
    has_waf = bool(firewall.get("waf_detected")) or bool(firewall.get("waf_behavioral"))
    rate_limited = any(
        r.get("rate_limited")
        for r in (firewall.get("rate_limit_results") or [])
    )

    services_at_risk: list[dict] = []

    BRUTE_RISK = {
        22: ("SSH", "mittel", "SSH hat ChallengeResponseAuthentication, aber ohne fail2ban sind 1000+ Versuche/Minute möglich. hydra/medusa cracken schwache Passwörter in Stunden."),
        21: ("FTP", "hoch", "FTP hat kein eingebautes Rate-Limiting. Ein Angreifer testet Credentials mit hydra unbegrenzt schnell."),
        3389: ("RDP", "sehr hoch", "RDP hat kein Rate-Limiting. NLA schützt, aber bei deaktiviertem NLA sind Brute-Force-Angriffe mit crowbar/hydra trivial. RDP ist der #1 Ransomware-Einstiegspunkt."),
        3306: ("MySQL", "mittel", "MySQL hat max_connect_errors (default 100), aber das lässt sich umgehen. Mit hydra/medusa gegen root + leere/schwache Passwörter."),
        5432: ("PostgreSQL", "mittel", "PostgreSQL hat pg_hba.conf, aber bei md5-Auth ohne IP-Beschränkung ist Brute-Force mit hydra möglich."),
        6379: ("Redis", "extrem", "Redis hat KEIN Rate-Limiting für AUTH. Ein Angreifer testet 100.000+ Passwörter/Sekunde."),
        27017: ("MongoDB", "hoch", "MongoDB ohne --auth hat gar keine Passwort-Hürde. Mit Auth: kein Rate-Limiting, Brute-Force trivial."),
        110: ("POP3", "hoch", "POP3 hat kein Rate-Limiting. Mailbox-Passwörter werden mit hydra in Minuten geknackt."),
        143: ("IMAP", "hoch", "IMAP hat kein Rate-Limiting. Zugriff auf Patienten-E-Mails nach erfolgreichem Brute-Force."),
    }

    for port in sorted(open_ports):
        if port not in BRUTE_RISK:
            continue
        service, risk_level, explanation = BRUTE_RISK[port]
        services_at_risk.append({
            "port": port,
            "service": service,
            "brute_force_risk": risk_level,
            "explanation": explanation,
            "waf_protection": has_waf,
            "rate_limited": rate_limited,
        })

    if not services_at_risk:
        return

    result.metadata.setdefault("brute_force_assessment", {})[ip] = services_at_risk

    critical_services = [s for s in services_at_risk if s["brute_force_risk"] in ("sehr hoch", "extrem")]
    high_services = [s for s in services_at_risk if s["brute_force_risk"] == "hoch"]

    lines = []
    for s in services_at_risk:
        protection = ""
        if has_waf:
            protection = " (WAF erkannt → teilweise geschützt)"
        lines.append(
            f"  • {s['service']} (Port {s['port']}): "
            f"Brute-Force-Risiko **{s['brute_force_risk']}**{protection}\n"
            f"    {s['explanation']}"
        )

    sev = Severity.HIGH if critical_services else Severity.MEDIUM if high_services else Severity.LOW

    if has_waf:
        waf_note = "\n\n✅ WAF erkannt — bietet teilweisen Schutz gegen automatisierte Angriffe."
    elif firewall_known:
        waf_note = "\n\n❌ Keine WAF erkannt — kein Netzwerk-Level-Schutz gegen Brute-Force."
    else:
        waf_note = ""  # firewall_test didn't run (non-deep scan); don't speculate.

    result.add(Finding(
        id=f"access.brute_force_risk.{ip.replace('.', '_')}",
        title=f"Brute-Force-Risikoeinschätzung: {len(services_at_risk)} exponierte Services auf {ip}",
        description=(
            "Für jeden offenen Service wurde bewertet, wie leicht ein Brute-Force-Angriff "
            "wäre — basierend auf eingebautem Rate-Limiting, WAF-Schutz und bekanntem "
            "Angreifer-Tooling:\n\n" + "\n".join(lines) + waf_note
        ),
        severity=sev,
        category="Default Access",
        evidence={"services": services_at_risk},
        recommendation=(
            "1. Fail2ban/CrowdSec auf dem Server installieren (sperrt IPs nach N Fehlversuchen).\n"
            "2. Dienste die nicht öffentlich sein müssen per Firewall auf VPN/IP-Whitelist beschränken.\n"
            "3. Starke Passwörter erzwingen (min. 16 Zeichen, kein Wörterbuch-Wort).\n"
            "4. MFA wo möglich (SSH: pam_google_authenticator, RDP: Duo/Azure MFA)."
        ),
        kbv_ref="KBV Anlage 2+3 (Zugriffskontrolle, Netzwerk-Härtung)",
    ))


# Hostname patterns that identify shared-hosting / reseller infrastructure.
# A MySQL/FTP server reachable on such an IP is not the customer's own server —
# it's some neighbour's service on the shared host, and emitting it as a
# finding for the customer is misleading (they can't close the port).
_SHARED_HOSTING_PATTERNS: tuple[str, ...] = (
    "kasserver.com",
    "all-inkl.com",
    "hosteurope.de",
    "webpack.hosteurope",
    "alfahosting",
    "de-nserver.de",
    "nserver.de",
    "goserver.host",
    "ionos.com",
    "1and1.com",
    "secureserver.net",
    "hostinger.",
    "strato.de",
    "hidrive.strato",
    "estugo.de",
    "whserv.de",
    "your-server.de",
    "clients.your-server.de",
    "netcup-net.de",
    "netcup.net",           # vServer/shared cluster
    "domainfactory.de",
    "ispgateway.de",        # DomainFactory-Alias / shared
    "mittwald.de",
    "df-server.de",
    "wixsite.com",          # Wix website builder infrastructure
    "wix.com",
    "wixstatic.com",
    "oxeed.com",            # Open-Xchange mail hosting
    "firstcolo.net",
    "webgo24.de",
    "webgo.de",
    "contabo.net",          # VPS cluster
    "contaboserver.net",
    "raidboxes.io",         # WordPress managed hoster
    "wpengine.com",
    "kinsta.com",
    "netlify.com",          # static hosts
    "vercel.app",
    "fly.dev",
    "azurewebsites.net",
    "cloudfront.net",
)


def _is_shared_hosting_ptr(ptr: str | None) -> bool:
    if not ptr:
        return False
    p = ptr.lower()
    return any(needle in p for needle in _SHARED_HOSTING_PATTERNS)


def check_default_access(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    """Test unauthenticated access + brute-force risk on every open port."""
    step("Default-Access + Brute-Force-Risk", 85)

    port_scan = result.metadata.get("active_port_scan") or {}
    # PTR check: if the IP lives on a shared-hosting PTR, open ports on that
    # IP belong to the hosting provider / neighbours, not to this customer.
    # We resolve the PTR inline (per-IP) because this module can run before
    # server_analysis writes its metadata.
    import socket
    shared_ips: dict[str, str] = {}
    for ip in port_scan.keys():
        try:
            ptr = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            ptr = ""
        if _is_shared_hosting_ptr(ptr):
            shared_ips[ip] = ptr
    if shared_ips:
        result.metadata.setdefault("shared_hosting_detected", {}).update(shared_ips)

    for ip, data in port_scan.items():
        open_ports = set(data.get("open_ports", []))

        if ip in shared_ips:
            # Skip DB/FTP/Memcached/SMTP service-level probes entirely — those
            # belong to the hosting provider, not the customer. The separate
            # "Shared Hosting" informational finding is still emitted by the
            # server_analysis scanner so the customer knows the overall risk.
            continue

        if 6379 in open_ports:
            _check_redis(ip, result)

        if 21 in open_ports:
            _check_ftp_anonymous(ip, result)

        if 9200 in open_ports:
            _check_elasticsearch(ip, result)

        if 27017 in open_ports:
            _check_mongodb(ip, result)

        if 3306 in open_ports:
            _check_mysql_exposed(ip, result)

        if 11211 in open_ports:
            _check_memcached(ip, result)

        if 25 in open_ports:
            _check_smtp_open_relay(ip, result)

        # Brute-force risk assessment for all exposed services
        _assess_brute_force_risk(ip, open_ports, result)
