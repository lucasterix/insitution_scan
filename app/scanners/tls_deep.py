"""Deep TLS analysis: forward secrecy, cipher strength, protocol details.

Complements SSL Labs (which grades externally) with a local TLS connection
that inspects the negotiated cipher suite directly. This catches:

- Missing forward secrecy (no ECDHE/DHE → if server key is compromised,
  all past sessions can be decrypted).
- Weak cipher algorithms (RC4, DES, 3DES, NULL).
- TLS compression enabled (CRIME attack vector).

Runs on the primary domain + any subdomains where we already have alive-status.
"""
from __future__ import annotations

import socket
import ssl
from typing import Callable

from app.scanners.base import Finding, ScanResult, Severity

TIMEOUT = 5.0

WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon"}
PFS_PREFIXES = ("ECDHE", "DHE", "TLS_AES", "TLS_CHACHA")


def _check_tls(hostname: str) -> dict | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                version = ssock.version()
                compression = ssock.compression()
    except (socket.timeout, ssl.SSLError, OSError):
        return None

    if not cipher:
        return None

    cipher_name, protocol, bits = cipher
    return {
        "hostname": hostname,
        "cipher_name": cipher_name,
        "protocol": protocol,
        "bits": bits,
        "tls_version": version,
        "compression": compression,
    }


def check_tls_deep(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("TLS Deep (Forward Secrecy / Cipher)", 55)

    info = _check_tls(domain)
    if not info:
        return

    result.metadata["tls_deep"] = info

    cipher_name = info["cipher_name"]
    bits = info.get("bits") or 0

    has_pfs = any(cipher_name.startswith(p) for p in PFS_PREFIXES)
    is_weak = any(w in cipher_name.upper() for w in WEAK_CIPHERS)
    has_compression = info.get("compression") is not None

    if not has_pfs:
        result.add(Finding(
            id="tls.no_forward_secrecy",
            title=f"Kein Forward Secrecy: Cipher {cipher_name}",
            description=(
                f"Der ausgehandelte Cipher ({cipher_name}) bietet kein Perfect Forward Secrecy "
                "(PFS). Ohne PFS können aufgezeichnete TLS-Sessions nachträglich entschlüsselt "
                "werden, wenn der Server-Schlüssel irgendwann kompromittiert wird. "
                "PFS-Cipher (ECDHE/DHE) erzeugen pro Session einen neuen Schlüssel."
            ),
            severity=Severity.LOW,
            category="TLS",
            evidence=info,
            recommendation="Cipher-Suite auf ECDHE-basierte Algorithmen umstellen (nginx: ssl_ciphers 'ECDHE-...').",
        ))

    if is_weak:
        # NULL/EXPORT/RC4/DES = practically broken → HIGH.
        # 3DES = theoretical (Sweet32 needs 2^32 chosen plaintexts) → MEDIUM.
        cipher_upper = cipher_name.upper()
        if any(s in cipher_upper for s in ("NULL", "EXPORT", "RC4", "_DES_")) and "3DES" not in cipher_upper:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        result.add(Finding(
            id="tls.weak_cipher",
            title=f"Schwacher Cipher: {cipher_name}",
            description=(
                f"Der ausgehandelte Cipher ({cipher_name}) gilt als kryptographisch schwach. "
                "RC4, DES, 3DES, NULL und EXPORT-Cipher können mit moderater Rechenleistung "
                "gebrochen werden."
            ),
            severity=sev,
            category="TLS",
            evidence=info,
            recommendation="Schwache Cipher deaktivieren und nur AES-128/256-GCM + ChaCha20 zulassen.",
        ))

    if has_compression:
        result.add(Finding(
            id="tls.compression_enabled",
            title="TLS-Kompression aktiv (CRIME-Angriffsvektor)",
            description=(
                "TLS-Kompression ermöglicht den CRIME-Angriff: ein Angreifer im Netzwerk "
                "kann durch Beobachten der komprimierten Paketgrößen Rückschlüsse auf den "
                "Klartext (z.B. Session-Cookies) ziehen."
            ),
            severity=Severity.MEDIUM,
            category="TLS",
            evidence=info,
            recommendation="TLS-Kompression deaktivieren (nginx: `ssl_prefer_server_ciphers on;` + keine COMP).",
        ))

    if bits and bits < 128:
        # <64 bits = broken in hours. 64-112 = days-weeks. 112-127 = theoretical.
        if bits < 64:
            sev = Severity.HIGH
        elif bits < 112:
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW
        result.add(Finding(
            id="tls.low_bit_cipher",
            title=f"Cipher mit nur {bits} Bit Schlüssellänge",
            description=f"Der Cipher {cipher_name} verwendet nur {bits} Bit — unter 128 Bit gilt als unsicher.",
            severity=sev,
            category="TLS",
            evidence=info,
        ))
