"""Auth-cookie forensics: JWT decoding + weak session detection.

Extends the basic Set-Cookie flags check (done in privacy.py) with:

- JWT parsing (header + payload, no signature verify).
- alg=none detection — CRITICAL, token can be forged without a secret.
- Long-lived token detection (>365d) — MEDIUM.
- Sensitive claims in plaintext (email/role/user_id) — LOW informational.
- Short/weak session IDs (< 16 chars) — LOW.

Runs against the homepage response. More thorough form-based session tests
(POST credentials, observe session rotation) are out of scope for passive
scanning.
"""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")


def _b64url_decode(segment: str) -> bytes | None:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception:  # noqa: BLE001
        return None


def _parse_jwt(token: str) -> tuple[dict, dict] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_raw = _b64url_decode(parts[0])
    payload_raw = _b64url_decode(parts[1])
    if header_raw is None or payload_raw is None:
        return None
    try:
        header = json.loads(header_raw)
        payload = json.loads(payload_raw)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def _collect_cookies(response: httpx.Response) -> list[tuple[str, str]]:
    """Return list of (cookie_name, cookie_value)."""
    out: list[tuple[str, str]] = []
    raw_list: list[str] = []
    if hasattr(response.headers, "get_list"):
        raw_list = response.headers.get_list("set-cookie")
    if not raw_list:
        raw = response.headers.get("set-cookie", "")
        if raw:
            raw_list = [raw]
    for raw in raw_list:
        first_part = raw.split(";", 1)[0].strip()
        if "=" not in first_part:
            continue
        name, value = first_part.split("=", 1)
        out.append((name.strip(), value.strip()))
    return out


def check_cookie_forensics(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Cookie-Forensik", 89)

    try:
        with httpx.Client(
            timeout=6.0, follow_redirects=False, headers={"User-Agent": USER_AGENT}
        ) as client:
            r = client.get(f"https://{domain}")
    except httpx.HTTPError:
        return

    cookies = _collect_cookies(r)
    if not cookies:
        return

    report: list[dict] = []

    for name, value in cookies:
        entry: dict = {"cookie": name, "value_len": len(value)}

        # Short / weak session ID
        if len(value) < 16 and any(kw in name.lower() for kw in ("session", "sid", "token", "auth")):
            result.add(
                Finding(
                    id=f"cookie.weak_session.{name}",
                    title=f"Schwache Session-ID in Cookie '{name}' (nur {len(value)} Zeichen)",
                    description=(
                        "Der Cookie-Wert hat weniger als 16 Zeichen und enthält session/sid/token/"
                        "auth im Namen. Das ist für kryptographisch sichere Session-IDs zu kurz — "
                        "Angreifer können durch Brute-Force valide Sessions erraten."
                    ),
                    severity=Severity.LOW,
                    category="Cookie Forensics",
                    evidence={"cookie": name, "length": len(value)},
                    recommendation="Session-IDs mit min. 128 Bit Entropie generieren (z.B. secrets.token_urlsafe(32)).",
                )
            )

        # JWT detection
        if JWT_RE.match(value):
            parsed = _parse_jwt(value)
            if parsed is None:
                continue
            header, payload = parsed
            alg = str(header.get("alg", "")).lower()
            entry["jwt"] = {"alg": alg, "claims": list(payload.keys())}

            # alg=none
            if alg == "none":
                result.add(
                    Finding(
                        id=f"cookie.jwt_alg_none.{name}",
                        title=f"JWT-Cookie '{name}' verwendet alg=none",
                        description=(
                            "Der JWT ist unsigniert: ein Angreifer kann im Browser beliebige "
                            "Claims setzen und als gültiger Nutzer/Admin eingeloggt sein. "
                            "Das ist eine der ältesten JWT-Lücken und wird bei vielen Frameworks "
                            "bei Fehlkonfiguration serverseitig akzeptiert."
                        ),
                        severity=Severity.CRITICAL,
                        category="Cookie Forensics",
                        evidence={"cookie": name, "jwt_header": header, "jwt_payload": payload},
                        recommendation="Server-Side alg-Whitelist erzwingen (nur HS256/RS256/ES256), niemals 'none' akzeptieren.",
                    )
                )

            # Weak HMAC algorithm
            if alg == "hs256":
                # HS256 is fine when secret is strong, but flag as informational
                entry["hs256"] = True

            # Expiry checks
            exp = payload.get("exp")
            if isinstance(exp, (int, float)):
                try:
                    exp_dt = datetime.fromtimestamp(int(exp), tz=timezone.utc)
                    delta_days = (exp_dt - datetime.now(timezone.utc)).days
                    entry["exp_days_left"] = delta_days
                    if delta_days < 0:
                        result.add(
                            Finding(
                                id=f"cookie.jwt_expired.{name}",
                                title=f"JWT-Cookie '{name}' ist bereits abgelaufen",
                                description="Der Server stellt einen bereits abgelaufenen JWT aus. Entweder ist die Uhr falsch konfiguriert oder das Token-Management fehlerhaft.",
                                severity=Severity.LOW,
                                category="Cookie Forensics",
                                evidence={"cookie": name, "exp": exp, "days_ago": -delta_days},
                            )
                        )
                    elif delta_days > 365:
                        result.add(
                            Finding(
                                id=f"cookie.jwt_long_lived.{name}",
                                title=f"JWT-Cookie '{name}' ist sehr langlebig ({delta_days} Tage)",
                                description=(
                                    "Sehr langlebige Access-Tokens können nach Kompromittierung "
                                    "lange missbraucht werden, weil es keinen Refresh-/Revoke-Mechanismus "
                                    "gibt. Best Practice: Access-Token < 24 h, Refresh-Token mit "
                                    "Revoke-Liste serverseitig."
                                ),
                                severity=Severity.MEDIUM,
                                category="Cookie Forensics",
                                evidence={"cookie": name, "exp": exp, "days_left": delta_days},
                                recommendation="Access-Token auf <24 h setzen, Refresh-Token-Flow implementieren.",
                            )
                        )
                except (ValueError, OSError, OverflowError):
                    pass

            # Leaked PII in payload
            pii_claims = {
                k for k in payload.keys()
                if k.lower() in {"email", "mail", "name", "username", "user_id", "uid", "role", "roles", "permissions", "admin", "is_admin"}
            }
            if pii_claims:
                result.add(
                    Finding(
                        id=f"cookie.jwt_claims_readable.{name}",
                        title=f"JWT-Cookie '{name}' enthält Klartext-Claims ({', '.join(sorted(pii_claims))})",
                        description=(
                            "JWTs sind Base64-kodiert, nicht verschlüsselt. Jeder Browser-Nutzer "
                            f"kann die Felder {', '.join(sorted(pii_claims))} im Klartext lesen. "
                            "Bei E-Mail/User-ID ist das oft gewollt, bei 'role'/'is_admin' nicht — "
                            "Clientseitig exponierte Rollen laden Angreifer zu Privilege-Escalation-"
                            "Versuchen ein."
                        ),
                        severity=Severity.LOW,
                        category="Cookie Forensics",
                        evidence={"cookie": name, "claims": sorted(pii_claims), "payload_sample": payload},
                        recommendation=(
                            "Sensitive Daten aus dem Payload nehmen und serverseitig in der Session "
                            "halten. Nur minimal notwendige Claims (sub, exp, iat) im JWT."
                        ),
                    )
                )

        report.append(entry)

    if report:
        result.metadata["cookie_forensics"] = report
