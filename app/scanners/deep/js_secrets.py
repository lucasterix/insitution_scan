"""Scan JavaScript files for embedded secrets and API endpoints.

SPAs regularly bundle API base URLs, anon/public keys, and sometimes
production credentials into JS files that are served to every visitor.
We crawl the homepage for script tags, fetch each JS file (cap 500 KB)
and run a curated regex set over the content.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import httpx

from app.scanners._baseline import fetch_baselines, is_catchall
from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"
MAX_JS_FILES = 15
MAX_JS_BYTES = 500_000
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

# (name, severity, pattern)
SECRET_PATTERNS: list[tuple[str, Severity, re.Pattern]] = [
    ("AWS Access Key", Severity.CRITICAL, re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret (heuristic)", Severity.CRITICAL, re.compile(r"(?i)aws_secret_access_key['\"\s:=]+[\"']?([A-Za-z0-9/+=]{40})")),
    ("Generic API key = ...", Severity.HIGH, re.compile(r"(?i)(?:api[-_]?key|apikey|secret|token)['\"\s:=]+[\"']([A-Za-z0-9_\-]{24,})[\"']")),
    ("Stripe Live Key", Severity.CRITICAL, re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Publishable", Severity.INFO, re.compile(r"pk_live_[0-9a-zA-Z]{24,}")),
    ("Google API Key", Severity.HIGH, re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Google OAuth Client", Severity.MEDIUM, re.compile(r"[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com")),
    ("GitHub Token", Severity.CRITICAL, re.compile(r"gh[posu]_[A-Za-z0-9]{36,}")),
    ("Slack Token", Severity.HIGH, re.compile(r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[0-9A-Za-z]{24,}")),
    ("JWT", Severity.LOW, re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}")),
    ("Private Key Block", Severity.CRITICAL, re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Firebase URL", Severity.INFO, re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
    ("Sentry DSN", Severity.LOW, re.compile(r"https://[a-f0-9]{32}@[a-z0-9\-.]+/\d+")),
]

API_ENDPOINT_RE = re.compile(r'["\'](/api/[a-zA-Z0-9/_\-]+)["\']')


def _fetch(client: httpx.Client, url: str) -> str | None:
    try:
        r = client.get(url)
        if r.status_code != 200:
            return None
        content = r.content
        if len(content) > MAX_JS_BYTES:
            content = content[:MAX_JS_BYTES]
        # Decode best-effort
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return None
    except httpx.HTTPError:
        return None


def check_js_secrets(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("JS Secret Scanner", 70)

    baselines = fetch_baselines(domain)

    try:
        with httpx.Client(
            timeout=8.0,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            r = client.get(f"https://{domain}")
            if r.status_code != 200:
                return
            html = r.text[:500_000]

            urls: list[str] = []
            seen: set[str] = set()
            for m in SCRIPT_SRC_RE.finditer(html):
                src = m.group(1)
                if src.startswith("http"):
                    url = src
                elif src.startswith("//"):
                    url = f"https:{src}"
                elif src.startswith("/"):
                    url = f"https://{domain}{src}"
                else:
                    continue
                if url in seen:
                    continue
                seen.add(url)
                urls.append(url)
                if len(urls) >= MAX_JS_FILES:
                    break

            if not urls:
                return

            js_files: list[dict] = []
            all_secrets: list[dict] = []
            all_endpoints: set[str] = set()

            def task(url: str) -> None:
                text = _fetch(client, url)
                if text is None:
                    return
                if is_catchall(text[:8192], baselines):
                    return
                js_files.append({"url": url, "length": len(text)})
                for name, sev, pat in SECRET_PATTERNS:
                    for m in pat.finditer(text):
                        snippet = m.group(0)[:80]
                        all_secrets.append({"file": url, "type": name, "severity": sev.value, "snippet": snippet})
                for m in API_ENDPOINT_RE.finditer(text):
                    all_endpoints.add(m.group(1))

            with ThreadPoolExecutor(max_workers=6) as ex:
                futures = [ex.submit(task, url) for url in urls]
                for f in as_completed(futures):
                    f.result()
    except httpx.HTTPError:
        return

    result.metadata["js_analysis"] = {
        "files_scanned": js_files,
        "api_endpoints_found": sorted(all_endpoints)[:100],
    }

    # Emit a finding per unique secret type with worst severity.
    grouped: dict[str, list[dict]] = {}
    for s in all_secrets:
        grouped.setdefault(s["type"], []).append(s)

    for secret_type, hits in grouped.items():
        sev = Severity(hits[0]["severity"])
        result.add(Finding(
            id=f"deep.js_secret.{secret_type.lower().replace(' ', '_')}",
            title=f"{secret_type} in JavaScript gefunden ({len(hits)}x)",
            description=(
                f"In ausgelieferten JavaScript-Dateien wurde mindestens ein Treffer für "
                f"'{secret_type}' gefunden. Credentials in Frontend-Assets sind für jeden "
                "Besucher lesbar und müssen als kompromittiert angesehen werden."
            ),
            severity=sev,
            category="Deep Scan",
            evidence={"hits": hits[:5]},
            recommendation=(
                "Secret sofort rotieren und aus dem Build entfernen. Für Public-Keys ist das "
                "meist harmlos, für alle anderen Typen kritisch. Secret-Scanning in der CI "
                "aktivieren (gitleaks, trufflehog)."
            ),
        ))

    if all_endpoints:
        result.add(Finding(
            id="deep.js_api_endpoints",
            title=f"{len(all_endpoints)} interne API-Endpunkte aus JavaScript extrahiert",
            description=(
                "Aus den geladenen JS-Bundles wurden interne API-Pfade extrahiert. "
                "Diese Endpunkte müssen einzeln auf Authentifizierung, Input-Validierung und "
                "Rate-Limiting geprüft werden — sie sind die wahre Angriffsfläche der App."
            ),
            severity=Severity.INFO,
            category="Deep Scan",
            evidence={"endpoints": sorted(all_endpoints)[:30]},
            recommendation="API-Endpunkte manuell oder per automatisiertem API-Pentest prüfen.",
        ))
