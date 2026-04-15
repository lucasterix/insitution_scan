"""Healthcare-specific security checks for German MVZ / Arztpraxen.

Focuses on the typical tech stack of a medical care center:

1. KIM (Kommunikation im Medizinwesen) infrastructure detection
2. Telematikinfrastruktur (TI) connector web UIs (SecuNET, KoCoBox, CGM)
3. Praxis-Verwaltungssystem (PVS) fingerprinting from HTML
4. Patient portal / Terminbuchung widget detection (Doctolib, Samedi, Jameda)
5. Sensitive healthcare API / patient area path probes
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import dns.exception
import dns.resolver
import httpx

from app.scanners._baseline import fetch_baselines, is_catchall
from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

# --- 1. KIM DNS -----------------------------------------------------------

KIM_DNS_CHECKS = (
    ("SRV", "_kim._tcp.{domain}"),
    ("A", "kim.{domain}"),
    ("A", "kim-smtp.{domain}"),
    ("A", "mail-kim.{domain}"),
)

# --- 2. TI-Konnektor web UIs --------------------------------------------

TI_CONNECTOR_PATHS: list[tuple[str, str]] = [
    ("/cetp/services/", "SecuNET Konnektor CETP"),
    ("/cetp-services/", "SecuNET Konnektor CETP"),
    ("/management", "Konnektor Management Web-UI"),
    ("/management/login", "Konnektor Management Login"),
    ("/kocobox/", "KoCoBox MED+ Web-UI"),
    ("/konnektor/", "Konnektor Web-UI"),
    ("/adminkonsole/", "Konnektor Admin Konsole"),
    ("/rise/", "RISE Konnektor"),
    ("/secunet/", "SecuNET Konnektor"),
    ("/cgm/", "CGM TI Portal"),
]

# --- 3. PVS fingerprint patterns ----------------------------------------

PVS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"turbomed", re.IGNORECASE), "TurboMed"),
    (re.compile(r"medistar", re.IGNORECASE), "MEDISTAR"),
    (re.compile(r"albis[\s-]?on[\s-]?windows", re.IGNORECASE), "ALBIS"),
    (re.compile(r"\balbis\b", re.IGNORECASE), "ALBIS"),
    (re.compile(r"x\.isynet|xisynet", re.IGNORECASE), "x.isynet"),
    (re.compile(r"\bduria\b", re.IGNORECASE), "duria"),
    (re.compile(r"\btomedo\b", re.IGNORECASE), "Tomedo"),
    (re.compile(r"medical\s+office", re.IGNORECASE), "Medical Office"),
    (re.compile(r"\bifap\s+praxiscenter\b", re.IGNORECASE), "ifap praxisCENTER"),
    (re.compile(r"compugroup\s+medical|\bcgm[\s-]", re.IGNORECASE), "CompuGroup Medical"),
    (re.compile(r"\bt2med\b", re.IGNORECASE), "T2med"),
    (re.compile(r"\bquincy\b.{0,20}(win|win\.net)", re.IGNORECASE), "QUINCY"),
    (re.compile(r"\bdampsoft\b", re.IGNORECASE), "Dampsoft"),
    (re.compile(r"doctolib\.de", re.IGNORECASE), "Doctolib Widget"),
    (re.compile(r"samedi\.de", re.IGNORECASE), "Samedi Widget"),
    (re.compile(r"jameda\.de", re.IGNORECASE), "Jameda Widget"),
    (re.compile(r"clickdoc\.de", re.IGNORECASE), "Clickdoc Widget"),
    (re.compile(r"redmedical\.de|red\s*connect", re.IGNORECASE), "RED connect"),
    (re.compile(r"sprechstunde\.online", re.IGNORECASE), "sprechstunde.online"),
    (re.compile(r"arztkonsultation\.de", re.IGNORECASE), "arztkonsultation.de"),
    (re.compile(r"cgm\s*elvi", re.IGNORECASE), "CGM ELVI"),
    (re.compile(r"doctena", re.IGNORECASE), "Doctena"),
    (re.compile(r"eterno\s*health", re.IGNORECASE), "Eterno"),
]

# --- 4. Healthcare-sensitive paths --------------------------------------

SENSITIVE_HEALTH_PATHS: list[tuple[str, Severity, str]] = [
    ("/patienten", Severity.INFO, "Patientenbereich"),
    ("/patientenbereich", Severity.INFO, "Patientenbereich"),
    ("/meinbereich", Severity.INFO, "Patientenbereich"),
    ("/befunde", Severity.MEDIUM, "Befund-Download-Bereich"),
    ("/befund", Severity.MEDIUM, "Befund-Download-Bereich"),
    ("/downloads/befunde", Severity.MEDIUM, "Befund-Downloads"),
    ("/rezept", Severity.MEDIUM, "Rezept-Bereich"),
    ("/erezept", Severity.MEDIUM, "eRezept-Bereich"),
    ("/rezepte", Severity.MEDIUM, "Rezept-Bereich"),
    ("/portal", Severity.INFO, "Portal"),
    ("/login", Severity.INFO, "Login-Seite"),
    ("/api/patients", Severity.CRITICAL, "Patienten-API"),
    ("/api/patient", Severity.CRITICAL, "Patienten-API"),
    ("/api/appointments", Severity.HIGH, "Termine-API"),
    ("/api/medical", Severity.CRITICAL, "Medizin-API"),
    ("/api/v1/patients", Severity.CRITICAL, "Patienten-API v1"),
    ("/webcoll", Severity.MEDIUM, "webCOLL Portal"),
]


def _resolve(name: str, rtype: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    resolver.timeout = 3.0
    try:
        answers = resolver.resolve(name, rtype, raise_on_no_answer=False)
        return [r.to_text() for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def _check_kim(domain: str, result: ScanResult) -> None:
    kim_found: dict[str, list[str]] = {}
    for rtype, tmpl in KIM_DNS_CHECKS:
        name = tmpl.format(domain=domain)
        records = _resolve(name, rtype)
        if records:
            kim_found[name] = records

    if kim_found:
        result.metadata["kim"] = kim_found
        result.add(Finding(
            id="healthcare.kim_detected",
            title="KIM-Infrastruktur erkannt",
            description=(
                "Es wurden DNS-Einträge gefunden, die auf eine aktive KIM-"
                "(Kommunikation im Medizinwesen)-Anbindung hinweisen. "
                "Das ist ein positives Signal — stellt aber gleichzeitig sicher, "
                "dass die KIM-S/MIME-Zertifikate gültig und nicht zurückgerufen sind."
            ),
            severity=Severity.INFO,
            category="Healthcare",
            evidence=kim_found,
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 4 (Medizinprodukte/TI)",
        ))


def _probe_connector_paths(domain: str, result: ScanResult, baselines: set[str]) -> None:
    found: list[dict] = []

    # Content hints — the real connector UIs contain product-specific strings.
    # Without a hint we fall back to "must not be a catch-all and must not look
    # like the generic homepage body".
    HINTS: dict[str, str] = {
        "/cetp/services/": "cetp",
        "/cetp-services/": "cetp",
        "/kocobox/": "kocobox",
        "/secunet/": "secunet",
        "/rise/": "rise",
        "/cgm/": "cgm",
    }

    def task(entry: tuple[str, str]) -> dict | None:
        path, label = entry
        try:
            with httpx.Client(
                timeout=4.0,
                follow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                r = client.get(f"https://{domain}{path}")
                if r.status_code not in (200, 401, 403):
                    return None
                body = r.text[:4096] if "text" in r.headers.get("content-type", "").lower() else ""

                # 401/403 responses are interesting even without body match — they still indicate the app exists.
                if r.status_code in (401, 403):
                    return {
                        "path": path,
                        "status": r.status_code,
                        "label": label,
                        "server": r.headers.get("server", ""),
                    }

                # 200 case: reject SPA catch-all.
                if is_catchall(body, baselines):
                    return None

                # If we have a content hint, require it in the body.
                hint = HINTS.get(path)
                if hint and hint not in body.lower():
                    return None

                return {
                    "path": path,
                    "status": r.status_code,
                    "label": label,
                    "server": r.headers.get("server", ""),
                }
        except httpx.HTTPError:
            return None

    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = [ex.submit(task, e) for e in TI_CONNECTOR_PATHS]
        for f in as_completed(futures):
            hit = f.result()
            if hit:
                found.append(hit)

    if found:
        result.metadata["ti_connector_hits"] = found
        for hit in found:
            result.add(Finding(
                id=f"healthcare.connector.{hit['path'].strip('/').replace('/', '_')}",
                title=f"TI-Konnektor-Pfad öffentlich erreichbar: {hit['label']}",
                description=(
                    f"Der Pfad {hit['path']} antwortet mit HTTP {hit['status']}. "
                    "TI-Konnektor-Web-UIs gehören ausschließlich ins interne Netz "
                    "und dürfen niemals aus dem Internet erreichbar sein — das ist "
                    "ein direkter Angriffspunkt auf die Telematikinfrastruktur."
                ),
                severity=Severity.CRITICAL,
                category="Healthcare / TI",
                evidence=hit,
                recommendation=(
                    "Konnektor-Web-UI sofort per Firewall/VPN abschotten. "
                    "Gematik-konforme Trennung Praxis-LAN ↔ Internet herstellen."
                ),
                kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 4 & 5 (TI-Komponenten)",
            ))


def _check_pvs_fingerprint(domain: str, result: ScanResult) -> None:
    # Reuse HTML already pulled by the HTTP check if available.
    html_text = ""
    try:
        with httpx.Client(
            timeout=8.0,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        ) as client:
            r = client.get(f"https://{domain}")
            if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
                html_text = r.text[:500_000]
                # Also try /impressum and /kontakt — widgets often live there.
                for path in ("/impressum", "/kontakt", "/termine"):
                    try:
                        r2 = client.get(f"https://{domain}{path}")
                        if r2.status_code == 200 and "text/html" in r2.headers.get("content-type", ""):
                            html_text += "\n" + r2.text[:200_000]
                    except httpx.HTTPError:
                        continue
    except httpx.HTTPError:
        return

    if not html_text:
        return

    detected: list[str] = []
    for pattern, name in PVS_PATTERNS:
        if pattern.search(html_text):
            detected.append(name)

    if detected:
        result.metadata["pvs_stack"] = sorted(set(detected))
        result.add(Finding(
            id="healthcare.pvs_detected",
            title=f"Medizin-Software erkannt: {', '.join(sorted(set(detected)))}",
            description=(
                "Im HTML der Website wurden Hinweise auf folgende Medizin-/"
                "Praxis-Software gefunden. Das ist weder gut noch schlecht — "
                "es ist aber ein Angriffsvektor, weil Angreifer die passenden "
                "Exploits gezielt für diese Produkte suchen können."
            ),
            severity=Severity.INFO,
            category="Healthcare",
            evidence={"detected": sorted(set(detected))},
            recommendation=(
                "Prüfen welche Software tatsächlich eingesetzt wird und ob sie "
                "über die aktuellsten Sicherheits-Updates verfügt. Embedded "
                "Widgets (Doctolib, Samedi) laden Scripts von Dritten und "
                "erfordern einen Consent-Banner."
            ),
        ))


def _probe_health_paths(domain: str, result: ScanResult, baselines: set[str]) -> None:
    found_paths: list[dict] = []

    def task(entry: tuple[str, Severity, str]) -> dict | None:
        path, sev, label = entry
        try:
            with httpx.Client(
                timeout=4.0,
                follow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                r = client.get(f"https://{domain}{path}")
                if r.status_code != 200:
                    return None
                body = r.text[:4096] if "text" in r.headers.get("content-type", "").lower() else ""
                if is_catchall(body, baselines):
                    return None
                return {"path": path, "status": r.status_code, "sev": sev.value, "label": label, "content_type": r.headers.get("content-type", "")}
        except httpx.HTTPError:
            return None

    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = [ex.submit(task, e) for e in SENSITIVE_HEALTH_PATHS]
        for f in as_completed(futures):
            hit = f.result()
            if hit:
                found_paths.append(hit)

    if found_paths:
        result.metadata["health_paths"] = found_paths
        # Separate API vs. normal path severity: API hits are always emitted, path hits only as INFO grouped.
        api_hits = [p for p in found_paths if p["path"].startswith("/api/")]
        if api_hits:
            for hit in api_hits:
                result.add(Finding(
                    id=f"healthcare.api_exposed.{hit['path'].strip('/').replace('/', '_')}",
                    title=f"{hit['label']} öffentlich erreichbar: {hit['path']}",
                    description=(
                        f"Der API-Endpunkt {hit['path']} antwortet mit HTTP 200 ohne Authentifizierung. "
                        "APIs für Patienten-/Medizin-Daten dürfen niemals unauthentisiert "
                        "erreichbar sein."
                    ),
                    severity=Severity.CRITICAL,
                    category="Healthcare / API",
                    evidence=hit,
                    recommendation="Endpoint hinter Authentifizierung/VPN stellen oder entfernen.",
                    kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 3 (Zugriffskontrolle)",
                ))


def check_healthcare(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Healthcare (KIM/TI/PVS)", 46)
    baselines = fetch_baselines(domain)
    _check_kim(domain, result)
    _probe_connector_paths(domain, result, baselines)
    _check_pvs_fingerprint(domain, result)
    _probe_health_paths(domain, result, baselines)
