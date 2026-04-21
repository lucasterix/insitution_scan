"""Delta-Refiner: after the initial recon phase, decide which of the heavy
scanner modules make sense for this specific target.

Input context that the refiner sees:
  - domain + is_ip
  - DNS records (A/MX/NS/TXT snippets)
  - HTTP server / powered-by headers
  - whether Google Workspace is in use (MX hints)
  - whether the homepage html looks like WordPress / Joomla / Drupal
  - whether a KBV/healthcare context was flagged (KIM DNS, PVS strings)

Output: a dict `{skip: [module_name, ...]}`. The refiner is ALLOWED ONLY to
skip modules from a whitelisted "expensive_optional" set — it can never
skip core checks (DNS, TLS, HTTP, exposed_files, privacy, …). That's the
safety rail against over-aggressive refinement.

Inspired by pentagi's refiner.tmpl but far simpler: one LLM call, delta ops
only, no iterative planner-loop.
"""
from __future__ import annotations

import json
import logging
import re

from app import llm

log = logging.getLogger("refiner")

# Modules the refiner is allowed to skip. Everything else is mandatory.
# Chosen to be modules that:
#   - have real runtime cost (external APIs, port-scans, heavy HTML parsing)
#   - produce findings only on specific target profiles
OPTIONAL_MODULES: set[str] = {
    "check_healthcare",         # KIM/TI/PVS — only relevant for actual MVZ/Praxen
    "check_vpn_endpoints",      # VPN gateway probes — irrelevant for static sites
    "harvest_and_check",        # HIBP/LeakCheck calls — skip when no emails harvestable
    "check_image_metadata",     # EXIF — only if the site has images
    "check_pdf_metadata",       # PDF EXIF — only if wayback/crawl found PDFs
    "check_remote_access",      # RDP/Guac/ScreenConnect probes
    "check_cms",                # WP/Drupal — skip if generator header is clearly not CMS
    "check_cookie_forensics",   # JWT forensics — skip if no cookies set
    "check_form_security",      # login-form analysis — skip if no forms found
    "brute_subdomains",         # 200-word subdomain brute — skip if CT log already rich
    "check_banners",            # TCP banner-grab — skip if port-scan found nothing
    "check_nmap",               # nmap -sV — skip if no open TCP ports beyond 80/443
}


REFINER_SYSTEM = (
    "Du bist der Delta-Refiner einer Scan-Pipeline für IT-Sicherheitsprüfungen. "
    "Du bekommst Recon-Daten einer Domain (DNS, HTTP-Header, Homepage-Fingerprint) und "
    "entscheidest welche OPTIONALEN Scanner-Module sich für dieses konkrete Ziel LOHNEN "
    "und welche übersprungen werden können.\n\n"
    "REGELN:\n"
    "1. Du darfst NUR Module aus der gelieferten `optional_modules`-Liste skippen. Andere "
    "nicht erwähnen.\n"
    "2. Skippe konservativ — im Zweifel laufen lassen. Skippe nur wenn du einen KLAREN "
    "Grund im Recon-Kontext hast.\n"
    "3. Beispiele: static HTML ohne Logins → skip check_form_security; keine offenen "
    "Ports außer 80/443 → skip check_banners + check_nmap; keine Bilder in der Homepage → "
    "skip check_image_metadata; keine MVZ/Praxis-Signale → skip check_healthcare.\n"
    "4. Output: striktes JSON, kein Kommentar, keine Fences:\n"
    '{"skip": ["module_name", ...], "reasons": {"module_name": "ein-satz begründung", ...}}\n'
    "Falls nichts skippbar: `{\"skip\": [], \"reasons\": {}}`."
)


def refine(recon_context: dict, *, scan_id: str | None = None) -> set[str]:
    """Return the set of module names to SKIP. Never raises; empty set on any failure."""
    if not llm.is_enabled():
        return set()

    user = json.dumps({
        "domain": recon_context.get("domain"),
        "is_ip": recon_context.get("is_ip", False),
        "dns": recon_context.get("dns") or {},
        "http_server": recon_context.get("http_server"),
        "http_powered_by": recon_context.get("http_powered_by"),
        "homepage_indicators": recon_context.get("homepage_indicators") or {},
        "optional_modules": sorted(OPTIONAL_MODULES),
    }, ensure_ascii=False, indent=2)

    try:
        text = llm.draft(REFINER_SYSTEM, user, max_tokens=400, temperature=0.1, scan_id=scan_id)
    except llm.BudgetExceeded:
        return set()
    except Exception as e:  # noqa: BLE001
        log.warning("Refiner call failed: %s", e)
        return set()

    # Strip code-fences the model sometimes adds despite the prompt.
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.MULTILINE)
    try:
        decision = json.loads(cleaned)
    except json.JSONDecodeError:
        log.warning("Refiner returned non-JSON, ignoring. Raw: %s", text[:200])
        return set()

    skip = set(decision.get("skip") or [])
    # Hard gate: only allow skipping whitelisted optional modules.
    allowed = skip & OPTIONAL_MODULES
    dropped = skip - OPTIONAL_MODULES
    if dropped:
        log.info("Refiner tried to skip non-optional modules (ignored): %s", dropped)
    if allowed:
        log.info("Refiner decided to skip: %s — reasons: %s",
                 sorted(allowed), decision.get("reasons") or {})
    return allowed


def collect_recon_context(domain: str, result_metadata: dict, is_ip: bool) -> dict:
    """Package the recon signals the refiner needs from result.metadata."""
    dns = result_metadata.get("dns") or {}
    http_info = (result_metadata.get("http") or {}).get("https") or {}
    headers = http_info.get("headers") or {}

    homepage_html = (result_metadata.get("homepage_html") or "").lower()
    indicators = {
        "looks_wordpress": "wp-content/" in homepage_html or "/wp-includes/" in homepage_html or "wp-json" in homepage_html,
        "looks_drupal": "sites/default/" in homepage_html or "drupal-settings" in homepage_html,
        "looks_joomla": "/media/jui/" in homepage_html or "joomla" in homepage_html,
        "has_login_form": '<input type="password"' in homepage_html or "type='password'" in homepage_html,
        "has_images": "<img " in homepage_html,
        "google_workspace_mx": any("google.com" in (str(mx) or "") for mx in (dns.get("MX") or [])),
        "mvz_keywords": any(kw in homepage_html for kw in ("mvz", "medizinisches versorgungszentrum", "praxis", "arzt", "termin buchen")),
    }
    return {
        "domain": domain,
        "is_ip": is_ip,
        "dns": {
            "A": (dns.get("A") or [])[:2],
            "MX": [str(mx)[:80] for mx in (dns.get("MX") or [])[:3]],
            "NS": [str(ns)[:80] for ns in (dns.get("NS") or [])[:3]],
        },
        "http_server": headers.get("server"),
        "http_powered_by": headers.get("x-powered-by"),
        "homepage_indicators": indicators,
    }
