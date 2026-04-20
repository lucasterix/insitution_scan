"""Offer builder: turn a finished scan into an honest cost estimate.

For every finding we estimate the hours a competent engineer needs to
remediate the issue (including testing). Totals are multiplied by an
hourly rate and grouped by severity for readability.

The numbers are opinionated but deliberately conservative — we'd rather
quote a bit high and come in under than sandbag the customer.

Finding-id lookup rules:
  1. exact match in EFFORT_HOURS.
  2. prefix match (keys ending in ".*").
  3. fallback per severity from SEVERITY_DEFAULT_HOURS.

Unknown severities get 0h (we surface nothing invented).
"""
from __future__ import annotations

from typing import Iterable

# Default rate for an independent IT-security consultant in Germany (net).
# Can be overridden per institution via scan.context["hourly_rate_eur"].
DEFAULT_HOURLY_RATE_EUR = 150.0
VAT_RATE = 0.19  # Standard MWSt.

# Severity-based fallback when no specific match fires.
SEVERITY_DEFAULT_HOURS = {
    "critical": 2.0,
    "high": 1.0,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.0,
}

# Known finding-ids → hours. Keys ending with ".*" are prefix-matches.
EFFORT_HOURS: dict[str, float] = {
    # ─── CRITICAL: direct system access / data exfil ────────────────────────
    "creds.default.*":              0.5,   # change password + document
    "access.redis_no_auth":         1.0,   # set requirepass + firewall + rotate keys if needed
    "access.mongodb_no_auth":       1.5,   # enable auth + create admin user + rebind
    "access.elasticsearch_no_auth": 2.0,   # enable X-Pack security + user setup
    "access.ftp_anonymous":         0.5,   # disable anonymous + FTP → SFTP migration
    "access.ssh_no_auth.*":         0.5,
    "access.memcached_no_auth":     0.5,   # firewall-only; no auth protocol
    "access.smtp_open_relay":       1.0,
    "exposed.git_head":             2.0,   # block + audit committed secrets + rotate
    "exposed.git_config":           2.0,
    "exposed.env":                  3.0,   # remove + rotate ALL env secrets
    "exposed.env_bak":              3.0,
    "exposed.env_local":            3.0,
    "exposed.env_production":       3.0,
    "exposed.wp_config_bak":        3.0,
    "exposed.wp_config_old":        3.0,
    "exposed.config_php_bak":       3.0,
    "exposed.backup_sql":           6.0,   # analyze dump + notify users + rotate credentials
    "exposed.sql_dump":             6.0,
    "exposed.db_sqlite":            4.0,
    "cookie.jwt_alg_none.*":        4.0,   # server-side alg allowlist + tests
    "healthcare.connector.*":      16.0,   # network segmentation project
    "healthcare.api_exposed.*":     8.0,   # auth wrapper + callers
    "step2.api_unauth_sensitive":   8.0,
    "step2.subdomain_takeover.*":   0.5,   # DNS cleanup
    "step2.spf_takeover":           0.5,
    "idor.*":                       8.0,   # authz refactor
    "api.delete_accepted":          4.0,
    "api.write_accepted":           3.0,
    "deep.js_secret.*":             3.0,   # rotate credential + remove from bundle
    "vuln.*":                       3.0,   # typical patching + regression test
    "nuclei.*":                     3.0,
    "email.spf_too_permissive":     0.25,

    # ─── HIGH: brute-force / limited-effort compromise ─────────────────────
    "email.spf_missing":            0.5,
    "email.dmarc_missing":          0.5,
    "vpn.no_auth.*":                1.0,
    "vpn.endpoint.*":               2.0,   # patch + access restriction
    "remote.web.*":                 2.0,
    "remote.mgmt.*":                2.0,
    "wp.plugin.*.outdated":         1.0,
    "tls.expired":                  1.0,
    "http.tls_cert_invalid":        1.0,
    "tls.legacy_protocol":          0.5,   # disable old TLS in nginx/apache
    "access.mysql_exposed":         2.0,
    "access.postgres_exposed":      2.0,
    "server.ssh_protocol_v1":       1.0,
    "firewall.rate_limit_missing":  1.0,
    "eol.software.*":               8.0,   # OS/major upgrade
    "shodan.port.*":                1.0,   # firewall rule
    "subdomain.tls_expired.*":      1.0,

    # ─── MEDIUM: chain attacks, compliance pain ─────────────────────────────
    "email.dkim_missing":           1.0,
    "email.dmarc_policy_none":      0.25,
    "privacy.tracker.*":            1.0,   # remove or add consent-mgmt integration
    "privacy.impressum_missing":    2.0,
    "privacy.impressum_incomplete": 0.5,
    "privacy.cookie_flags_missing": 0.5,
    "auth.csrf_token_missing":      2.0,
    "auth.mfa_not_detected":        4.0,   # TOTP integration
    "wp.xmlrpc_enabled":            0.25,
    "wp.user_enum_wp_json":         0.5,
    "wp.author_enum":               0.25,
    "deep.open_redirect":           1.0,
    "deep.host_header_injection":   2.0,
    "deep.mixed_content_active":    1.0,
    "deep.cors_misconfigured":      2.0,
    "firewall.no_payload_blocked":  4.0,   # Cloudflare Managed Rules + tuning
    "firewall.waf_permissive":      2.0,
    "tls.weak_cipher":              0.5,
    "tls.compression_enabled":      0.25,
    "cookie.jwt_long_lived.*":      4.0,   # short-lived access + refresh flow

    # ─── LOW / INFO: defense-in-depth, info disclosure ─────────────────────
    "http.header.*":                0.1,   # one nginx line each
    "http.no_https_redirect":       0.25,
    "dns.caa_missing":              0.25,
    "email.mta_sts_missing":        1.0,
    "email.mta_sts_policy_missing": 0.5,
    "email.tls_rpt_missing":        0.25,
    "exposed.security_txt_missing": 0.25,
    "tech.server_version_disclosed": 0.1,
    "tech.generator_disclosed":     0.1,
    "tech.jquery_outdated":         0.5,
    "tech.bootstrap_outdated":      0.5,
    "tls.no_forward_secrecy":       0.25,
    "tls.low_bit_cipher":           0.5,
    "osint.robots_reveals_admin":   0.25,
    "image.exif_gps_leaked":        0.5,
    "image.exif_personal_leaked":   0.25,
    "pdf.author_leaked":            0.5,
    "cookie.weak_session.*":        1.0,
    "cookie.jwt_claims_readable.*": 0.5,
    "cookie.jwt_expired.*":         0.25,
    "subdomain.headers.*":          0.25,
}


def _hours_for_finding(finding_id: str, severity: str) -> float:
    """Return estimated hours for a finding, applying exact → prefix → severity fallback."""
    if finding_id in EFFORT_HOURS:
        return EFFORT_HOURS[finding_id]
    # Prefix match for "name.*" entries.
    for key, val in EFFORT_HOURS.items():
        if key.endswith(".*") and finding_id.startswith(key[:-1]):
            return val
    return SEVERITY_DEFAULT_HOURS.get((severity or "").lower(), 0.0)


# Findings that describe *synthesis* or *reputation* rather than a distinct
# piece of remediation work — they get fully covered by other line items.
# Dropped from the offer so we don't double-bill.
DROP_FROM_OFFER_PREFIXES: tuple[str, ...] = (
    "deep.exploit_chain.",    # narrates chains of already-priced issues
    "abuseipdb.",             # reputation signal, no fix work
    "otx.",                   # threat-intel signal, no fix work
    "server.shared_hosting.", # observation, not a finding to fix
    "banner.version.",        # covered by the related CVE/EOL line
    "tech.server_version_disclosed",  # subsumed by HSTS/header hygiene
    "tech.generator_disclosed",
    "dns.brute_force_new_subs",  # info discovery, not a fix
)

# Firewall findings that describe the same root cause. If any of these co-fires
# with a higher-priority peer, the lower-priority ones are dropped from the
# offer (kept in the report; just not billed twice).
FIREWALL_SIBLINGS: dict[str, tuple[str, ...]] = {
    # key = keep-this-if-present ; value = drop-these-if-key-present
    "firewall.no_payload_blocked":  ("firewall.no_waf_detected",),
    "firewall.waf_permissive":      ("firewall.no_waf_detected",),
    "firewall.partial_block":       ("firewall.no_waf_detected",),
}


def _bundle_cve_findings(raw_items: list[dict], findings: list[dict]) -> list[dict]:
    """Collapse per-CVE lines into one 'patch component X (N CVE)' item per
    product. A real-world patch covers all CVEs of a product in one shot —
    billing each CVE separately inflates the quote and looks unserious.

    Returns the new item list (non-CVE items untouched, CVE items bundled).
    """
    # Build an index of component → list of finding-ids
    component_to_fids: dict[str, list[str]] = {}
    component_worst_sev: dict[str, str] = {}
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for f in findings:
        fid = f.get("id") or ""
        if not fid.startswith("vuln."):
            continue
        ev = f.get("evidence") or {}
        comp = (ev.get("component") or "").strip().lower()
        if not comp:
            continue
        component_to_fids.setdefault(comp, []).append(fid)
        cur = component_worst_sev.get(comp, "info")
        new = (f.get("severity") or "info").lower()
        if sev_rank.get(new, 9) < sev_rank.get(cur, 9):
            component_worst_sev[comp] = new

    # Components with 2+ CVEs benefit from bundling
    to_bundle: dict[str, list[str]] = {c: fids for c, fids in component_to_fids.items() if len(fids) >= 2}
    if not to_bundle:
        return raw_items

    bundled_fids: set[str] = {fid for fids in to_bundle.values() for fid in fids}
    kept = [it for it in raw_items if it["id"] not in bundled_fids]

    # One bundled line per component — hours = single patch job (3h for
    # web apps / 4h for OS-level components). We cap the total so many
    # CVEs don't multiply.
    for comp, fids in to_bundle.items():
        is_os = any(k in comp for k in ("openssh", "nginx", "apache", "postfix", "kernel", "bind"))
        bundled_hours = 4.0 if is_os else 3.0
        worst = component_worst_sev.get(comp, "high")
        kept.append({
            "id": f"bundle.vuln.{comp.replace(' ', '_')}",
            "title": f"{comp.capitalize()} patchen ({len(fids)} bekannte CVE{'s' if len(fids) > 1 else ''})",
            "severity": worst,
            "category": "Known CVE",
            "hours": bundled_hours,
            "net_eur": 0.0,  # recomputed below with the rate
            "_bundle_from": fids,
        })

    return kept


def _drop_sibling_duplicates(raw_items: list[dict]) -> list[dict]:
    """Apply FIREWALL_SIBLINGS + DROP_FROM_OFFER_PREFIXES rules to the items list."""
    present_ids = {it["id"] for it in raw_items}
    drop_ids: set[str] = set()
    for keep_id, drops in FIREWALL_SIBLINGS.items():
        if keep_id in present_ids:
            for d in drops:
                drop_ids.add(d)
    return [
        it for it in raw_items
        if it["id"] not in drop_ids
        and not any(it["id"].startswith(p) for p in DROP_FROM_OFFER_PREFIXES)
    ]


def build_offer(result: dict, hourly_rate_eur: float | None = None) -> dict:
    """Aggregate findings → hours → euro. Never raises on unknown shapes.

    Returns a dict suitable for Jinja rendering. When there's nothing to quote
    (empty findings or only INFO), the caller can still display a "keine
    Handlungsempfehlung notwendig" note using the returned totals.

    Bundling rules (so the quote reads like a serious remediation offer, not
    a bag of dedup'd vulnerabilities):
      · multiple CVEs on the same product → ONE "patch {product}" line
      · exploit-chain / reputation / version-banner items → dropped (work is
        covered by the underlying issues that already price)
      · redundant firewall findings → keep the most-specific, drop the
        generic 'no WAF' sibling
    """
    rate = float(hourly_rate_eur or DEFAULT_HOURLY_RATE_EUR)

    findings = list(result.get("findings") or [])
    items: list[dict] = []

    for f in findings:
        fid = f.get("id") or ""
        sev = (f.get("severity") or "info").lower()
        hours = _hours_for_finding(fid, sev)

        items.append({
            "id": fid,
            "title": f.get("title") or fid,
            "severity": sev,
            "category": f.get("category") or "",
            "hours": hours,
            "net_eur": round(hours * rate, 2),
        })

    # Apply bundling + drop rules.
    items = _bundle_cve_findings(items, findings)
    items = _drop_sibling_duplicates(items)
    # Recompute net for all items now that the list is final.
    for it in items:
        it["net_eur"] = round(it["hours"] * rate, 2)

    # Aggregate by severity after bundling — that's what the customer sees.
    by_severity: dict[str, dict] = {
        k: {"count": 0, "hours": 0.0, "net": 0.0}
        for k in ("critical", "high", "medium", "low", "info")
    }
    for it in items:
        sev = it["severity"]
        if sev in by_severity:
            by_severity[sev]["count"] += 1
            by_severity[sev]["hours"] = round(by_severity[sev]["hours"] + it["hours"], 2)
            by_severity[sev]["net"] = round(by_severity[sev]["net"] + it["net_eur"], 2)

    total_hours = round(sum(it["hours"] for it in items), 2)
    net = round(total_hours * rate, 2)
    vat = round(net * VAT_RATE, 2)
    gross = round(net + vat, 2)

    # Sort: highest severity + effort first (drives the conversation).
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items.sort(key=lambda x: (sev_order.get(x["severity"], 99), -x["hours"]))

    return {
        "hourly_rate_eur": rate,
        "vat_rate": VAT_RATE,
        "items": items,
        "by_severity": by_severity,
        "total_hours": total_hours,
        "net_eur": net,
        "vat_eur": vat,
        "gross_eur": gross,
        "has_action_items": total_hours > 0,
    }


def format_eur(value: float) -> str:
    """German EUR formatting: 1.234,56 €. Uses a non-breaking space so the
    amount + symbol never wraps across two lines in a narrow column."""
    s = f"{value:,.2f}"
    s = s.replace(",", "X").replace(".", ",").replace("X", ".")
    return f"{s}\u00a0€"
