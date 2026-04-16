"""Nuclei vulnerability scanner integration.

Runs projectdiscovery/nuclei with curated template tags against the target.
This is the bridge between our custom detection (step 1) and active exploit
verification: nuclei sends actual payloads to confirm exploitability.

Focus areas (via -tags):
  wordpress   — WP plugin/theme CVE PoCs, xmlrpc abuse, user-enum
  cve         — all CVE templates (filtered to medium+ severity)
  default-login — default credentials for admin panels, databases, CMS
  misconfig   — misconfiguration templates (CORS, SSRF, path traversal)
  exposure    — exposed admin panels, debug endpoints, config files

Runs with:
  - 180s hard timeout (subprocess)
  - 50 req/s rate limit
  - 10 max concurrency
  - medium/high/critical severity filter (skip info/low noise)
  - JSON-lines output → parsed into our Finding system
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Callable

from app.scanners.base import Finding, ScanResult, Severity

NUCLEI_TIMEOUT = 180
NUCLEI_TAGS = "wordpress,cve,default-login,misconfig,exposure"
NUCLEI_SEVERITY = "critical,high,medium"
NUCLEI_RATE_LIMIT = "50"
NUCLEI_CONCURRENCY = "10"

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _nuclei_available() -> bool:
    try:
        r = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            timeout=10,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_nuclei(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    """Run nuclei against the target domain and parse JSON results."""
    if not _nuclei_available():
        result.metadata.setdefault("nuclei", {})["available"] = False
        return

    step("Nuclei Vulnerability Scan", 76)

    cmd = [
        "nuclei",
        "-u", f"https://{domain}",
        "-tags", NUCLEI_TAGS,
        "-severity", NUCLEI_SEVERITY,
        "-jsonl",
        "-silent",
        "-timeout", "5",
        "-retries", "1",
        "-max-host-error", "15",
        "-rl", NUCLEI_RATE_LIMIT,
        "-c", NUCLEI_CONCURRENCY,
        "-no-update-templates",
        "-disable-update-check",
        "-no-color",
    ]

    env = dict(os.environ)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=NUCLEI_TIMEOUT,
            text=True,
            env=env,
        )
    except subprocess.TimeoutExpired:
        result.metadata.setdefault("nuclei", {})["timeout"] = True
        result.add(Finding(
            id="nuclei.timeout",
            title="Nuclei-Scan nach 180s abgebrochen",
            description="Der nuclei-Scan hat das Zeitlimit überschritten. Teilresultate können fehlen.",
            severity=Severity.INFO,
            category="Nuclei Scan",
        ))
        return
    except FileNotFoundError:
        return

    raw_findings: list[dict] = []
    for line in (proc.stdout or "").strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            raw_findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    result.metadata["nuclei"] = {
        "available": True,
        "templates_matched": len(raw_findings),
        "returncode": proc.returncode,
    }

    if not raw_findings:
        return

    seen_templates: set[str] = set()

    for entry in raw_findings:
        template_id = entry.get("template-id") or entry.get("templateID") or "unknown"
        if template_id in seen_templates:
            continue
        seen_templates.add(template_id)

        info = entry.get("info") or {}
        name = info.get("name") or template_id
        severity_str = (info.get("severity") or "info").lower()
        severity = SEVERITY_MAP.get(severity_str, Severity.INFO)
        description = info.get("description") or ""
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]

        matched_at = entry.get("matched-at") or entry.get("matched") or ""
        matcher_name = entry.get("matcher-name") or ""
        curl_command = entry.get("curl-command") or ""
        extracted = entry.get("extracted-results") or []

        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        # Extract CVE ID if present
        cve_id = ""
        tid_upper = template_id.upper()
        if tid_upper.startswith("CVE-"):
            cve_id = tid_upper
        else:
            for tag in tags:
                if tag.upper().startswith("CVE-"):
                    cve_id = tag.upper()
                    break

        evidence: dict = {
            "template": template_id,
            "matched_at": matched_at,
            "tags": tags,
        }
        if matcher_name:
            evidence["matcher"] = matcher_name
        if curl_command:
            evidence["curl"] = curl_command[:500]
        if extracted:
            evidence["extracted"] = extracted[:5]
        if references:
            evidence["references"] = references[:5]

        title = f"Nuclei: {name}"
        if cve_id:
            title += f" ({cve_id})"

        desc_parts = []
        if description:
            desc_parts.append(description)
        if matched_at:
            desc_parts.append(f"Match: {matched_at}")
        if cve_id:
            desc_parts.append(f"CVE: {cve_id}")
        desc_parts.append(
            "Dieser Befund wurde durch ein nuclei-Template aktiv verifiziert — "
            "die Schwachstelle ist nicht nur theoretisch (aus der Versionsnummer), "
            "sondern der Exploit-Pfad ist tatsächlich erreichbar."
        )

        result.add(Finding(
            id=f"nuclei.{template_id}",
            title=title,
            description="\n\n".join(desc_parts),
            severity=severity,
            category="Nuclei Scan",
            evidence=evidence,
            recommendation=(
                "Die von nuclei bestätigte Schwachstelle ist aktiv exploitierbar. "
                "Sofortige Behebung empfohlen — Details in den Template-Referenzen."
                + (f"\n\nReferenzen: {', '.join(references[:3])}" if references else "")
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (Patch-Management)",
        ))
