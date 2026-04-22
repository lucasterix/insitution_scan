"""Post-scan Claude review — auto-audit every completed scan for FPs.

Runs once after `run_scan_job` flips a scan to completed. Sends the
scan's finding list + metadata snippet to Claude with an auditor
prompt, parses the JSON verdict, and stores it on the Scan row.

If the verdict is 'issues', the Auto-Offer queue hook declines to
schedule the offer mail until a human has reviewed and unlocked the
scan. The customer never gets a mail based on noisy findings.

Budget-aware: uses the same `app.llm.draft()` wrapper as the report
agents, so the per-scan token cap applies.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("scan_review")


AUDITOR_SYSTEM = """Du bist ein unabhängiger Security-Auditor, der IT-
Sicherheits-Scans eines deutschen MVZ-/Praxis-Scanners gegenliest, bevor
sie an Kunden (Ärzt:innen, MVZ, Zahnärzt:innen, Physiotherapeut:innen)
versendet werden. Deine Aufgabe: False Positives, Inkonsistenzen und
alarmistische Wordings finden, die das Unternehmen (ZDKG / Advanced
Analytics GmbH) blamieren würden.

ERKENNE INSBESONDERE:
1. Shared-Hosting-Leak: Findings mit IPs/PTRs bei bekannten Hostern
   (KAS, IONOS, Strato, Host Europe, de-nserver, alfahosting, goserver,
   wixsite, one.com, squarespace, secureserver/GoDaddy, Netcup,
   DomainFactory, Mittwald, elastic-ssl.ui-r.com, dt-internet.de,
   Hostinger, Netlify, Vercel, Kinsta, wpengine, raidboxes,
   clients.your-server.de = Hetzner-shared). Die OS-Ports (SSH, MySQL,
   FTP, SMB) auf diesen IPs gehören NICHT dem Kunden.

2. SPA/Static-Site-FPs: Next.js, Squarespace, Wix, Wordpress-Themes
   antworten oft mit HTTP 200 + text/html auf jeden Pfad oder HTTP
   403 auf alles Unbekannte (WAF-Blanket). Findings wie "phpMyAdmin/
   Jenkins/Grafana/VPN-Portal existiert" sind dann Artefakte, keine
   echten Exponierungen.

3. Unplausible Befundkombinationen: ein Physio hat keine 7 konkurrie-
   renden TI-Konnektoren (KoCoBox + SecuNET + RISE + CGM + …). Ein
   Zahnarzt hat nicht AWS + Kubernetes + Grafana + Jenkins zeitgleich.

4. Fabrizierte/halluzinierte CVEs: CVE-IDs aus der Zukunft oder mit
   einem EPSS-Score <0.01 auf einem angeblich "CRITICAL" Befund sind
   verdächtig. Echte kritische CVEs haben in der Regel EPSS >0.05.

5. Impressum-Extraktion-Garbage: Managername leer / "- -" / enthält
   Punktuation; E-Mail-Adressen mit führendem Punkt ("info@.xxx");
   Ärztekammer-Boilerplate-Adressen wie "info@aekn.de" / "info@kvn.de"
   die nicht zum Kunden gehören; Straßen die an einer anderen Stadt
   liegen als Postleitzahl.

6. Open-Redirect-FPs: www→www oder http→https canonical 301 ist KEIN
   offener Redirect.

7. Widerspruchs-Findings: "SSL Labs Grade A" + "TLS connect failed"
   gleichzeitig, oder "KIM korrekt konfiguriert" + "KIM fehlt"
   gleichzeitig.

ANTWORTFORMAT (strikt JSON, nichts anderes):
{
  "verdict": "clean" | "issues",
  "summary": "max. 2 Sätze, warum clean oder welche Muster problematisch",
  "flagged_findings": ["finding_id1", "finding_id2", ...]
}

Nutze "clean" wenn alle Befunde plausibel sind. Nutze "issues" bei
jedem klaren FP, Inkonsistenz oder halluzinierten CVE. Flagge jede
id die du für problematisch hältst. Kein Plausibilitäts-Zweifel →
"issues". Die Kosten eines False-Positive-Versandes an einen Kunden
sind höher als der Aufwand einer Menschen-Nachprüfung."""


def _compress_scan_for_review(scan: Any) -> str:
    """Turn a completed Scan into a compact review payload (<= ~3k tokens)."""
    result = scan.result or {}
    findings = result.get("findings") or []
    meta = result.get("metadata") or {}

    # Pull minimally-sufficient context: top 40 findings sorted by severity,
    # plus key metadata buckets (dns, server_analysis, impressum, tech).
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings, key=lambda f: sev_rank.get(f.get("severity", "info"), 5)
    )[:40]
    trimmed = []
    for f in sorted_findings:
        trimmed.append({
            "id": f.get("id"),
            "severity": f.get("severity"),
            "title": (f.get("title") or "")[:180],
            "evidence": (f.get("evidence") or {}) if isinstance(f.get("evidence"), dict) else {},
        })

    context = {
        "domain": scan.target_domain,
        "institution": scan.institution_name,
        "deep_scan": scan.deep_scan,
        "finding_count_total": len(findings),
        "finding_count_by_severity": {
            sev: sum(1 for f in findings if f.get("severity") == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        },
        "dns_A": (meta.get("dns") or {}).get("A"),
        "server_analysis": {
            "ptr": (meta.get("server_analysis") or {}).get("ptr"),
            "shared_hosting": (meta.get("server_analysis") or {}).get("shared_hosting"),
        },
        "shared_hosting_detected": meta.get("shared_hosting_detected"),
        "impressum": meta.get("impressum") or {},
        "tech_versions": meta.get("tech") or {},
        "mail_provider": meta.get("mail_provider") or [],
        "findings_top40": trimmed,
    }
    return json.dumps(context, ensure_ascii=False, default=str)


def _parse_verdict(text: str) -> tuple[str, str, list[str]]:
    """Extract (verdict, summary, flagged_ids) from the LLM's JSON reply."""
    if not text:
        return "error", "LLM lieferte leere Antwort", []
    # Strip any ```json fences
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t.startswith("json"):
            t = t[4:]
        t = t.strip()
    # Find the first { and last }
    start = t.find("{")
    end = t.rfind("}")
    if start < 0 or end <= start:
        return "error", f"LLM-Antwort ohne JSON: {text[:200]}", []
    try:
        obj = json.loads(t[start:end + 1])
    except json.JSONDecodeError as e:
        return "error", f"JSON parse error: {e}", []
    v = obj.get("verdict")
    if v not in ("clean", "issues"):
        v = "error"
    summary = str(obj.get("summary") or "")[:2000]
    flagged = obj.get("flagged_findings") or []
    if not isinstance(flagged, list):
        flagged = []
    flagged_ids = [str(x)[:200] for x in flagged if x][:50]
    return v, summary, flagged_ids


def review_scan_sync(scan_id: str) -> None:
    """Run the review synchronously (called from the RQ worker post-scan).

    On LLM error we record verdict='error' + the message on the scan so
    the UI can surface it without blocking the queue.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app import llm
    from app.config import get_settings
    from app.models import Scan

    if not llm.is_enabled():
        log.info("scan_review: LLM disabled, skipping %s", scan_id)
        return

    settings = get_settings()
    sync_url = settings.database_url.replace("+asyncpg", "+psycopg") if "+asyncpg" in settings.database_url else settings.database_url
    engine = create_engine(sync_url, pool_pre_ping=True)
    with Session(engine) as s:
        scan = s.get(Scan, scan_id)
        if not scan or scan.status != "completed" or not scan.result:
            return
        payload = _compress_scan_for_review(scan)
        try:
            reply = llm.draft(
                AUDITOR_SYSTEM,
                payload,
                max_tokens=700,
                temperature=0.1,
                scan_id=scan_id,
            )
        except llm.BudgetExceeded as e:
            scan.review_verdict = "error"
            scan.review_summary = f"LLM-Budget erschöpft: {e}"
            scan.reviewed_at = datetime.now(timezone.utc)
            s.commit()
            return
        except Exception as e:  # noqa: BLE001
            scan.review_verdict = "error"
            scan.review_summary = f"LLM-Fehler: {type(e).__name__}: {str(e)[:300]}"
            scan.reviewed_at = datetime.now(timezone.utc)
            s.commit()
            return

        verdict, summary, flagged = _parse_verdict(reply)
        scan.review_verdict = verdict
        scan.review_summary = summary
        scan.review_flagged_ids = flagged
        scan.reviewed_at = datetime.now(timezone.utc)
        s.commit()
        log.info(
            "scan_review: %s → %s (%d flagged)",
            scan.target_domain, verdict, len(flagged),
        )
