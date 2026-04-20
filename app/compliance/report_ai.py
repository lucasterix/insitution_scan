"""3-Agent pipeline for the PDF Management-Zusammenfassung.

Inspired by pentagi's role separation: one big LLM call doing everything
tends to either hallucinate or produce vague prose. Splitting into three
focused stages gives auditable, grounded output:

  Enricher  — reads scan metadata + findings, emits a structured JSON
              with key observations (worst findings, KBV status, shadow-IT
              signals, institution type).
  Reporter  — turns that JSON into 2-3 paragraphs of German Sie-form
              executive prose in Daniel Rupp's voice.
  Adviser   — re-reads the reporter's draft against the original findings
              and returns either OK or a revised text with fabrications
              removed and tone tightened.

All three share the per-scan LLM budget (defined in app/config). Results
are cached in Redis keyed by a findings-content hash, so regenerating
the PDF for the same scan doesn't re-burn tokens.
"""
from __future__ import annotations

import hashlib
import json
import logging

from app import llm
from app.compliance.dashboard import build_dashboard
from app.queue import redis_conn

log = logging.getLogger("report_ai")

CACHE_TTL_SECONDS = 60 * 60 * 24 * 30  # 30 days


# ---------- helpers ----------


def _cache_key(scan_id: str, findings: list[dict], version: str = "v2") -> str:
    """Stable hash over finding ids + institution, so edits to the scan
    invalidate the cache automatically."""
    blob = json.dumps(
        sorted([(f.get("id"), f.get("severity")) for f in findings or []]),
        separators=(",", ":"),
    )
    h = hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]
    return f"report_ai:{version}:{scan_id}:{h}"


def _cached(key: str) -> str | None:
    try:
        raw = redis_conn.get(key)
        if raw:
            return raw.decode("utf-8") if isinstance(raw, bytes) else raw
    except Exception:  # noqa: BLE001
        pass
    return None


def _store(key: str, value: str) -> None:
    try:
        redis_conn.setex(key, CACHE_TTL_SECONDS, value)
    except Exception:  # noqa: BLE001
        pass


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------- Stage 1: Enricher ----------


ENRICHER_SYSTEM = (
    "Du bist der Enricher-Agent einer IT-Sicherheits-Report-Pipeline. Du bekommst "
    "Rohdaten eines Sicherheits-Scans (Institution, Domain, Findings) und gibst "
    "einen streng strukturierten JSON-Text zurück — ohne Prosa, ohne Einleitung.\n\n"
    "Das JSON-Schema muss genau so sein:\n"
    "{\n"
    "  \"institution_type\": \"...\",           // kurze Einordnung: MVZ, Arztpraxis, KMU, …\n"
    "  \"worst_severity\": \"critical|high|medium|low|info\",\n"
    "  \"top_three_risks\": [\"...\", \"...\", \"...\"], // 3 Finding-Titel (original) mit höchstem Risiko\n"
    "  \"compliance_flags\": [\"dsgvo\", \"kbv\", ...], // Liste der betroffenen Compliance-Rahmen\n"
    "  \"dominant_categories\": [\"...\", \"...\"], // die 2-3 Bereiche mit den meisten Handlungsempfehlungen\n"
    "  \"shadow_it_signals\": \"kurzer Satz oder leer\",  // Hinweise auf unentdeckte/vergessene Subdomains, VPN-Zugänge\n"
    "  \"notable_context\": \"kurzer Satz oder leer\"    // Weiteres auffälliges (z.B. PVS erkannt, Konnektor offen)\n"
    "}\n\n"
    "Keine Erfindungen — nutze NUR Informationen aus den gelieferten Findings. Keine konkreten "
    "CVE-Nummern, keine Versionsnummern, keine Fabrikationen. Keine Kommentare außerhalb des JSON."
)


def enrich(institution_name: str, target_domain: str, findings: list[dict], dashboard: dict | None = None, *, scan_id: str | None = None) -> dict:
    """Stage 1: Structured JSON-summary of the scan facts. Deterministic-ish
    input → keyed enrichment object."""
    sev_counts: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        cat = f.get("category") or ""
        by_category[cat] = by_category.get(cat, 0) + 1

    # Pass the worst 15 findings + counts by severity to the LLM (plenty of signal,
    # not so much that we blow the context).
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get((f.get("severity") or "info").lower(), 9))
    compact = [
        {
            "id": f.get("id"),
            "title": _truncate(f.get("title", ""), 160),
            "severity": f.get("severity"),
            "category": f.get("category"),
        }
        for f in sorted_findings[:15]
    ]

    user_prompt = json.dumps({
        "institution_name": institution_name,
        "target_domain": target_domain,
        "counts_by_severity": sev_counts,
        "counts_by_category": by_category,
        "worst_findings_sample": compact,
        "grade": (dashboard or {}).get("grade", {}).get("letter"),
        "score": (dashboard or {}).get("score"),
    }, ensure_ascii=False, indent=2)

    text = llm.draft(ENRICHER_SYSTEM, user_prompt, max_tokens=700, temperature=0.2, scan_id=scan_id)
    # Try to parse JSON; on failure return a minimal dict so Reporter still works.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        log.warning("Enricher returned non-JSON, using fallback. Got: %s", text[:200])
        return {"worst_severity": max(sev_counts, key=lambda k: sev_order.get(k, 9), default="info")}


# ---------- Stage 2: Reporter ----------


REPORTER_SYSTEM = (
    "Du bist der Reporter-Agent. Du schreibst die Management-Zusammenfassung eines "
    "IT-Sicherheits-Prüfberichts im Namen von Daniel Rupp (Advanced Analytics GmbH / ZDKG). "
    "Zielpublikum: Geschäftsführung einer Arztpraxis, eines MVZ oder KMU — nicht-technisch.\n\n"
    "REGELN:\n"
    "- 2-3 Absätze, deutsches Sie-Form, ruhiger seriöser Ton.\n"
    "- Keine CVE-Nummern, keine konkreten Versionsnummern, keine spezifischen Zahlen außer "
    "jenen die im Input stehen.\n"
    "- Kein Marketing-Sprech, kein Alarmismus.\n"
    "- Keine Floskeln wie 'wie Sie wissen', 'im heutigen digitalen Zeitalter'.\n"
    "- Struktur: (1) was wurde geprüft + Gesamteindruck, (2) was sind die wichtigsten Handlungs-"
    "bereiche, (3) Empfehlung zur Priorisierung.\n"
    "- Output: reiner Fließtext, KEINE Überschriften, KEIN Markdown, KEINE Listen. "
    "Absätze getrennt durch Leerzeile.\n"
    "- Keine Grußformel (der Bericht hat an anderer Stelle schon eine)."
)


def report(enrichment: dict, institution_name: str, target_domain: str, *, scan_id: str | None = None) -> str:
    """Stage 2: prose output for humans."""
    user_prompt = (
        "Basiere die Zusammenfassung auf diesem Enricher-Output:\n\n"
        + json.dumps(enrichment, ensure_ascii=False, indent=2)
        + f"\n\nInstitution: {institution_name}\nDomain: {target_domain}\n\n"
        "Schreibe die Management-Zusammenfassung jetzt."
    )
    return llm.draft(REPORTER_SYSTEM, user_prompt, max_tokens=700, temperature=0.45, scan_id=scan_id)


# ---------- Stage 3: Adviser ----------


ADVISER_SYSTEM = (
    "Du bist der Adviser-Agent. Du bekommst einen Management-Zusammenfassungs-Entwurf plus "
    "die Original-Findings und den Enricher-Output. Deine Aufgabe ist **Audit + Revision**:\n\n"
    "1. Enthält der Entwurf Zahlen/CVE/Versionen/Aussagen die NICHT aus den Findings oder "
    "dem Enricher-Output belegt sind? → Entferne sie oder formuliere vage.\n"
    "2. Ton zu alarmistisch, zu markenmäßig, zu schwurbelig? → Glätte.\n"
    "3. Passt die Priorisierung zu den tatsächlichen Schweregraden?\n"
    "4. Sie-Form konsequent?\n\n"
    "Gib NUR die finale, korrigierte Fassung zurück — kein Kommentar, kein 'Hier ist die "
    "Revision:'. Wenn der Entwurf in Ordnung ist, gib ihn 1:1 zurück."
)


def advise(draft_text: str, enrichment: dict, findings: list[dict], *, scan_id: str | None = None) -> str:
    """Stage 3: audit + revise."""
    # Give the adviser 20 original finding titles for grounding (not all — token cost).
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    grounded = sorted(findings, key=lambda f: sev_order.get((f.get("severity") or "info").lower(), 9))[:20]
    user_prompt = (
        "ENTWURF:\n" + draft_text + "\n\n"
        "ENRICHER-OUTPUT:\n" + json.dumps(enrichment, ensure_ascii=False, indent=2) + "\n\n"
        "ORIGINAL-FINDINGS (Auszug):\n"
        + "\n".join(f"- [{f.get('severity')}] {_truncate(f.get('title', ''), 120)}" for f in grounded)
        + "\n\nGib die finale Fassung jetzt zurück."
    )
    return llm.draft(ADVISER_SYSTEM, user_prompt, max_tokens=700, temperature=0.2, scan_id=scan_id)


# ---------- Convenience: full pipeline with cache ----------


def generate_executive_summary(
    scan_id: str,
    institution_name: str,
    target_domain: str,
    findings: list[dict],
    result: dict | None = None,
) -> str | None:
    """Run the three agents (with per-scan token budget enforced in llm.draft).

    Returns the final prose, or None when AI is disabled / budget exhausted —
    caller should then fall back to a simple template-based summary.
    """
    if not llm.is_enabled():
        return None
    if not findings:
        return None

    key = _cache_key(scan_id, findings)
    cached = _cached(key)
    if cached:
        return cached

    try:
        dashboard = build_dashboard(result or {"findings": findings})
    except Exception:  # noqa: BLE001
        dashboard = None

    try:
        enrichment = enrich(institution_name, target_domain, findings, dashboard, scan_id=scan_id)
        draft_text = report(enrichment, institution_name, target_domain, scan_id=scan_id)
        final = advise(draft_text, enrichment, findings, scan_id=scan_id)
    except llm.BudgetExceeded as e:
        log.info("report_ai skipped: budget exceeded (%s)", e)
        return None
    except Exception as e:  # noqa: BLE001
        log.warning("report_ai failed: %s: %s", type(e).__name__, e)
        return None

    final = (final or "").strip()
    if final:
        _store(key, final)
    return final or None
