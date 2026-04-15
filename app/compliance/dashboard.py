"""Build the security dashboard context from a scan result.

Computes the weighted risk score, category groupings, top risks and a
legal-framework mapping that the scan detail page and PDF report both consume.
"""
from __future__ import annotations

from dataclasses import dataclass

# Per-finding weights used to compute the overall risk score. These mirror
# the CVSS-style "kritisch zählt viel" heuristic.
SEVERITY_WEIGHT = {
    "critical": 25,
    "high": 10,
    "medium": 4,
    "low": 1,
    "info": 0,
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class RiskGrade:
    letter: str  # A+ / A / B / C / D / F
    label: str   # Text that goes next to the letter
    color: str   # Tailwind color used for the dashboard banner
    description: str


def _grade_from_score(score: int, crit: int, high: int) -> RiskGrade:
    """Map a weighted score to a letter grade.

    Hard rule: any CRITICAL finding caps the grade at D; more than one caps at F.
    """
    if crit >= 2:
        return RiskGrade("F", "Unmittelbarer Handlungsbedarf", "rose",
                         "Mehrere kritische Befunde. Bitte sofort beheben — das Tool wertet dies als akuten Sicherheitsvorfall.")
    if crit == 1:
        return RiskGrade("D", "Kritischer Befund vorhanden", "rose",
                         "Mindestens ein kritischer Befund. Beheben Sie diesen zuerst.")
    if score >= 40 or high >= 3:
        return RiskGrade("C", "Deutliche Schwachstellen", "orange",
                         "Mehrere erhebliche Befunde. Priorisierte Behebung in den nächsten 30 Tagen.")
    if score >= 15 or high >= 1:
        return RiskGrade("B", "Überschaubare Risiken", "amber",
                         "Einzelne Befunde mit mittlerer Priorität. Fix im nächsten Wartungsfenster.")
    if score >= 5:
        return RiskGrade("A", "Gute Basis-Härtung", "emerald",
                         "Nur kleinere Befunde. Gute technische Grundkonfiguration.")
    return RiskGrade("A+", "Vorbildlich gehärtet", "emerald",
                     "Keine oder nur informative Befunde. Weiter so.")


# Category → (display label, emoji, color tailwind). Used by the dashboard grid.
CATEGORY_META: dict[str, tuple[str, str, str]] = {
    "DNS": ("DNS & Namens­auflösung", "🧭", "sky"),
    "E-Mail": ("E-Mail-Sicherheit", "✉️", "indigo"),
    "TLS": ("TLS / Verschlüsselung", "🔒", "emerald"),
    "Security Headers": ("HTTP Security Headers", "🧱", "teal"),
    "Web": ("Web-Erreichbarkeit", "🌐", "blue"),
    "Technologie-Offenlegung": ("Tech-Offen­legung", "🔎", "cyan"),
    "Outdated Libraries": ("Veraltete Libraries", "📦", "amber"),
    "Known CVE": ("Bekannte CVEs", "🛑", "rose"),
    "Network Exposure": ("Netzwerk-Exponierung", "📡", "orange"),
    "Exposed File": ("Offene Dateien", "📂", "rose"),
    "Credential Leak": ("Credential Leaks", "🔑", "rose"),
    "OSINT": ("OSINT", "🔍", "slate"),
    "Threat Intel": ("Threat Intel", "⚠️", "red"),
    "Reputation": ("IP-Reputation", "🚨", "orange"),
    "Subdomain Exposure": ("Subdomain-Expo­sition", "🌐", "fuchsia"),
    "Metadaten": ("Dateimetadaten", "🧾", "violet"),
    "DSGVO": ("DSGVO / TMG", "⚖️", "purple"),
    "Healthcare": ("Healthcare / KIM", "🏥", "pink"),
    "Healthcare / TI": ("TI-Konnektor", "🩺", "rose"),
    "Healthcare / API": ("Patient-API", "💉", "rose"),
    "Meta": ("Meta", "📎", "slate"),
}


def build_dashboard(scan_result: dict | None) -> dict:
    if not scan_result:
        return {
            "has_data": False,
        }

    findings = scan_result.get("findings") or []
    counts = scan_result.get("severity_counts") or {k: 0 for k in SEVERITY_ORDER}

    # Overall weighted score capped to 100.
    weighted = sum(SEVERITY_WEIGHT.get(f.get("severity", "info"), 0) for f in findings)
    score = min(100, weighted)
    grade = _grade_from_score(
        score,
        crit=counts.get("critical", 0),
        high=counts.get("high", 0),
    )

    # Group by category for the dashboard grid.
    by_cat_map: dict[str, list[dict]] = {}
    for f in findings:
        by_cat_map.setdefault(f.get("category", "Meta"), []).append(f)

    categories = []
    for cat_name, items in sorted(by_cat_map.items(), key=lambda x: -len(x[1])):
        worst = "info"
        for i in items:
            sev = i.get("severity", "info")
            if SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(worst):
                worst = sev
        label, emoji, color = CATEGORY_META.get(cat_name, (cat_name, "•", "slate"))
        cat_counts = {s: 0 for s in SEVERITY_ORDER}
        for i in items:
            cat_counts[i.get("severity", "info")] += 1
        categories.append(
            {
                "name": cat_name,
                "label": label,
                "emoji": emoji,
                "color": color,
                "total": len(items),
                "worst": worst,
                "counts": cat_counts,
                "findings": sorted(items, key=lambda f: SEVERITY_ORDER.index(f.get("severity", "info"))),
            }
        )

    # Top-5 risks: highest severity first, then ranked by category impact.
    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    top_risks = sorted(
        findings,
        key=lambda f: (severity_rank.get(f.get("severity", "info"), 99), f.get("id", "")),
    )[:5]

    return {
        "has_data": True,
        "score": score,
        "grade": {
            "letter": grade.letter,
            "label": grade.label,
            "color": grade.color,
            "description": grade.description,
        },
        "counts": counts,
        "total_findings": len(findings),
        "categories": categories,
        "top_risks": top_risks,
    }
