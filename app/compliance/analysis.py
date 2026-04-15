"""Build a KBV compliance summary from a scan result dict."""
from __future__ import annotations

from app.compliance.kbv_mapping import KBV_REQUIREMENTS, KBVRequirement, status_for_requirement


def build_kbv_summary(scan_result: dict | None) -> dict | None:
    if not scan_result:
        return None

    findings = scan_result.get("findings") or []
    finding_ids: set[str] = {f.get("id") for f in findings if f.get("id")}

    # Aggregate worst severity per requirement, for prioritization.
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    worst_sev_for_prefix: dict[str, str] = {}
    for f in findings:
        fid = f.get("id") or ""
        sev = f.get("severity", "info")
        cur = worst_sev_for_prefix.get(fid, "info")
        if sev_order.get(sev, 0) > sev_order.get(cur, 0):
            worst_sev_for_prefix[fid] = sev

    by_anlage: dict[int, list[dict]] = {}
    anlagen_titles = {
        1: "Anlage 1 — Grundlegende Anforderungen",
        2: "Anlage 2 — Mittlere Anforderungen",
        3: "Anlage 3 — Hohe Anforderungen (MVZ >20 BE)",
        4: "Anlage 4 — Medizinprodukte",
        5: "Anlage 5 — Dezentrale TI-Komponenten",
    }

    totals_ok = 0
    totals_fail = 0

    for req in KBV_REQUIREMENTS:
        status = status_for_requirement(req, finding_ids)
        worst_sev = "info"
        matched_ids: list[str] = []
        if status == "fail":
            for fid in finding_ids:
                for prefix in req.finding_id_prefixes:
                    if fid == prefix or fid.startswith(prefix):
                        matched_ids.append(fid)
                        sev = worst_sev_for_prefix.get(fid, "info")
                        if sev_order.get(sev, 0) > sev_order.get(worst_sev, 0):
                            worst_sev = sev
                        break

        if status == "ok":
            totals_ok += 1
        else:
            totals_fail += 1

        by_anlage.setdefault(req.anlage, []).append(
            {
                "code": req.code,
                "title": req.title,
                "description": req.description,
                "status": status,
                "severity": worst_sev if status == "fail" else "info",
                "matched_finding_ids": matched_ids,
            }
        )

    return {
        "anlagen": [
            {
                "anlage": a,
                "title": anlagen_titles.get(a, f"Anlage {a}"),
                "requirements": by_anlage[a],
                "fail_count": sum(1 for r in by_anlage[a] if r["status"] == "fail"),
                "ok_count": sum(1 for r in by_anlage[a] if r["status"] == "ok"),
            }
            for a in sorted(by_anlage.keys())
        ],
        "totals": {
            "ok": totals_ok,
            "fail": totals_fail,
            "total": totals_ok + totals_fail,
            "pct": round(100 * totals_ok / max(1, totals_ok + totals_fail)),
        },
    }
