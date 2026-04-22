"""Background job: run a scan and persist status/result to the database.

Runs in the RQ worker process (sync). Uses a sync engine to avoid mixing
asyncio event loops with RQ's fork-based worker.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.scanners.osint import run_osint_scan

settings = get_settings()

# Sync URL variant for the worker (strip asyncpg driver).
SYNC_DB_URL = settings.database_url.replace("+asyncpg", "+psycopg") if "+asyncpg" in settings.database_url else settings.database_url


def _sync_engine():
    try:
        return create_engine(SYNC_DB_URL, pool_pre_ping=True)
    except Exception:
        return create_engine(
            settings.database_url.replace("postgresql+asyncpg", "postgresql"),
            pool_pre_ping=True,
        )


def _format_eur(cents_or_eur) -> str:
    """German-formatted EUR string. Accepts float/int euros."""
    try:
        n = float(cents_or_eur)
    except (TypeError, ValueError):
        return "0,00 €"
    return f"{n:,.2f} €".replace(",", "X").replace(".", ",").replace("X", ".")


def _compose_batch_offer(scan) -> tuple[str, str]:
    """Build subject + body for the batch auto-offer mail.

    Individualised: references the institution name, cites concrete
    severity counts + offer totals, and opens with an institution-
    specific greeting. Intentionally avoids words like "automatisiert"
    — the mail is presented as expert-authored, because a human reviews
    it in the /inbox scheduled banner before 08:00.
    """
    from app.compliance.offer import build_offer

    inst = (scan.institution_name or "").strip()
    domain = scan.target_domain
    rate = (scan.context or {}).get("hourly_rate_eur") if scan.context else None
    try:
        offer = build_offer(scan.result or {}, hourly_rate_eur=rate) or {}
    except Exception:  # noqa: BLE001
        offer = {}

    findings = (scan.result or {}).get("findings") or []
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s_ = f.get("severity")
        if s_ in sev:
            sev[s_] += 1
    actionable = sev["critical"] + sev["high"] + sev["medium"] + sev["low"]

    # Opening: prefer the institution name if it reads like a proper noun,
    # else fall back to the generic greeting.
    if inst and any(ch.isalpha() for ch in inst):
        greeting = f"sehr geehrte Damen und Herren des {inst},"
    else:
        greeting = "sehr geehrte Damen und Herren,"

    subject = f"Prüfbericht {domain} — Befunde und Angebot"

    # Findings line — only mention severities that are actually present, so
    # the mail doesn't claim "0 kritische" when there are none.
    sev_parts: list[str] = []
    if sev["critical"]:
        sev_parts.append(f"{sev['critical']} kritische")
    if sev["high"]:
        sev_parts.append(f"{sev['high']} hohe")
    if sev["medium"]:
        sev_parts.append(f"{sev['medium']} mittlere")
    if sev_parts:
        sev_line = (
            f"im Rahmen unserer externen Sicherheitsprüfung Ihrer Domain {domain} "
            f"haben wir {actionable} handlungsrelevante Befunde identifiziert — "
            f"darunter {', '.join(sev_parts)}."
        )
    else:
        sev_line = (
            f"im Rahmen unserer externen Sicherheitsprüfung Ihrer Domain {domain} "
            f"ergeben sich aktuell keine als kritisch oder hoch eingestuften Befunde. "
            f"Wir haben die Prüfung dennoch vollständig dokumentiert."
        )

    # Offer line — only if we have figures.
    offer_line = ""
    if offer and offer.get("total_hours"):
        offer_line = (
            f"Unser Aufwands-Angebot weist einen Gesamtaufwand von ca. "
            f"{offer['total_hours']:.1f} Stunden aus (Stundensatz: "
            f"{_format_eur(offer.get('hourly_rate_eur', 0))}): "
            f"{_format_eur(offer.get('net_eur', 0))} netto, "
            f"{_format_eur(offer.get('gross_eur', 0))} brutto. "
            f"Abgerechnet wird spitz nach tatsächlichem Aufwand."
        )

    body_parts = [
        greeting,
        "",
        sev_line,
        "",
        "Im Anhang finden Sie:",
        "  • den vollständigen Prüfbericht",
        "  • ein Aufwands-Angebot mit Stundenkalkulation",
    ]
    if offer_line:
        body_parts += ["", offer_line]
    body_parts += [
        "",
        "Für eine Umsetzung oder Rückfragen erreichen Sie uns unter +49 176 43677735 "
        "oder per Antwort auf diese Mail.",
        "",
        "Mit freundlichen Grüßen",
        "",
        "Daniel Rupp",
        "Advanced Analytics GmbH — ZDKG",
        "daniel.rupp@zdkg.de · zdkg.de",
    ]
    return subject, "\n".join(body_parts)


def _queue_auto_offer_if_configured(engine, scan_id: str) -> None:
    """If the scan was created via CSV batch import with auto_offer_* set,
    create a ScheduledEmail row that the dispatcher will send at the
    scheduled time. Idempotent: auto_offer_dispatched_at guards against
    duplicate queueing on re-runs.
    """
    from app.models import Scan, ScheduledEmail

    with Session(engine) as s:
        scan = s.get(Scan, scan_id)
        if not scan:
            return
        if not (scan.auto_offer_recipient and scan.auto_offer_scheduled_for):
            return
        if scan.auto_offer_dispatched_at:
            return  # already queued

        # Respect the AI-review gate: any scan flagged 'issues' gets its
        # auto-offer BLOCKED. The user reviews + unlocks manually via the
        # scan detail UI. Better to delay a send than mail noisy findings.
        if scan.review_verdict == "issues":
            print(
                f"[auto_offer] BLOCKED by review_verdict=issues for {scan.target_domain}; "
                "human needs to unlock before mail queues.",
                flush=True,
            )
            return

        subject, body = _compose_batch_offer(scan)

        sched = ScheduledEmail(
            inbound_message_id=None,
            scan_id=scan.id,
            to_addr=scan.auto_offer_recipient,
            cc_addr=None,
            subject=subject,
            body_text=body,
            in_reply_to=None,
            references=None,
            scheduled_for=scan.auto_offer_scheduled_for,
            status="queued",
            include_offer_pdfs=True,
        )
        s.add(sched)
        scan.auto_offer_dispatched_at = datetime.now(timezone.utc)
        s.commit()
        print(f"[auto_offer] queued for scan={scan_id} at {scan.auto_offer_scheduled_for.isoformat()}", flush=True)


def run_scan_job(scan_id: str, domain: str, deep_scan: bool = False, rate_limit_test: bool = False) -> None:
    from app.models import Scan  # local import avoids eager metadata init

    engine = _sync_engine()

    def set_status(**fields) -> None:
        with Session(engine) as s:
            s.execute(update(Scan).where(Scan.id == scan_id).values(**fields))
            s.commit()

    set_status(status="running", started_at=datetime.now(timezone.utc), progress=1, current_step="Initialisiere")

    def progress_cb(label: str, pct: int) -> None:
        set_status(progress=pct, current_step=label)

    try:
        result = run_osint_scan(domain, on_progress=progress_cb, deep_scan=deep_scan, rate_limit_test=rate_limit_test)
        set_status(
            status="completed",
            progress=100,
            current_step="Abgeschlossen",
            finished_at=datetime.now(timezone.utc),
            result=result,
        )

        # Update per-domain episodic memory so rescans show "seit X Tagen offen".
        # Wrapped to never fail the scan on episode-update errors.
        try:
            from app.compliance.episodes import update_episodes_sync
            with Session(engine) as s:
                summary = update_episodes_sync(s, scan_id, domain, result)
                print(f"[episodes] {domain}: {summary}", flush=True)
        except Exception as ep_err:  # noqa: BLE001
            print(f"[episodes] update failed: {type(ep_err).__name__}: {ep_err}", flush=True)

        # Claude auto-review of the completed scan. Runs before the
        # auto-offer queue hook so a "issues" verdict blocks the mail.
        # Failures never fail the scan — just log + move on.
        try:
            from app.scan_review import review_scan_sync
            review_scan_sync(scan_id)
        except Exception as rv_err:  # noqa: BLE001
            print(f"[scan_review] failed: {type(rv_err).__name__}: {rv_err}", flush=True)

        # CSV-Batch-Import: if auto_offer_* fields are set, park a ScheduledEmail
        # so the dispatcher ships the offer at the scheduled time with both PDFs
        # attached. Wrapped so failures never block the scan itself.
        try:
            _queue_auto_offer_if_configured(engine, scan_id)
        except Exception as ao_err:  # noqa: BLE001
            print(f"[auto_offer] queue failed: {type(ao_err).__name__}: {ao_err}", flush=True)
    except Exception as e:  # noqa: BLE001
        set_status(
            status="failed",
            error=f"{type(e).__name__}: {e}",
            finished_at=datetime.now(timezone.utc),
        )
        raise
