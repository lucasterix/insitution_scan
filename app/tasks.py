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

        # Compose a neutral default body. The scheduled banner on /inbox lets
        # the user review and cancel before the actual send time.
        subject = f"IT-Sicherheitsprüfung {scan.target_domain} — Prüfbericht + Angebot"
        body = (
            "Sehr geehrte Damen und Herren,\n\n"
            f"anbei erhalten Sie den Prüfbericht unserer IT-Sicherheitsprüfung für "
            f"{scan.institution_name or scan.target_domain} ({scan.target_domain}) "
            "sowie unser unverbindliches Angebot zur Behebung der festgestellten Befunde.\n\n"
            "Die Prüfung erfolgte im Rahmen unserer Vorsorgetätigkeit für Einrichtungen "
            "des Gesundheitssektors — Grundlage sind KBV §390 SGB V, DSGVO Art. 32 und "
            "ggf. NIS2UmsuCG. Für Rückfragen oder einen kurzen Termin erreichen Sie uns "
            "unter +49 176 43677735 oder per Antwort auf diese Mail.\n\n"
            "Mit freundlichen Grüßen\n\n"
            "Daniel Rupp\n"
            "Advanced Analytics GmbH — ZDKG"
        )

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
