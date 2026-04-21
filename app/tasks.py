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
    except Exception as e:  # noqa: BLE001
        set_status(
            status="failed",
            error=f"{type(e).__name__}: {e}",
            finished_at=datetime.now(timezone.utc),
        )
        raise
