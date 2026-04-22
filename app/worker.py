"""RQ worker entrypoint with startup self-healing.

Docker-compose replaces worker containers on every new image deploy.
The scan job each worker was processing at that moment becomes an
orphan: the Scan row stays status='running' forever, and nobody picks
it up again. On startup we therefore look for any Scan marked
'running' whose started_at is older than STUCK_AFTER_MINUTES, reset it
to 'queued', and push a fresh RQ job so the fleet recovers
automatically.

Idempotent — if two workers start at the same time, the second one's
UPDATE just finds no rows to touch.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from rq import Worker
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.queue import redis_conn, scan_queue
from app.tasks import run_scan_job

STUCK_AFTER_MINUTES = 10
log = logging.getLogger("worker")


def _requeue_stuck_scans() -> None:
    """Find running scans that look orphaned and re-enqueue them."""
    from app.models import Scan  # lazy to avoid metadata init at import time

    s = get_settings()
    sync_url = s.database_url.replace("+asyncpg", "+psycopg") if "+asyncpg" in s.database_url else s.database_url
    try:
        engine = create_engine(sync_url, pool_pre_ping=True)
    except Exception as e:  # noqa: BLE001
        log.warning("startup-requeue: DB connect failed: %s", e)
        return

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=STUCK_AFTER_MINUTES)
    try:
        with Session(engine) as sess:
            stuck = list(sess.execute(
                select(Scan).where(Scan.status == "running", Scan.started_at < cutoff)
            ).scalars())
            if not stuck:
                return
            ids = [x.id for x in stuck]
            sess.execute(
                update(Scan).where(Scan.id.in_(ids)).values(
                    status="queued", progress=0, current_step=None,
                    started_at=None, finished_at=None, error=None, result=None,
                )
            )
            sess.commit()
            for scan in stuck:
                scan_queue.enqueue(
                    run_scan_job, scan.id, scan.target_domain,
                    scan.deep_scan, scan.rate_limit_test,
                    job_id=f"scan-{scan.id}-revive-{datetime.now().strftime('%H%M%S')}",
                )
                log.info("startup-requeue: re-queued %s (was stuck in running)", scan.target_domain)
    except Exception as e:  # noqa: BLE001
        log.warning("startup-requeue: unexpected error: %s", e)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    _requeue_stuck_scans()
    worker = Worker([scan_queue], connection=redis_conn)
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    main()
