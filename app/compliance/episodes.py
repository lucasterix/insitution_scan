"""Episodic memory: finding-level history per domain across rescans.

After each completed scan, every finding is upserted into `scan_episodes`:
  - first scan → insert with observation_count=1
  - later scan still showing it → update last_seen + bump observation_count
  - later scan no longer showing it → stamp resolved_at on the existing row

This powers the "seit X Tagen offen" badges on the scan detail + the PDF,
and the "endlich geschlossen" signal when a customer fixes something
between two scans. Inspired by pentagi's Graphiti memory but kept
lightweight — Postgres, no extra stack.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session


def update_episodes_sync(session: Session, scan_id: str, domain: str, result: dict) -> dict:
    """Sync variant used by the RQ worker after a scan completes.

    Returns a small summary dict {inserted, updated, resolved} for logging.
    """
    from app.models import ScanEpisode  # local import

    now = datetime.now(timezone.utc)
    findings = list(result.get("findings") or [])
    seen_ids: set[str] = set()

    # Pre-fetch all existing episodes for this domain in one round-trip.
    existing = {
        ep.finding_id: ep
        for ep in session.execute(
            select(ScanEpisode).where(ScanEpisode.domain == domain)
        ).scalars()
    }

    inserted = updated = resolved = 0

    for f in findings:
        fid = f.get("id")
        if not fid:
            continue
        seen_ids.add(fid)
        ep = existing.get(fid)
        if ep is None:
            session.add(ScanEpisode(
                domain=domain,
                finding_id=fid,
                severity=(f.get("severity") or "info").lower(),
                title=(f.get("title") or "")[:500],
                category=(f.get("category") or "")[:128] or None,
                first_seen=now,
                last_seen=now,
                observation_count=1,
                scan_id_latest=scan_id,
            ))
            inserted += 1
        else:
            ep.last_seen = now
            ep.observation_count = (ep.observation_count or 0) + 1
            ep.scan_id_latest = scan_id
            # If it was marked resolved before and now reappears, un-resolve.
            if ep.resolved_at is not None:
                ep.resolved_at = None
            # Latest title / severity wins (finding definitions can evolve).
            ep.severity = (f.get("severity") or ep.severity or "info").lower()
            ep.title = (f.get("title") or ep.title or "")[:500]
            updated += 1

    # Findings that existed before but weren't seen this time → resolve.
    for fid, ep in existing.items():
        if fid in seen_ids:
            continue
        if ep.resolved_at is None:
            ep.resolved_at = now
            resolved += 1

    session.commit()
    return {"inserted": inserted, "updated": updated, "resolved": resolved}


def days_since(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = now - dt
    return max(0, delta.days)
