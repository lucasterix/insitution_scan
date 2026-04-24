from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.compliance.analysis import build_kbv_summary
from app.compliance.dashboard import build_dashboard
from app.compliance.offer import build_offer, format_eur
from app.db import get_session
from app.models import Message, Scan, ScheduledEmail
from app.queue import redis_conn, scan_queue
from app.scanners.osint import _normalize_domain
from app.tasks import run_scan_job

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


async def _tpl(request: Request, session: AsyncSession, template: str, ctx: dict) -> HTMLResponse:
    from sqlalchemy import func
    user = await get_current_user(request, session)
    ctx["current_user"] = user
    # Navbar unread badge — cheap SELECT, fine on every page.
    if "nav_unread_msgs" not in ctx:
        try:
            ctx["nav_unread_msgs"] = (await session.execute(
                select(func.count(Message.id)).where(
                    Message.direction == "inbound", Message.read_at.is_(None)
                )
            )).scalar() or 0
        except Exception:  # noqa: BLE001 — never block rendering on this
            ctx["nav_unread_msgs"] = 0
    return templates.TemplateResponse(request, template, ctx)


def _summarize_for_list(scan: Scan) -> dict | None:
    """Compact per-scan summary for the dashboard list row:
      - grade letter + color
      - counts by severity (only non-zero buckets)
      - gross EUR total from the offer
    Returns None for scans without a result (queued/running/failed early).
    Pure in-memory work on scan.result — no DB, no LLM."""
    if not scan.result or not (scan.result.get("findings") or []):
        return None
    try:
        dash = build_dashboard(scan.result)
        if not dash or not dash.get("has_data"):
            return None
        rate = (scan.context or {}).get("hourly_rate_eur") if scan.context else None
        offer = build_offer(scan.result, hourly_rate_eur=rate)
        counts = dash.get("counts") or {}
        grade = dash.get("grade") or {}
        return {
            "grade_letter": grade.get("letter"),
            "grade_color":  grade.get("color"),
            "critical": counts.get("critical", 0),
            "high":     counts.get("high", 0),
            "medium":   counts.get("medium", 0),
            "low":      counts.get("low", 0),
            "info":     counts.get("info", 0),
            "gross_eur": offer.get("gross_eur", 0),
            "hours":     offer.get("total_hours", 0),
        }
    except Exception:  # noqa: BLE001 — list view must never fail on summary errors
        return None


@router.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    session: AsyncSession = Depends(get_session),
    status: str = "",
    q: str = "",
    page: int = 1,
) -> HTMLResponse:
    from datetime import timedelta
    from sqlalchemy import and_, func, or_

    PER_PAGE = 20
    page = max(1, page)

    # ---- Aggregate stats (full DB, not filtered) ----
    now = datetime.now(timezone.utc)
    today_start = now - timedelta(days=1)
    stats_q = await session.execute(
        select(Scan.status, func.count(Scan.id)).group_by(Scan.status)
    )
    by_status = {row[0]: row[1] for row in stats_q.all()}

    today_count = (await session.execute(
        select(func.count(Scan.id)).where(Scan.created_at >= today_start)
    )).scalar() or 0

    # Avg duration on completed scans with timestamps.
    avg_row = (await session.execute(
        select(func.avg(func.extract("epoch", Scan.finished_at) - func.extract("epoch", Scan.started_at)))
        .where(Scan.status == "completed", Scan.started_at.isnot(None), Scan.finished_at.isnot(None))
    )).scalar()
    avg_duration_s = int(avg_row) if avg_row else 0

    unread_msgs = (await session.execute(
        select(func.count(Message.id)).where(
            Message.direction == "inbound", Message.read_at.is_(None)
        )
    )).scalar() or 0

    from app import llm as _llm
    llm_today = _llm.today_usage() if _llm.is_enabled() else None

    stats = {
        "total":     sum(by_status.values()),
        "queued":    by_status.get("queued", 0),
        "running":   by_status.get("running", 0),
        "completed": by_status.get("completed", 0),
        "failed":    by_status.get("failed", 0),
        "today":     today_count,
        "avg_duration_s": avg_duration_s,
        "unread_msgs": unread_msgs,
        "llm_today":  llm_today,
    }

    # ---- Filtered + paginated list ----
    where = []
    if status in ("queued", "running", "completed", "failed"):
        where.append(Scan.status == status)
    if q:
        needle = f"%{q.strip()}%"
        where.append(or_(Scan.institution_name.ilike(needle), Scan.target_domain.ilike(needle)))

    count_stmt = select(func.count(Scan.id))
    if where:
        count_stmt = count_stmt.where(and_(*where))
    total_matching = (await session.execute(count_stmt)).scalar() or 0
    total_pages = max(1, (total_matching + PER_PAGE - 1) // PER_PAGE)
    page = min(page, total_pages)

    list_stmt = select(Scan).order_by(Scan.created_at.desc()).limit(PER_PAGE).offset((page - 1) * PER_PAGE)
    if where:
        list_stmt = list_stmt.where(and_(*where))
    scans = list((await session.execute(list_stmt)).scalars().all())

    # Compute in-memory summary (grade + severity counts + EUR) per completed scan,
    # so the list shows criticality + price without a click-through.
    summaries = {s.id: _summarize_for_list(s) for s in scans}

    # Pending offer mails per scan on this page: map scan_id → ScheduledEmail
    # so the row can show "Mail geplant für …" and let the user stop it in one click.
    scan_ids_on_page = [s.id for s in scans]
    pending_by_scan: dict[str, dict] = {}
    if scan_ids_on_page:
        q_sched = select(ScheduledEmail).where(
            ScheduledEmail.status == "queued",
            ScheduledEmail.scan_id.in_(scan_ids_on_page),
        )
        for sched in (await session.execute(q_sched)).scalars():
            # Take the earliest queued per scan.
            existing = pending_by_scan.get(sched.scan_id or "")
            if not existing or sched.scheduled_for < existing["scheduled_for"]:
                pending_by_scan[sched.scan_id or ""] = {
                    "id": sched.id,
                    "scheduled_for": sched.scheduled_for,
                    "to_addr": sched.to_addr,
                }

    return await _tpl(
        request, session, "index.html",
        {
            "scans": scans, "stats": stats, "summaries": summaries,
            "format_eur": format_eur,
            "status_filter": status, "q": q,
            "page": page, "total_pages": total_pages, "per_page": PER_PAGE,
            "total_matching": total_matching,
            "pending_offer_by_scan": pending_by_scan,
        },
    )


@router.get("/scans/new", response_class=HTMLResponse)
async def new_scan_form(request: Request, session: AsyncSession = Depends(get_session)) -> HTMLResponse:
    return await _tpl(request, session, "scan_new.html", {})


def _parse_targets(raw: str) -> list[str]:
    """Split raw input (lines, commas, semicolons, whitespace) into unique domain candidates."""
    import re as _re
    pieces = [p.strip() for p in _re.split(r"[\s,;]+", raw or "") if p.strip()]
    # Normalize + dedupe while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for p in pieces:
        norm = _normalize_domain(p)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def _validate_target(candidate: str) -> bool:
    import ipaddress as _ipa
    try:
        _ipa.ip_address(candidate)
        return True
    except ValueError:
        pass
    return "." in candidate


@router.post("/scans")
async def create_scan(
    request: Request,
    institution_name: str = Form(...),
    target_domain: str = Form(...),
    ownership_confirmed: str = Form(None),
    deep_scan: str = Form(None),
    rate_limit_test: str = Form(None),
    context_notes: str = Form(""),
    context_emails: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    targets = _parse_targets(target_domain)
    invalid = [t for t in targets if not _validate_target(t)]
    if not targets:
        raise HTTPException(status_code=400, detail="Keine gültige Domain oder IP-Adresse erkannt")
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Ungültige Einträge: {', '.join(invalid[:5])}",
        )
    # Hard cap to prevent accidental DoS of the worker queue.
    if len(targets) > 50:
        raise HTTPException(
            status_code=400,
            detail=f"Zu viele Ziele auf einmal ({len(targets)}). Bitte maximal 50 pro Batch.",
        )

    if not ownership_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Die Eigentümer-Bestätigung ist Pflicht. Scans fremder Systeme sind strafbar (§202c StGB).",
        )

    is_deep = bool(deep_scan)
    is_rate_test = bool(rate_limit_test)

    context: dict = {}
    if context_notes.strip():
        context["notes"] = context_notes.strip()[:2000]
    if context_emails.strip():
        emails = [e.strip().lower() for e in context_emails.split(",") if "@" in e]
        if emails:
            context["extra_emails"] = emails[:20]

    created_ids: list[str] = []
    inst = institution_name.strip()
    for domain in targets:
        scan = Scan(
            institution_name=inst,
            target_domain=domain,
            status="queued",
            progress=0,
            ownership_confirmed=True,
            deep_scan=is_deep,
            rate_limit_test=is_rate_test,
            context=context or None,
        )
        session.add(scan)
        await session.flush()  # assign id without committing
        created_ids.append(scan.id)

    await session.commit()

    # Enqueue AFTER commit so the worker never picks up a row that's still in-flight.
    for sid, domain in zip(created_ids, targets):
        scan_queue.enqueue(
            run_scan_job, sid, domain, is_deep, is_rate_test, job_id=f"scan-{sid}"
        )

    # One scan → straight to its detail page. Multiple → back to index where the
    # user sees the whole batch and can watch each one progress.
    if len(created_ids) == 1:
        return RedirectResponse(url=f"/scans/{created_ids[0]}", status_code=303)
    return RedirectResponse(url="/?batch=" + str(len(created_ids)), status_code=303)


# --------------------------- CSV-Batch-Import ---------------------------

BATCH_SPAM_SPACING_MINUTES = 4  # gap between consecutive auto-offer sends
BATCH_MAX_ROWS = 200  # hard cap to keep the worker queue sane


def _parse_batch_csv(raw: bytes) -> list[dict]:
    """Turn a CSV upload into rows with (institution_name, recipient, domain).

    Accepts encodings utf-8 / cp1252 / latin-1 (the input sample came from
    Excel-exported data with mojibake like 'Ã¤' for 'ä' — we still accept it
    but the institution name will carry that mojibake through).

    Strips duplicate domains (keeps the first row per domain) and skips
    rows with no parseable email. Returns an ordered list.
    """
    import csv
    import io
    text: str | None = None
    for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise HTTPException(status_code=400, detail="CSV-Datei konnte nicht dekodiert werden")

    reader = csv.DictReader(io.StringIO(text))
    out: list[dict] = []
    seen_domains: set[str] = set()
    for row in reader:
        name = (row.get("name") or "").strip()
        email_cell = (row.get("email") or "").strip()
        if not email_cell:
            continue
        # email column may carry multiple addrs separated by ; or ,
        candidates = [e.strip().lower() for e in email_cell.replace(",", ";").split(";") if "@" in e]
        if not candidates:
            continue
        primary = candidates[0]
        domain = primary.rsplit("@", 1)[-1]
        if not domain or not _validate_target(domain):
            continue
        if domain in seen_domains:
            continue
        seen_domains.add(domain)
        out.append({
            "institution_name": name or domain,
            "recipient": primary,
            "domain": domain,
        })
        if len(out) >= BATCH_MAX_ROWS:
            break
    return out


def _tomorrow_at_eight_berlin() -> datetime:
    """Next calendar day, 08:00 Europe/Berlin, returned as aware UTC datetime."""
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("Europe/Berlin")
    except Exception:  # noqa: BLE001
        tz = timezone.utc
    now_local = datetime.now(tz)
    tomorrow = (now_local + timedelta(days=1)).replace(hour=8, minute=0, second=0, microsecond=0)
    return tomorrow.astimezone(timezone.utc)


@router.get("/batch", response_class=HTMLResponse)
async def batch_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    return await _tpl(request, session, "batch_csv.html", {
        "spacing_minutes": BATCH_SPAM_SPACING_MINUTES,
        "max_rows": BATCH_MAX_ROWS,
    })


@router.post("/batch/csv")
async def batch_csv_upload(
    request: Request,
    file: UploadFile = File(...),
    deep_scan: str = Form(None),
    send_when: str = Form("tomorrow8"),
    custom_start: str = Form(""),
    spacing_minutes: int = Form(BATCH_SPAM_SPACING_MINUTES),
    session: AsyncSession = Depends(get_session),
) -> Response:
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")

    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Leere Datei")
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Datei zu groß (max 2 MB)")

    rows = _parse_batch_csv(raw)
    if not rows:
        raise HTTPException(status_code=400, detail="Keine verwertbaren Zeilen (Header name,email?)")

    from uuid import uuid4 as _uuid
    batch_id = str(_uuid())
    is_deep = bool(deep_scan)

    # ---------- Send-time strategy ----------
    # Three modes, always with minutes-spacing between consecutive mails:
    #   "now"        — first mail goes out on next poller tick, each next one
    #                  +spacing_minutes later. Useful for small hot batches.
    #   "tomorrow8"  — tomorrow 08:00 Europe/Berlin (default, original behavior).
    #   "custom"     — user picked a specific datetime-local. Parsed as Berlin
    #                  local via _parse_scheduled_for; falls back to tomorrow8
    #                  if empty/past.
    spacing = max(1, min(int(spacing_minutes or BATCH_SPAM_SPACING_MINUTES), 60))
    if send_when == "now":
        # Each scan still needs to finish before its mail fires — give the
        # first one a small head start so the scan has time to complete.
        start_utc = datetime.now(timezone.utc) + timedelta(minutes=spacing)
    elif send_when == "custom":
        parsed = _parse_scheduled_for(custom_start)
        start_utc = parsed if parsed is not None else _tomorrow_at_eight_berlin()
    else:
        start_utc = _tomorrow_at_eight_berlin()

    created_ids: list[tuple[str, str]] = []
    for i, row in enumerate(rows):
        send_at = start_utc + timedelta(minutes=i * spacing)
        scan = Scan(
            institution_name=row["institution_name"][:255],
            target_domain=row["domain"],
            status="queued",
            progress=0,
            ownership_confirmed=True,
            deep_scan=is_deep,
            rate_limit_test=False,
            context={"source": "csv_batch", "batch_id": batch_id},
            batch_id=batch_id,
            auto_offer_recipient=row["recipient"],
            auto_offer_scheduled_for=send_at,
        )
        session.add(scan)
        await session.flush()
        created_ids.append((scan.id, row["domain"]))

    await session.commit()

    for sid, domain in created_ids:
        scan_queue.enqueue(
            run_scan_job, sid, domain, is_deep, False, job_id=f"scan-{sid}"
        )

    return RedirectResponse(url=f"/?batch_id={batch_id}", status_code=303)


def _contact_and_offer(scan: Scan) -> tuple[dict, dict]:
    """Build the contact card + offer for templates."""
    result = scan.result or {}
    contact = (result.get("metadata") or {}).get("impressum") or {}
    # Fall back to harvested emails when impressum parse missed one.
    if not contact.get("emails"):
        harvested = (result.get("metadata") or {}).get("harvested_emails") or []
        if harvested:
            contact = {**contact, "emails": harvested[:5]}
    rate = (scan.context or {}).get("hourly_rate_eur") if scan.context else None
    offer = build_offer(result, hourly_rate_eur=rate) if scan.status == "completed" else None
    return contact, offer


async def _episodes_for_scan(session: AsyncSession, scan: Scan) -> dict[str, dict]:
    """Return {finding_id: {first_seen, last_seen, observation_count, days_known, resolved_at}}
    for the scan's target_domain. UI uses this to render 'seit X Tagen offen' badges."""
    from app.models import ScanEpisode
    from app.compliance.episodes import days_since

    q = select(ScanEpisode).where(ScanEpisode.domain == scan.target_domain)
    res = await session.execute(q)
    out: dict[str, dict] = {}
    for ep in res.scalars():
        out[ep.finding_id] = {
            "first_seen": ep.first_seen,
            "last_seen": ep.last_seen,
            "observation_count": ep.observation_count or 1,
            "days_known": days_since(ep.first_seen),
            "resolved_at": ep.resolved_at,
        }
    return out


# Number of days an outbound can sit without a reply before we surface
# the "Folgemail" CTA. Tweak here if the cadence needs to change.
FOLLOWUP_OVERDUE_DAYS = 4


def _followup_state(scan: Scan, messages: list[Message]) -> dict | None:
    """Return {overdue, days_since, last_outbound, recipient} or None.

    None = no follow-up makes sense yet (no outbound, a reply already came,
    or we're still inside the grace window).
    """
    outbounds = [m for m in messages if m.direction == "outbound"]
    if not outbounds:
        return None
    last_out = max(outbounds, key=lambda m: m.received_at or datetime.min.replace(tzinfo=timezone.utc))
    if not last_out.received_at:
        return None
    # Reply already arrived after our last outbound → thread is alive, skip.
    for m in messages:
        if m.direction == "inbound" and m.received_at and m.received_at > last_out.received_at:
            return None

    days = (datetime.now(timezone.utc) - last_out.received_at).days
    overdue = days >= FOLLOWUP_OVERDUE_DAYS
    if not overdue:
        return None
    recipient = last_out.to_addr or ""
    # to_addr may contain multiple recipients separated by comma/semicolon —
    # keep the first real address for the follow-up.
    if recipient:
        first = recipient.split(",")[0].split(";")[0].strip()
        recipient = first
    return {
        "overdue": True,
        "days_since": days,
        "last_outbound": last_out,
        "recipient": recipient,
    }


async def _messages_for_scan(session: AsyncSession, scan: Scan) -> list[Message]:
    """Return all messages tied to this scan (either directly or via sender domain match)."""
    # Primary: direct scan_id link
    q = select(Message).where(Message.scan_id == scan.id).order_by(Message.received_at.asc())
    res = await session.execute(q)
    msgs = list(res.scalars().all())

    # Auxiliary: inbound mails from the scan's target_domain that landed without
    # a scan_id link — surface them as "likely related". Keep IDs dedup'd.
    seen = {m.id for m in msgs}
    q2 = select(Message).where(
        Message.direction == "inbound",
        Message.scan_id.is_(None),
        Message.from_addr.ilike(f"%@{scan.target_domain}"),
    ).order_by(Message.received_at.asc())
    res2 = await session.execute(q2)
    for m in res2.scalars().all():
        if m.id not in seen:
            msgs.append(m)
    # Final sort by received_at
    msgs.sort(key=lambda m: m.received_at or datetime.min.replace(tzinfo=timezone.utc))
    return msgs


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(
    request: Request, scan_id: str, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    kbv = build_kbv_summary(scan.result)
    dashboard = build_dashboard(scan.result)
    contact, offer = _contact_and_offer(scan)
    messages = await _messages_for_scan(session, scan)
    episodes = await _episodes_for_scan(session, scan)
    followup = _followup_state(scan, messages)
    return await _tpl(
        request, session, "scan_detail.html",
        {"scan": scan, "kbv": kbv, "dashboard": dashboard,
         "contact": contact, "offer": offer, "format_eur": format_eur,
         "messages": messages, "episodes": episodes, "followup": followup},
    )


@router.get("/scans/{scan_id}/status", response_class=HTMLResponse)
async def scan_status_fragment(
    request: Request, scan_id: str, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    kbv = build_kbv_summary(scan.result)
    dashboard = build_dashboard(scan.result)
    contact, offer = _contact_and_offer(scan)
    messages = await _messages_for_scan(session, scan)
    episodes = await _episodes_for_scan(session, scan)
    followup = _followup_state(scan, messages)
    return templates.TemplateResponse(
        request, "partials/scan_status.html",
        {"scan": scan, "kbv": kbv, "dashboard": dashboard,
         "contact": contact, "offer": offer, "format_eur": format_eur,
         "messages": messages, "episodes": episodes, "followup": followup},
    )


@router.get("/inbox", response_class=HTMLResponse)
async def inbox(
    request: Request,
    session: AsyncSession = Depends(get_session),
    direction: str = "",
    q: str = "",
    unread: int = 0,
    page: int = 1,
) -> HTMLResponse:
    from sqlalchemy import and_, func, or_
    PER_PAGE = 50
    page = max(1, page)

    where = []
    if direction in ("inbound", "outbound"):
        where.append(Message.direction == direction)
    if unread:
        where.append(and_(Message.direction == "inbound", Message.read_at.is_(None)))
    if q:
        needle = f"%{q.strip()}%"
        where.append(or_(
            Message.subject.ilike(needle),
            Message.from_addr.ilike(needle),
            Message.to_addr.ilike(needle),
            Message.body_text.ilike(needle),
        ))

    count_stmt = select(func.count(Message.id))
    if where:
        count_stmt = count_stmt.where(and_(*where))
    total = (await session.execute(count_stmt)).scalar() or 0
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = min(page, total_pages)

    list_stmt = select(Message).order_by(Message.received_at.desc()).limit(PER_PAGE).offset((page - 1) * PER_PAGE)
    if where:
        list_stmt = list_stmt.where(and_(*where))
    messages = list((await session.execute(list_stmt)).scalars().all())

    scan_ids = {m.scan_id for m in messages if m.scan_id}
    scans_by_id: dict[str, Scan] = {}
    if scan_ids:
        q2 = select(Scan).where(Scan.id.in_(scan_ids))
        res2 = await session.execute(q2)
        for s in res2.scalars():
            scans_by_id[s.id] = s

    # Draft counters for the banner: how many AI drafts are waiting for action?
    draft_counts = {"dry_run": 0, "forward": 0}
    for action in ("dry_run", "forward"):
        c = (await session.execute(
            select(func.count(Message.id)).where(
                Message.direction == "inbound", Message.bot_action == action
            )
        )).scalar() or 0
        draft_counts[action] = c

    # Pending scheduled replies: show them in a banner so the user can cancel
    # before they go out. Sorted ascending by due time so the next one is on top.
    q_sched = select(ScheduledEmail).where(
        ScheduledEmail.status == "queued"
    ).order_by(ScheduledEmail.scheduled_for.asc()).limit(20)
    scheduled_pending = list((await session.execute(q_sched)).scalars().all())

    return await _tpl(
        request, session, "inbox.html",
        {
            "messages": messages, "scans_by_id": scans_by_id,
            "direction_filter": direction, "q": q, "unread_only": bool(unread),
            "page": page, "total_pages": total_pages, "total": total,
            "draft_counts": draft_counts,
            "scheduled_pending": scheduled_pending,
        },
    )


@router.post("/inbox/mark-all-read")
async def inbox_mark_all_read(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Response:
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")
    from sqlalchemy import update
    await session.execute(
        update(Message)
        .where(Message.direction == "inbound", Message.read_at.is_(None))
        .values(read_at=datetime.now(timezone.utc))
    )
    await session.commit()
    return RedirectResponse(url="/inbox", status_code=303)


@router.get("/messages/{message_id}", response_class=HTMLResponse)
async def message_detail(
    request: Request, message_id: str, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    msg = await session.get(Message, message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Nachricht nicht gefunden")
    # Auto-mark inbound messages as read on view.
    if msg.direction == "inbound" and msg.read_at is None:
        msg.read_at = datetime.now(timezone.utc)
        await session.commit()
    scan = await session.get(Scan, msg.scan_id) if msg.scan_id else None
    return await _tpl(
        request, session, "message_detail.html",
        {"msg": msg, "scan": scan},
    )


def _build_draft_prompt(msg: Message, scan: Scan | None, thread: list[Message]) -> tuple[str, str]:
    """Return (system_prompt, user_prompt) for the LLM to draft a reply."""
    system = (
        "Du bist Daniel Rupp, Geschäftsführer der Advanced Analytics GmbH (Marke: ZDKG — Zentrum für "
        "Digitale Kommunikation und Governance), einem IT-Sicherheits- und Compliance-Beratungsunternehmen "
        "in Göttingen. Du antwortest professionell, höflich und in präzisem Deutsch mit Sie-Form auf "
        "E-Mails von Kunden und Interessenten — meistens Medizinische Versorgungszentren, Arztpraxen und "
        "regulierte Institutionen.\n\n"
        "HARTE REGELN (nicht verletzen):\n"
        "1. ERFINDE NICHTS. Nenne KEINE CVE-Nummern, KEINE Versionsnummern, KEINE Zahl konkreter Befunde, "
        "KEINE Preise, KEINE Termine — außer sie stehen WÖRTLICH im unten gelieferten Kontext. "
        "Wenn ein Detail nicht im Kontext steht, lasse es weg oder schreibe vage ('zum Beispiel im "
        "Bereich E-Mail-Authentifizierung', 'in der Priorisierung der kritischen Befunde', etc.).\n"
        "2. Wenn KEIN Scan-Kontext mit konkreten Befunden mitgeliefert ist, erwähne KEINE spezifischen "
        "Scan-Ergebnisse. Antworte dann rein auf die Mail-Anfrage.\n"
        "3. Immer Sie-Form, niemals Du. Auch wenn der Kunde Du schreibt.\n\n"
        "FORM:\n"
        "- Kompakt (3–5 Absätze), keine Floskeln, klarer Tonfall.\n"
        "- Bei unklaren Fragen biete ein kurzes Gespräch (Telefon +49 176 43677735 oder Videocall) an.\n"
        "- Grußformel am Ende: 'Mit freundlichen Grüßen\\n\\nDaniel Rupp\\nAdvanced Analytics GmbH — ZDKG'.\n"
        "- Ausgabe: reiner Mail-Text, keine Markdown-Formatierung, keine ```-Fences, keine Präambel wie "
        "'Hier ist der Entwurf:'. Schreibe direkt den Mail-Body."
    )

    scan_context = ""
    if scan:
        scan_context = (
            f"Zugehöriger Scan:\n"
            f"  Institution: {scan.institution_name}\n"
            f"  Domain:      {scan.target_domain}\n"
            f"  Status:      {scan.status}\n"
        )
        try:
            findings = (scan.result or {}).get("findings") or []
            sev_counts: dict[str, int] = {}
            for f in findings:
                sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1
            if sev_counts:
                parts = [f"{v} {k}" for k, v in sorted(sev_counts.items())]
                scan_context += f"  Befunde:     {', '.join(parts)}\n"
            # Include top 5 titles — they often relate to what the customer is asking about.
            top = [f for f in findings if f.get("severity") in ("critical", "high")][:5]
            if top:
                scan_context += "  Top-Befunde:\n"
                for f in top:
                    scan_context += f"    - [{f.get('severity')}] {f.get('title')}\n"
        except Exception:  # noqa: BLE001
            pass

    thread_context = ""
    if thread:
        thread_context = "\nBisheriger E-Mail-Verlauf (älteste zuerst):\n"
        for t in thread[-4:]:  # last 4 messages for context
            if t.id == msg.id:
                continue
            direction_label = "WIR schrieben" if t.direction == "outbound" else f"KUNDE ({t.from_addr}) schrieb"
            body_snip = (t.body_text or "")[:800]
            thread_context += (
                f"\n--- {direction_label} am {t.received_at.strftime('%d.%m.%Y %H:%M') if t.received_at else '?'} "
                f"zum Thema '{t.subject or ''}':\n{body_snip}\n"
            )

    user_prompt = (
        f"{scan_context}{thread_context}\n"
        f"Aktuelle Mail des Kunden (zu beantworten):\n"
        f"  Von: {msg.from_addr}\n"
        f"  Betreff: {msg.subject or ''}\n"
        f"  Zeitpunkt: {msg.received_at.strftime('%d.%m.%Y %H:%M') if msg.received_at else ''}\n\n"
        f"{(msg.body_text or '(kein Text)')[:4000]}\n\n"
        f"Schreibe jetzt den Antwort-Mail-Text."
    )
    return system, user_prompt


def _fallback_draft(msg: Message, scan: Scan | None) -> str:
    """Plain template when LLM is off or errors out."""
    greeting = "Sehr geehrte Damen und Herren"
    if msg.from_addr:
        greeting = f"Sehr geehrte(r) {msg.from_addr.split('@')[0].replace('.', ' ').title()}"
    return (
        f"{greeting},\n\n"
        "vielen Dank für Ihre Nachricht. Wir werden uns umgehend mit Ihrem Anliegen "
        "beschäftigen und melden uns mit einer Antwort zurück.\n\n"
        "Bei Rückfragen erreichen Sie uns jederzeit unter +49 176 43677735 "
        "oder per Antwort auf diese Mail.\n\n"
        "Mit freundlichen Grüßen\n"
        "Daniel Rupp\n"
        "Advanced Analytics GmbH — ZDKG"
    )


def _build_followup_prompt(scan: Scan, last_out: Message, days_since: int) -> tuple[str, str]:
    """System + user prompt for a firmer follow-up after FOLLOWUP_OVERDUE_DAYS of silence.

    The tone is "bestimmt, sachlich, mit Verweis auf konkrete Verstöße" — not
    aggressive, not threatening, but unmistakably geschäftsförmlich and with
    a deadline. ERFINDE NICHTS is still in force.
    """
    system = (
        "Du bist Daniel Rupp, Geschäftsführer der Advanced Analytics GmbH (ZDKG). "
        "Du schreibst eine FOLGEMAIL an eine Institution, die auf deine erste Mail "
        f"(Scan-Bericht + Angebot) seit {days_since} Tagen nicht geantwortet hat. "
        "Die Tonalität ist bestimmt und geschäftsförmlich — deutlich kühler als die erste Mail, "
        "aber nie unhöflich und NICHT drohend.\n\n"
        "HARTE REGELN:\n"
        "1. ERFINDE NICHTS. Nur Befunde, die WÖRTLICH im Kontext unten stehen, dürfen referenziert "
        "   werden. KEINE CVE-Nummern, KEINE Versionen, KEINE Zahlen über das hinaus was mitgeliefert wird.\n"
        "2. Nenne die konkret festgestellten Verstöße nochmal klar benannt (severity + Titel jeweils "
        "   auf eine Zeile). Wenn KRITISCHE oder HOHE Befunde vorliegen, benenne diese explizit oben "
        "   als ‚kritische Sicherheitsmängel' bzw. ‚hohe Risiken'.\n"
        "3. Weise sachlich darauf hin, dass unbehandelte Mängel dieser Art unter KBV §390 SGB V, DSGVO "
        "   Art. 32 und ggf. NIS2 regelmäßig bußgeld- und haftungsrelevant sind — ohne konkrete Bußgeldhöhen "
        "   zu nennen. Keine Drohungen, keine Ultimaten, die wir nicht einhalten könnten.\n"
        "4. Setze eine konkrete, moderate Frist für eine Rückmeldung (z.B. ‚in den kommenden 7 Werktagen').\n"
        "5. Biete am Ende einen kurzen Rückruf/Videocall an (Telefon +49 176 43677735).\n"
        "6. Immer Sie-Form. Kein Du.\n\n"
        "FORM:\n"
        "- 3–5 Absätze. Keine Floskeln. Keine Markdown. Keine ```-Fences.\n"
        "- Betreff baut auf dem letzten Mailbetreff auf (Präfix ‚Folgemail: ' oder ‚Erinnerung: ').\n"
        "- Grußformel: ‚Mit freundlichen Grüßen\\n\\nDaniel Rupp\\nAdvanced Analytics GmbH — ZDKG'.\n"
        "- Ausgabe: direkt der Mail-Body — kein Betreff im Output, keine Präambel."
    )
    findings = (scan.result or {}).get("findings") or []
    critical = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    medium = [f for f in findings if f.get("severity") == "medium"]
    lines = []
    lines.append(f"Scan: {scan.institution_name} / {scan.target_domain}")
    lines.append(f"Letzte Mail an den Kunden: {last_out.received_at.strftime('%d.%m.%Y') if last_out.received_at else '?'} — Betreff: {last_out.subject or '(ohne Betreff)'}")
    lines.append(f"Seitdem keine Antwort eingegangen (Stand: {days_since} Tage).")
    lines.append("")
    if critical:
        lines.append(f"KRITISCHE Befunde ({len(critical)}):")
        for f in critical[:8]:
            lines.append(f"  - {f.get('title')}")
    if high:
        lines.append(f"HOHE Befunde ({len(high)}):")
        for f in high[:8]:
            lines.append(f"  - {f.get('title')}")
    if medium and not critical and not high:
        lines.append(f"MITTLERE Befunde ({len(medium)}):")
        for f in medium[:5]:
            lines.append(f"  - {f.get('title')}")
    if not (critical or high or medium):
        lines.append("(Es liegen aktuell keine als kritisch/hoch/mittel eingestuften Befunde vor.)")
    lines.append("")
    lines.append("Letzte ausgehende Mail (Auszug):")
    lines.append((last_out.body_text or "(kein Text)")[:1500])
    user_prompt = "\n".join(lines) + "\n\nSchreibe jetzt den Mail-Body der Folgemail."
    return system, user_prompt


def _fallback_followup(scan: Scan, last_out: Message, days_since: int) -> str:
    """Deterministic follow-up text if the LLM is off/errored."""
    findings = (scan.result or {}).get("findings") or []
    critical = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    bullet_lines: list[str] = []
    for f in critical[:6]:
        bullet_lines.append(f"  • [KRITISCH] {f.get('title')}")
    for f in high[:6]:
        bullet_lines.append(f"  • [HOCH] {f.get('title')}")
    findings_block = "\n".join(bullet_lines) if bullet_lines else "  (siehe beigefügten Prüfbericht)"
    return (
        f"Sehr geehrte Damen und Herren,\n\n"
        f"wir hatten Ihnen am {last_out.received_at.strftime('%d.%m.%Y') if last_out.received_at else '?'} "
        f"unseren Prüfbericht mit konkretem Handlungsvorschlag übermittelt. Seitdem sind "
        f"{days_since} Tage vergangen, ohne dass uns eine Rückmeldung erreicht hat.\n\n"
        f"Unabhängig davon bleiben die festgestellten Mängel unverändert bestehen. "
        f"Dies betrifft insbesondere folgende Befunde:\n\n"
        f"{findings_block}\n\n"
        f"Mängel dieser Art fallen in den Regelungsbereich von KBV §390 SGB V, DSGVO Art. 32 und — "
        f"bei wesentlichen/wichtigen Einrichtungen im Gesundheitssektor — NIS2UmsuCG. "
        f"Eine fortgesetzte Nichtbearbeitung ist haftungs- und aufsichtsrechtlich heikel.\n\n"
        f"Wir bitten um eine Rückmeldung innerhalb der kommenden 7 Werktage — gerne telefonisch "
        f"unter +49 176 43677735 oder per Antwort auf diese Mail. Sollten Sie Rückfragen zum "
        f"Bericht oder zum Angebot haben, klären wir diese in einem kurzen Gespräch.\n\n"
        f"Mit freundlichen Grüßen\n\n"
        f"Daniel Rupp\n"
        f"Advanced Analytics GmbH — ZDKG"
    )


@router.get("/scans/{scan_id}/followup", response_class=HTMLResponse)
async def followup_compose(
    request: Request, scan_id: str, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    messages = await _messages_for_scan(session, scan)
    state = _followup_state(scan, messages)
    if not state:
        # Let the user still reach the page even if not strictly "overdue" —
        # show a gentle hint. But if no outbound at all, 400.
        has_outbound = any(m.direction == "outbound" for m in messages)
        if not has_outbound:
            raise HTTPException(status_code=400, detail="Keine ausgehende Mail vorhanden, auf die folgemailbar wäre.")
    last_out = state["last_outbound"] if state else next(
        (m for m in sorted(
            (x for x in messages if x.direction == "outbound"),
            key=lambda x: x.received_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )),
        None,
    )
    days_since = state["days_since"] if state else ((datetime.now(timezone.utc) - last_out.received_at).days if last_out and last_out.received_at else 0)
    recipient = (state or {}).get("recipient") or (last_out.to_addr.split(",")[0].strip() if last_out and last_out.to_addr else "")

    from app import llm
    draft = _fallback_followup(scan, last_out, days_since)
    if llm.is_enabled():
        try:
            sysp, userp = _build_followup_prompt(scan, last_out, days_since)
            ai = llm.draft(sysp, userp, scan_id=scan.id)
            if ai and ai.strip():
                draft = ai.strip()
        except Exception:  # noqa: BLE001
            pass

    suggested_subject = last_out.subject or ""
    if suggested_subject and not suggested_subject.lower().startswith(("folgemail", "erinnerung", "re:")):
        suggested_subject = f"Folgemail: {suggested_subject}"
    elif not suggested_subject:
        suggested_subject = f"Folgemail zum Prüfbericht {scan.target_domain}"

    return await _tpl(
        request, session, "followup_compose.html",
        {
            "scan": scan, "last_out": last_out, "days_since": days_since,
            "recipient": recipient, "draft": draft, "suggested_subject": suggested_subject,
            "state": state,
        },
    )


@router.post("/scans/{scan_id}/send-followup")
async def send_followup(
    request: Request,
    scan_id: str,
    subject: str = Form(...),
    body: str = Form(...),
    to: str = Form(...),
    cc: str = Form(""),
    scheduled_for: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> Response:
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")

    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    if not to.strip():
        raise HTTPException(status_code=400, detail="Empfänger fehlt")

    from app import mailer
    if not mailer.is_enabled():
        raise HTTPException(status_code=503, detail="SMTP nicht konfiguriert")

    # Thread into the last outbound so the follow-up is visibly a continuation.
    messages = await _messages_for_scan(session, scan)
    outbounds = [m for m in messages if m.direction == "outbound"]
    last_out = max(outbounds, key=lambda m: m.received_at or datetime.min.replace(tzinfo=timezone.utc)) if outbounds else None
    in_reply_to = last_out.message_id if last_out else None
    refs = None
    if last_out:
        refs_parts = [p for p in [(last_out.references or ""), (last_out.message_id or "")] if p]
        refs = " ".join(refs_parts).strip() or None

    send_at = _parse_scheduled_for(scheduled_for)
    if send_at is not None:
        sched = ScheduledEmail(
            inbound_message_id=None,
            scan_id=scan.id,
            to_addr=to.strip(),
            cc_addr=cc.strip() or None,
            subject=subject,
            body_text=body,
            in_reply_to=in_reply_to,
            references=refs,
            scheduled_for=send_at,
            status="queued",
        )
        session.add(sched)
        await session.commit()
        local_str = send_at.astimezone().strftime("%d.%m.%Y %H:%M")
        if request.headers.get("hx-request"):
            return HTMLResponse(
                '<div class="rounded-lg bg-amber-50 border border-amber-200 p-4 text-sm text-amber-900">'
                f'Folgemail geplant für <strong>{local_str}</strong> — geht automatisch an {to.strip()}.'
                '</div>'
            )
        return RedirectResponse(url=f"/scans/{scan.id}", status_code=303)

    try:
        rec = mailer.send_offer_email(
            to_email=to.strip(),
            subject=subject,
            body_text=body,
            attachments=[],
            cc=cc.strip() or None,
            in_reply_to=in_reply_to,
            references=refs,
        )
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SMTP-Fehler: {type(e).__name__}: {e}")

    session.add(Message(
        scan_id=scan.id,
        direction="outbound",
        message_id=rec["message_id"],
        in_reply_to=rec["in_reply_to"],
        references=rec["references"],
        from_addr=rec["from_addr"],
        to_addr=rec["to_addr"],
        cc_addr=rec["cc"],
        subject=rec["subject"],
        body_text=rec["body_text"],
    ))
    await session.commit()
    if request.headers.get("hx-request"):
        return HTMLResponse(
            '<div class="rounded-lg bg-emerald-50 border border-emerald-200 p-4 text-sm text-emerald-900">'
            f'Folgemail an {to.strip()} gesendet.'
            '</div>'
        )
    return RedirectResponse(url=f"/scans/{scan.id}", status_code=303)


@router.post("/messages/{message_id}/draft-reply", response_class=HTMLResponse)
async def draft_reply(
    request: Request, message_id: str, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")

    msg = await session.get(Message, message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Nachricht nicht gefunden")
    if msg.direction != "inbound":
        raise HTTPException(status_code=400, detail="Antworten nur auf eingehende Mails")

    scan = await session.get(Scan, msg.scan_id) if msg.scan_id else None
    # Thread context: same scan OR same In-Reply-To chain.
    thread: list[Message] = []
    if scan:
        q = select(Message).where(Message.scan_id == scan.id).order_by(Message.received_at.asc())
        res = await session.execute(q)
        thread = list(res.scalars().all())

    from app import llm
    try:
        if llm.is_enabled():
            system, user_prompt = _build_draft_prompt(msg, scan, thread)
            draft = llm.draft(system, user_prompt, scan_id=msg.scan_id)
            if not draft.strip():
                draft = _fallback_draft(msg, scan)
        else:
            draft = _fallback_draft(msg, scan)
    except llm.BudgetExceeded as e:
        draft = (
            _fallback_draft(msg, scan)
            + f"\n\n[Hinweis: KI-Entwurf deaktiviert — {e}. Sie können dennoch "
            "manuell antworten.]"
        )
    except Exception as e:  # noqa: BLE001
        draft = _fallback_draft(msg, scan) + f"\n\n[Hinweis: KI-Entwurf fehlgeschlagen — {type(e).__name__}]"

    # Return a JSON-safe text payload. The UI swaps this straight into the textarea value.
    return HTMLResponse(draft)


def _parse_scheduled_for(raw: str | None) -> datetime | None:
    """Parse the scheduled_for form field.

    Accepts ISO 8601 with or without timezone. Bare datetime-local values
    (no tz) are assumed to be Europe/Berlin — that's what the browser
    <input type="datetime-local"> emits. Returns None if empty / invalid /
    in the past (caller treats None as 'send now').
    """
    if not raw or not raw.strip():
        return None
    raw = raw.strip()
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # datetime-local is local wall-clock — treat as Europe/Berlin.
        try:
            from zoneinfo import ZoneInfo
            dt = dt.replace(tzinfo=ZoneInfo("Europe/Berlin"))
        except Exception:  # noqa: BLE001
            dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    # A time ≤ now + 30s is treated as "send now" (avoids flaky dispatcher races).
    if dt <= datetime.now(timezone.utc) + timedelta(seconds=30):
        return None
    return dt


@router.post("/messages/{message_id}/send-reply")
async def send_reply(
    request: Request,
    message_id: str,
    subject: str = Form(...),
    body: str = Form(...),
    cc: str = Form(""),
    scheduled_for: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> Response:
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")

    msg = await session.get(Message, message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Nachricht nicht gefunden")
    if msg.direction != "inbound" or not msg.from_addr:
        raise HTTPException(status_code=400, detail="Antworten nur auf eingehende Mails mit Absender")

    from app import mailer
    if not mailer.is_enabled():
        raise HTTPException(status_code=503, detail="SMTP nicht konfiguriert")

    # Thread headers: point In-Reply-To at the original Message-ID, append to References.
    refs = (msg.references or "") + (" " + msg.message_id if msg.message_id else "")
    refs = refs.strip() or None

    # Scheduled path: park the reply and let the poller tick dispatch it.
    send_at = _parse_scheduled_for(scheduled_for)
    if send_at is not None:
        sched = ScheduledEmail(
            inbound_message_id=msg.id,
            scan_id=msg.scan_id,
            to_addr=msg.from_addr,
            cc_addr=cc or None,
            subject=subject,
            body_text=body,
            in_reply_to=msg.message_id,
            references=refs,
            scheduled_for=send_at,
            status="queued",
        )
        session.add(sched)
        await session.commit()
        local_str = send_at.astimezone().strftime("%d.%m.%Y %H:%M")
        if request.headers.get("hx-request"):
            return HTMLResponse(
                '<div class="rounded-lg bg-amber-50 border border-amber-200 p-4 text-sm text-amber-900">'
                f'Antwort geplant für <strong>{local_str}</strong> — wird automatisch an '
                f'{msg.from_addr} versendet.'
                '</div>'
            )
        target = f"/scans/{msg.scan_id}" if msg.scan_id else "/inbox"
        return RedirectResponse(url=target, status_code=303)

    try:
        rec = mailer.send_offer_email(
            to_email=msg.from_addr,
            subject=subject,
            body_text=body,
            attachments=[],
            cc=cc or None,
            in_reply_to=msg.message_id,
            references=refs,
        )
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SMTP-Fehler: {type(e).__name__}: {e}")

    session.add(Message(
        scan_id=msg.scan_id,
        direction="outbound",
        message_id=rec["message_id"],
        in_reply_to=rec["in_reply_to"],
        references=rec["references"],
        from_addr=rec["from_addr"],
        to_addr=rec["to_addr"],
        cc_addr=rec["cc"],
        subject=rec["subject"],
        body_text=rec["body_text"],
    ))
    await session.commit()

    if request.headers.get("hx-request"):
        return HTMLResponse(
            '<div class="rounded-lg bg-emerald-50 border border-emerald-200 p-4 text-sm text-emerald-900">'
            f'Antwort an {msg.from_addr} gesendet.'
            '</div>'
        )
    # Redirect back to the scan if we have one, else inbox.
    target = f"/scans/{msg.scan_id}" if msg.scan_id else "/inbox"
    return RedirectResponse(url=target, status_code=303)


@router.post("/scans/{scan_id}/review/unlock")
async def unlock_scan_review(
    request: Request, scan_id: str, session: AsyncSession = Depends(get_session)
) -> Response:
    """Human-override: flip review_verdict='issues' to 'clean' after manual check.

    Writing a short reason is required so the audit trail is meaningful.
    """
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")

    form = await request.form()
    reason = (form.get("reason") or "").strip()[:500]
    if not reason:
        raise HTTPException(status_code=400, detail="Grund der Freigabe ist Pflicht.")

    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    if scan.review_verdict != "issues":
        return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)

    existing = scan.review_summary or ""
    scan.review_verdict = "clean"
    scan.review_summary = (
        f"[Manuell freigegeben von {user.email} am "
        f"{datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')}]\n"
        f"Grund: {reason}\n\n---\nUrsprüngliches AI-Urteil:\n{existing}"
    )
    await session.commit()
    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


@router.post("/scheduled/cancel-all")
async def cancel_all_scheduled(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Response:
    """Bulk-cancel every queued ScheduledEmail in the system.

    Use case: a batch has been queued but the user wants to stop ALL pending
    sends before they go out (e.g. found a bug, wants to re-scan). Auth-gated
    so a misclick is impossible without login.
    """
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")

    from sqlalchemy import update as _sql_update
    res = await session.execute(
        _sql_update(ScheduledEmail)
        .where(ScheduledEmail.status == "queued")
        .values(status="cancelled",
                error_message=f"bulk-cancelled by {user.email} at {datetime.now(timezone.utc).isoformat()}")
    )
    await session.commit()
    count = res.rowcount or 0
    if request.headers.get("hx-request"):
        return HTMLResponse(
            f'<div class="rounded-lg bg-emerald-50 border border-emerald-200 p-4 text-sm text-emerald-900">'
            f'{count} geplante Nachricht(en) storniert.'
            '</div>'
        )
    return RedirectResponse(url="/inbox", status_code=303)


@router.post("/scheduled/{sched_id}/cancel")
async def cancel_scheduled(
    request: Request, sched_id: str, session: AsyncSession = Depends(get_session)
) -> Response:
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")

    sched = await session.get(ScheduledEmail, sched_id)
    if not sched:
        raise HTTPException(status_code=404, detail="Geplante Mail nicht gefunden")
    if sched.status != "queued":
        raise HTTPException(status_code=400, detail=f"Status ist '{sched.status}' — nicht mehr abbrechbar")

    sched.status = "cancelled"
    await session.commit()

    if request.headers.get("hx-request"):
        return Response(status_code=200)
    return RedirectResponse(url="/inbox", status_code=303)


@router.post("/messages/{message_id}/delete")
async def delete_message(
    request: Request, message_id: str, session: AsyncSession = Depends(get_session)
) -> Response:
    """Remove the message from the local DB only. Gmail/IMAP stays untouched."""
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")

    msg = await session.get(Message, message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Nachricht nicht gefunden")

    await session.delete(msg)
    await session.commit()

    # HTMX: return empty body so the caller can swap the row/container out.
    # Regular POST from message_detail: redirect to inbox.
    if request.headers.get("hx-request"):
        return Response(status_code=200)
    return RedirectResponse(url="/inbox", status_code=303)


@router.post("/inbox/poll")
async def inbox_poll(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Response:
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")
    # On-demand poll — runs synchronously in the request for quick feedback.
    from app.imap_poller import poll_once
    summary = await poll_once()
    if request.headers.get("hx-request"):
        new = summary.get("new", 0)
        if summary.get("error"):
            body = f'<div class="text-sm text-rose-700">Fehler: {summary["error"]}</div>'
        elif new:
            body = f'<div class="text-sm text-emerald-700">{new} neue Nachricht(en) abgerufen — Seite aktualisieren.</div>'
        else:
            body = '<div class="text-sm text-slate-500">Keine neuen Nachrichten.</div>'
        return HTMLResponse(body)
    return RedirectResponse(url="/inbox", status_code=303)


@router.post("/scans/{scan_id}/rescan")
async def rescan(
    request: Request, scan_id: str, session: AsyncSession = Depends(get_session)
) -> Response:
    """One-click re-run: clone the scan's settings as a new queued Scan row."""
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")
    orig = await session.get(Scan, scan_id)
    if not orig:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")

    new_scan = Scan(
        institution_name=orig.institution_name,
        target_domain=orig.target_domain,
        status="queued",
        progress=0,
        ownership_confirmed=True,  # inherit the original consent
        deep_scan=orig.deep_scan,
        rate_limit_test=orig.rate_limit_test,
        context=orig.context,
    )
    session.add(new_scan)
    await session.flush()
    new_id = new_scan.id
    await session.commit()

    scan_queue.enqueue(
        run_scan_job, new_id, orig.target_domain, orig.deep_scan, orig.rate_limit_test,
        job_id=f"scan-{new_id}",
    )
    return RedirectResponse(url=f"/scans/{new_id}", status_code=303)


@router.post("/scans/{scan_id}/delete")
async def delete_scan(
    request: Request, scan_id: str, session: AsyncSession = Depends(get_session)
) -> Response:
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")

    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")

    # Best-effort cancel of the RQ job (may not exist if it already finished or was killed).
    try:
        from rq.job import Job
        job = Job.fetch(f"scan-{scan_id}", connection=redis_conn)
        job.cancel()
        job.delete()
    except Exception:  # noqa: BLE001
        pass

    await session.delete(scan)
    await session.commit()

    # HTMX request: empty body removes the row. Direct browser POST: redirect home.
    if request.headers.get("hx-request"):
        return Response(status_code=200)
    return RedirectResponse(url="/", status_code=303)


def _render_scan_pdf(request: Request, scan: Scan) -> bytes:
    """Request-path wrapper — delegates to app.reports."""
    from app.reports import render_scan_pdf_bytes
    return render_scan_pdf_bytes(scan, str(request.base_url))


def _render_offer_pdf(request: Request, scan: Scan) -> bytes:
    """Request-path wrapper — delegates to app.reports."""
    from app.reports import render_offer_pdf_bytes
    return render_offer_pdf_bytes(scan, str(request.base_url))


@router.get("/scans/{scan_id}/offer.pdf")
async def scan_offer_pdf(
    request: Request, scan_id: str, session: AsyncSession = Depends(get_session)
) -> Response:
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail="Scan ist noch nicht abgeschlossen")
    pdf_bytes = _render_offer_pdf(request, scan)
    filename = f"angebot-{scan.target_domain}-{scan.id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/scans/{scan_id}/send_offer")
async def send_offer_email(
    request: Request,
    scan_id: str,
    to_email: str = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
    cc: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> Response:
    user = await get_current_user(request, session)
    if user is None:
        raise HTTPException(status_code=401, detail="Login erforderlich")

    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail="Scan ist noch nicht abgeschlossen")

    from app import mailer
    if not mailer.is_enabled():
        raise HTTPException(
            status_code=503,
            detail="SMTP ist nicht konfiguriert. In der Umgebung SMTP_HOST etc. setzen.",
        )

    # Re-render both PDFs freshly — cheapest way to guarantee they match current DB state.
    scan_pdf = _render_scan_pdf(request, scan)
    offer_pdf = _render_offer_pdf(request, scan)

    attachments = [
        (f"angebot-{scan.target_domain}-{scan.id[:8]}.pdf", offer_pdf, "application/pdf"),
        (f"pruefbericht-{scan.target_domain}-{scan.id[:8]}.pdf", scan_pdf, "application/pdf"),
    ]

    try:
        send_record = mailer.send_offer_email(
            to_email=to_email,
            subject=subject,
            body_text=body,
            attachments=attachments,
            cc=cc or None,
        )
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SMTP-Fehler: {type(e).__name__}: {e}")

    # Persist the outbound message so future inbound replies can be threaded to
    # this scan via In-Reply-To matching.
    session.add(Message(
        scan_id=scan_id,
        direction="outbound",
        message_id=send_record["message_id"],
        from_addr=send_record["from_addr"],
        to_addr=send_record["to_addr"],
        cc_addr=send_record["cc"],
        subject=send_record["subject"],
        body_text=send_record["body_text"],
        attachments_meta=send_record["attachments_meta"],
    ))
    await session.commit()

    if request.headers.get("hx-request"):
        return HTMLResponse(
            '<div class="rounded-xl bg-emerald-50 border border-emerald-200 p-4 text-sm text-emerald-900">'
            f'E-Mail wurde erfolgreich an {to_email} versendet. Angebot und Prüfbericht sind als Anhang enthalten.'
            '</div>'
        )
    return RedirectResponse(url=f"/scans/{scan_id}?sent=1", status_code=303)


@router.get("/scans/{scan_id}/report.pdf")
async def scan_report_pdf(
    request: Request, scan_id: str, session: AsyncSession = Depends(get_session)
) -> Response:
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail="Scan ist noch nicht abgeschlossen")

    kbv = build_kbv_summary(scan.result)
    dashboard = build_dashboard(scan.result)
    generated_at = datetime.now(timezone.utc)

    html = templates.get_template("report_pdf.html").render(
        request=request, scan=scan, kbv=kbv, dashboard=dashboard, generated_at=generated_at
    )

    # Import WeasyPrint lazily so test environments without the system libs
    # can still import this module.
    from weasyprint import HTML  # type: ignore[import-not-found]

    pdf_bytes = HTML(string=html, base_url=str(request.base_url)).write_pdf()
    filename = f"mvz-scan-{scan.target_domain}-{scan.id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
