from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.compliance.analysis import build_kbv_summary
from app.compliance.dashboard import build_dashboard
from app.db import get_session
from app.models import Scan
from app.queue import redis_conn, scan_queue
from app.scanners.osint import _normalize_domain
from app.tasks import run_scan_job

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


async def _tpl(request: Request, session: AsyncSession, template: str, ctx: dict) -> HTMLResponse:
    user = await get_current_user(request, session)
    ctx["current_user"] = user
    return templates.TemplateResponse(request, template, ctx)


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, session: AsyncSession = Depends(get_session)) -> HTMLResponse:
    result = await session.execute(select(Scan).order_by(Scan.created_at.desc()).limit(20))
    scans = result.scalars().all()
    return await _tpl(request, session, "index.html", {"scans": scans})


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


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(
    request: Request, scan_id: str, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    kbv = build_kbv_summary(scan.result)
    dashboard = build_dashboard(scan.result)
    return await _tpl(
        request, session, "scan_detail.html",
        {"scan": scan, "kbv": kbv, "dashboard": dashboard},
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
    return templates.TemplateResponse(
        request, "partials/scan_status.html", {"scan": scan, "kbv": kbv, "dashboard": dashboard}
    )


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
