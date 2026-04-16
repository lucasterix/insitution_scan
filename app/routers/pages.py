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
from app.queue import scan_queue
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
    domain = _normalize_domain(target_domain)
    # Accept both domains (with dot) and IP addresses
    import ipaddress as _ipa
    is_valid_ip = False
    try:
        _ipa.ip_address(domain)
        is_valid_ip = True
    except ValueError:
        pass
    if not domain or (not is_valid_ip and "." not in domain):
        raise HTTPException(status_code=400, detail="Ungültige Domain oder IP-Adresse")

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

    scan = Scan(
        institution_name=institution_name.strip(),
        target_domain=domain,
        status="queued",
        progress=0,
        ownership_confirmed=True,
        deep_scan=is_deep,
        rate_limit_test=is_rate_test,
        context=context or None,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    scan_queue.enqueue(run_scan_job, scan.id, domain, is_deep, is_rate_test, job_id=f"scan-{scan.id}")

    return RedirectResponse(url=f"/scans/{scan.id}", status_code=303)


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
