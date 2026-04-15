from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Scan
from app.queue import scan_queue
from app.scanners.osint import _normalize_domain
from app.tasks import run_scan_job

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, session: AsyncSession = Depends(get_session)) -> HTMLResponse:
    result = await session.execute(select(Scan).order_by(Scan.created_at.desc()).limit(20))
    scans = result.scalars().all()
    return templates.TemplateResponse(request, "index.html", {"scans": scans})


@router.get("/scans/new", response_class=HTMLResponse)
async def new_scan_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "scan_new.html", {})


@router.post("/scans")
async def create_scan(
    request: Request,
    institution_name: str = Form(...),
    target_domain: str = Form(...),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    domain = _normalize_domain(target_domain)
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Ungültige Domain")

    scan = Scan(
        institution_name=institution_name.strip(),
        target_domain=domain,
        status="queued",
        progress=0,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    scan_queue.enqueue(run_scan_job, scan.id, domain, job_id=f"scan-{scan.id}")

    return RedirectResponse(url=f"/scans/{scan.id}", status_code=303)


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(
    request: Request, scan_id: str, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    return templates.TemplateResponse(request, "scan_detail.html", {"scan": scan})


@router.get("/scans/{scan_id}/status", response_class=HTMLResponse)
async def scan_status_fragment(
    request: Request, scan_id: str, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    return templates.TemplateResponse(request, "partials/scan_status.html", {"scan": scan})
