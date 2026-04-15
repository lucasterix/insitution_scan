from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Scan

router = APIRouter(prefix="/api", tags=["api"])


@router.get("/scans")
async def list_scans(session: AsyncSession = Depends(get_session)) -> list[dict]:
    result = await session.execute(select(Scan).order_by(Scan.created_at.desc()).limit(100))
    return [
        {
            "id": s.id,
            "institution_name": s.institution_name,
            "target_domain": s.target_domain,
            "status": s.status,
            "progress": s.progress,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in result.scalars().all()
    ]


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_session)) -> dict:
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    return {
        "id": scan.id,
        "institution_name": scan.institution_name,
        "target_domain": scan.target_domain,
        "status": scan.status,
        "progress": scan.progress,
        "current_step": scan.current_step,
        "error": scan.error,
        "result": scan.result,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    }
