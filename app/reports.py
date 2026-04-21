"""Request-free PDF renderers.

Call sites: pages.py (has a Request — pass str(request.base_url)) AND the
batch dispatcher (no Request — pass settings-derived absolute URL).

Both helpers previously lived inline in pages.py and took a Request object
solely to read its base_url. Centralising them here avoids re-implementing
the weasyprint + Jinja plumbing in the dispatcher.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi.templating import Jinja2Templates

from app.compliance.analysis import build_kbv_summary
from app.compliance.dashboard import build_dashboard
from app.compliance.offer import build_offer, format_eur
from app.models import Scan

templates = Jinja2Templates(directory="app/templates")


def _contact_and_offer_pure(scan: Scan) -> tuple[dict, dict | None]:
    result = scan.result or {}
    contact = (result.get("metadata") or {}).get("impressum") or {}
    if not contact.get("emails"):
        harvested = (result.get("metadata") or {}).get("harvested_emails") or []
        if harvested:
            contact = {**contact, "emails": harvested[:5]}
    rate = (scan.context or {}).get("hourly_rate_eur") if scan.context else None
    offer = build_offer(result, hourly_rate_eur=rate) if scan.status == "completed" else None
    return contact, offer


def render_scan_pdf_bytes(scan: Scan, base_url: str) -> bytes:
    """Render report PDF without a FastAPI Request.

    `base_url` must end with "/". Example: "https://scan.zdkg.de/".
    The template reads `request.base_url` for font/image refs — a
    SimpleNamespace shim is enough.
    """
    kbv = build_kbv_summary(scan.result)
    dashboard = build_dashboard(scan.result)
    generated_at = datetime.now(timezone.utc)

    from app.compliance.report_ai import generate_executive_summary
    ai_summary = None
    try:
        ai_summary = generate_executive_summary(
            scan_id=scan.id,
            institution_name=scan.institution_name or "",
            target_domain=scan.target_domain,
            findings=list((scan.result or {}).get("findings") or []),
            result=scan.result,
        )
    except Exception:  # noqa: BLE001
        ai_summary = None

    req = SimpleNamespace(base_url=base_url)
    html = templates.get_template("report_pdf.html").render(
        request=req, scan=scan, kbv=kbv, dashboard=dashboard,
        generated_at=generated_at, ai_summary=ai_summary,
    )
    from weasyprint import HTML
    return HTML(string=html, base_url=base_url).write_pdf()


def render_offer_pdf_bytes(scan: Scan, base_url: str) -> bytes:
    """Render offer PDF without a FastAPI Request."""
    contact, offer = _contact_and_offer_pure(scan)
    generated_at = datetime.now(timezone.utc)
    valid_until = generated_at + timedelta(days=30)
    req = SimpleNamespace(base_url=base_url)
    html = templates.get_template("offer_pdf.html").render(
        request=req, scan=scan, contact=contact, offer=offer,
        generated_at=generated_at, valid_until=valid_until, format_eur=format_eur,
    )
    from weasyprint import HTML
    return HTML(string=html, base_url=base_url).write_pdf()
