from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.compliance.analysis import build_kbv_summary
from app.compliance.dashboard import build_dashboard
from app.compliance.offer import build_offer, format_eur
from app.db import get_session
from app.models import Message, Scan
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
    return await _tpl(
        request, session, "scan_detail.html",
        {"scan": scan, "kbv": kbv, "dashboard": dashboard,
         "contact": contact, "offer": offer, "format_eur": format_eur,
         "messages": messages},
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
    return templates.TemplateResponse(
        request, "partials/scan_status.html",
        {"scan": scan, "kbv": kbv, "dashboard": dashboard,
         "contact": contact, "offer": offer, "format_eur": format_eur,
         "messages": messages},
    )


@router.get("/inbox", response_class=HTMLResponse)
async def inbox(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    # Load last 200 messages across all scans, newest first.
    q = select(Message).order_by(Message.received_at.desc()).limit(200)
    res = await session.execute(q)
    messages = list(res.scalars().all())
    # Fetch associated scans in bulk for display links.
    scan_ids = {m.scan_id for m in messages if m.scan_id}
    scans_by_id: dict[str, Scan] = {}
    if scan_ids:
        q2 = select(Scan).where(Scan.id.in_(scan_ids))
        res2 = await session.execute(q2)
        for s in res2.scalars():
            scans_by_id[s.id] = s
    return await _tpl(
        request, session, "inbox.html",
        {"messages": messages, "scans_by_id": scans_by_id},
    )


@router.get("/messages/{message_id}", response_class=HTMLResponse)
async def message_detail(
    request: Request, message_id: str, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    msg = await session.get(Message, message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Nachricht nicht gefunden")
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
            draft = llm.draft(system, user_prompt)
            if not draft.strip():
                draft = _fallback_draft(msg, scan)
        else:
            draft = _fallback_draft(msg, scan)
    except Exception as e:  # noqa: BLE001
        draft = _fallback_draft(msg, scan) + f"\n\n[Hinweis: KI-Entwurf fehlgeschlagen — {type(e).__name__}]"

    # Return a JSON-safe text payload. The UI swaps this straight into the textarea value.
    return HTMLResponse(draft)


@router.post("/messages/{message_id}/send-reply")
async def send_reply(
    request: Request,
    message_id: str,
    subject: str = Form(...),
    body: str = Form(...),
    cc: str = Form(""),
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
    """Render the main scan report PDF (shared between download + email)."""
    kbv = build_kbv_summary(scan.result)
    dashboard = build_dashboard(scan.result)
    generated_at = datetime.now(timezone.utc)
    html = templates.get_template("report_pdf.html").render(
        request=request, scan=scan, kbv=kbv, dashboard=dashboard, generated_at=generated_at
    )
    from weasyprint import HTML  # lazy import
    return HTML(string=html, base_url=str(request.base_url)).write_pdf()


def _render_offer_pdf(request: Request, scan: Scan) -> bytes:
    """Render the offer/Angebot PDF (shared between download + email)."""
    from datetime import timedelta
    contact, offer = _contact_and_offer(scan)
    generated_at = datetime.now(timezone.utc)
    valid_until = generated_at + timedelta(days=30)
    html = templates.get_template("offer_pdf.html").render(
        request=request, scan=scan, contact=contact, offer=offer,
        generated_at=generated_at, valid_until=valid_until, format_eur=format_eur,
    )
    from weasyprint import HTML  # lazy import
    return HTML(string=html, base_url=str(request.base_url)).write_pdf()


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
