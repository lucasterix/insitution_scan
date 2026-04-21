"""IMAP poller — fetches new mail, matches to scans, persists.

Runs as a standalone long-lived process (`python -m app.imap_poller`).
Connects to the configured IMAP server (default: imap.gmail.com:993 with
the same account used for outbound), pulls anything received in the
configured lookback window, dedupes against what's already stored, and
matches each new mail to a scan via:

  1. In-Reply-To / References → prior outbound message → scan_id
  2. Sender domain == scan.target_domain (or endswith .scan.target_domain)
  3. fallback: scan_id left NULL, visible only in the global inbox.

The poller is deliberately paranoid: it never deletes or re-flags mail,
it only reads. Connection failures log a warning and retry on the next
tick — no cascading failure.
"""
from __future__ import annotations

import asyncio
import email
import email.policy  # explicit — otherwise email.policy.default raises AttributeError
import email.utils
import imaplib
import logging
import time
import traceback
from datetime import datetime, timedelta, timezone
from email.header import decode_header, make_header
from email.message import EmailMessage

from sqlalchemy import select

from app.config import get_settings
from app.db import SessionLocal
from app.models import Message, Scan, ScheduledEmail

log = logging.getLogger("imap_poller")


# ---------- IMAP helpers ----------


def _decode_header(raw: str | None) -> str:
    if not raw:
        return ""
    try:
        return str(make_header(decode_header(raw)))
    except Exception:  # noqa: BLE001
        return raw


def _parse_addr(raw: str | None) -> str | None:
    if not raw:
        return None
    # email.utils handles "Name <addr@host>", lists, and folding.
    parsed = email.utils.getaddresses([raw])
    if not parsed:
        return None
    return parsed[0][1].strip().lower() or None


def _body_parts(msg: EmailMessage) -> tuple[str, str]:
    """Extract plain-text and HTML body. Attachments are ignored here."""
    text_parts: list[str] = []
    html_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disp:
                continue
            if ctype == "text/plain":
                try:
                    text_parts.append(part.get_content())
                except Exception:  # noqa: BLE001
                    payload = part.get_payload(decode=True) or b""
                    text_parts.append(payload.decode("utf-8", errors="replace"))
            elif ctype == "text/html":
                try:
                    html_parts.append(part.get_content())
                except Exception:  # noqa: BLE001
                    payload = part.get_payload(decode=True) or b""
                    html_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        try:
            text = msg.get_content() if msg.get_content_type() == "text/plain" else ""
            html = msg.get_content() if msg.get_content_type() == "text/html" else ""
        except Exception:  # noqa: BLE001
            payload = msg.get_payload(decode=True) or b""
            text = payload.decode("utf-8", errors="replace")
            html = ""
        if text:
            text_parts.append(text)
        if html:
            html_parts.append(html)
    return "\n\n".join(text_parts).strip()[:50_000], "\n\n".join(html_parts).strip()[:200_000]


def _attachments_meta(msg: EmailMessage) -> list[dict]:
    items: list[dict] = []
    if not msg.is_multipart():
        return items
    for part in msg.walk():
        disp = (part.get("Content-Disposition") or "").lower()
        if "attachment" not in disp:
            continue
        fn = _decode_header(part.get_filename() or "")
        payload = part.get_payload(decode=True) or b""
        items.append({
            "filename": fn,
            "size": len(payload),
            "mime": part.get_content_type(),
        })
    return items


# ---------- Matching ----------


async def _match_scan_id(session, from_addr: str | None, in_reply_to: str | None, references: str | None) -> str | None:
    # 1. By In-Reply-To → prior outbound message_id
    candidate_ids: list[str] = []
    if in_reply_to:
        candidate_ids.append(in_reply_to.strip())
    if references:
        for tok in references.split():
            tok = tok.strip()
            if tok and tok not in candidate_ids:
                candidate_ids.append(tok)

    if candidate_ids:
        q = select(Message.scan_id).where(
            Message.message_id.in_(candidate_ids),
            Message.direction == "outbound",
        )
        res = await session.execute(q)
        for (scan_id,) in res:
            if scan_id:
                return scan_id

    # 2. By sender domain → any scan for the matching target_domain
    if from_addr and "@" in from_addr:
        sender_domain = from_addr.rsplit("@", 1)[-1].lower()
        if sender_domain:
            q = select(Scan.id).where(Scan.target_domain == sender_domain).order_by(Scan.created_at.desc()).limit(1)
            res = await session.execute(q)
            for (scan_id,) in res:
                return scan_id
            # subdomain endswith match
            q = select(Scan.id).where(Scan.target_domain.ilike(f"%{sender_domain}")).order_by(Scan.created_at.desc()).limit(1)
            res = await session.execute(q)
            for (scan_id,) in res:
                return scan_id

    return None


# ---------- Core polling ----------


def _imap_connect() -> imaplib.IMAP4_SSL:
    s = get_settings()
    host = s.imap_host
    port = s.imap_port
    user = s.imap_user or s.smtp_user
    pw = s.imap_password or s.smtp_password
    if not (host and user and pw):
        raise RuntimeError("IMAP nicht konfiguriert")
    c = imaplib.IMAP4_SSL(host, port, timeout=30)
    c.login(user, pw)
    return c


def _fetch_since(conn: imaplib.IMAP4_SSL, folder: str, since_date: datetime) -> list[tuple[str, bytes]]:
    """Return list of (uid, raw_bytes) for mails received since since_date."""
    typ, _ = conn.select(folder, readonly=True)
    if typ != "OK":
        return []
    # IMAP date format is DD-Mon-YYYY
    date_str = since_date.strftime("%d-%b-%Y")
    typ, data = conn.uid("search", None, f"SINCE {date_str}")
    if typ != "OK" or not data or not data[0]:
        return []
    uids = data[0].split()
    if not uids:
        return []
    typ, msg_data = conn.uid("fetch", b",".join(uids), "(RFC822)")
    if typ != "OK" or not msg_data:
        return []
    out: list[tuple[str, bytes]] = []
    i = 0
    while i < len(msg_data):
        entry = msg_data[i]
        if isinstance(entry, tuple) and len(entry) >= 2:
            # entry[0] = b"<uid> (RFC822 {size}", entry[1] = raw bytes
            header_bytes = entry[0] if isinstance(entry[0], bytes) else entry[0].encode()
            # parse the UID out of "1234 (RFC822 {5678}"
            try:
                prefix = header_bytes.decode("ascii", errors="replace")
                uid = prefix.split()[0] if prefix else ""
            except Exception:  # noqa: BLE001
                uid = ""
            raw = entry[1]
            out.append((uid, raw))
        i += 1
    return out


async def _dispatch_due_scheduled() -> dict:
    """Send any ScheduledEmail rows whose scheduled_for <= now().

    Each row is handled independently — a mailer failure marks that one as
    'failed' with the error message but doesn't block the others.
    """
    from app import mailer
    if not mailer.is_enabled():
        return {"scheduled_checked": 0, "scheduled_sent": 0, "scheduled_skipped": "smtp-disabled"}

    now = datetime.now(timezone.utc)
    sent = 0
    failed = 0
    rows: list = []
    async with SessionLocal() as session:
        q = select(ScheduledEmail).where(
            ScheduledEmail.status == "queued",
            ScheduledEmail.scheduled_for <= now,
        ).limit(50)
        res = await session.execute(q)
        rows = list(res.scalars())
        for sched in rows:
            try:
                rec = mailer.send_offer_email(
                    to_email=sched.to_addr,
                    subject=sched.subject,
                    body_text=sched.body_text,
                    attachments=[],
                    cc=sched.cc_addr or None,
                    in_reply_to=sched.in_reply_to,
                    references=sched.references,
                )
            except Exception as e:  # noqa: BLE001
                sched.status = "failed"
                sched.error_message = f"{type(e).__name__}: {e}"[:500]
                failed += 1
                log.warning("scheduled send failed for %s: %s", sched.id, e)
                continue

            out_msg = Message(
                scan_id=sched.scan_id,
                direction="outbound",
                message_id=rec["message_id"],
                in_reply_to=rec["in_reply_to"],
                references=rec["references"],
                from_addr=rec["from_addr"],
                to_addr=rec["to_addr"],
                cc_addr=rec["cc"],
                subject=rec["subject"],
                body_text=rec["body_text"],
            )
            session.add(out_msg)
            await session.flush()
            sched.status = "sent"
            sched.sent_at = datetime.now(timezone.utc)
            sched.sent_message_id = out_msg.id
            sent += 1
        if rows:
            try:
                await session.commit()
            except Exception as e:  # noqa: BLE001
                await session.rollback()
                log.error("scheduled dispatch commit failed: %s", e)
    if sent or failed:
        log.info("scheduled dispatch: sent=%d failed=%d", sent, failed)
    return {"scheduled_checked": len(rows), "scheduled_sent": sent, "scheduled_failed": failed}


async def poll_once() -> dict:
    """Fetch any new mail from IMAP, persist + match. Returns a small summary dict."""
    s = get_settings()
    if not (s.imap_host and (s.imap_user or s.smtp_user) and (s.imap_password or s.smtp_password)):
        return {"skipped": "not-configured"}

    try:
        conn = _imap_connect()
    except Exception as e:  # noqa: BLE001
        log.warning("IMAP connect failed: %s: %s", type(e).__name__, e)
        return {"error": f"connect: {e}"}

    try:
        since = datetime.now(timezone.utc) - timedelta(days=s.imap_lookback_days)
        raw_items = _fetch_since(conn, s.imap_folder, since)
    finally:
        try:
            conn.logout()
        except Exception:  # noqa: BLE001
            pass

    if not raw_items:
        return {"checked": 0, "new": 0}

    new_count = 0
    errors = 0
    async with SessionLocal() as session:
        for uid, raw in raw_items:
            try:
                msg = email.message_from_bytes(raw, policy=email.policy.default)
            except Exception as e:  # noqa: BLE001
                errors += 1
                log.warning("parse failed for uid=%s: %s: %s", uid, type(e).__name__, e)
                continue

            msg_id = _decode_header(msg.get("Message-ID")) or None
            if msg_id:
                msg_id = msg_id.strip()

            # Dedup: skip if we already have this Message-ID.
            if msg_id:
                q = select(Message.id).where(Message.message_id == msg_id).limit(1)
                res = await session.execute(q)
                if res.first():
                    continue

            from_addr = _parse_addr(msg.get("From"))
            to_addr = _decode_header(msg.get("To")) or None
            cc_addr = _decode_header(msg.get("Cc")) or None
            subject = _decode_header(msg.get("Subject")) or None
            in_reply_to = (_decode_header(msg.get("In-Reply-To")) or "").strip() or None
            refs = _decode_header(msg.get("References")) or None
            date_hdr = msg.get("Date")
            received_at = None
            if date_hdr:
                try:
                    dt = email.utils.parsedate_to_datetime(date_hdr)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    received_at = dt
                except Exception:  # noqa: BLE001
                    pass

            body_text, body_html = _body_parts(msg)
            att_meta = _attachments_meta(msg)
            scan_id = await _match_scan_id(session, from_addr, in_reply_to, refs)

            new_msg = Message(
                scan_id=scan_id,
                direction="inbound",
                message_id=msg_id,
                in_reply_to=in_reply_to,
                references=refs,
                from_addr=from_addr,
                to_addr=(to_addr or "")[:1000],
                cc_addr=(cc_addr or "")[:1000] if cc_addr else None,
                subject=(subject or "")[:500] if subject else None,
                body_text=body_text or None,
                body_html=body_html or None,
                attachments_meta=att_meta or None,
                received_at=received_at or datetime.now(timezone.utc),
                raw_uid=(uid or "")[:64] or None,
            )
            session.add(new_msg)
            new_count += 1

        try:
            await session.commit()
            # Auto-reply hook: run synchronously after successful commit so the
            # bot sees the message in DB. Uses the sync engine — runs inside the
            # same RQ-worker / poller process. Failures in the bot never affect
            # the poller's success path (the message is already persisted).
            try:
                await _run_auto_replies_for_new_inbound(session, since_seconds=300)
            except Exception as e:  # noqa: BLE001
                log.warning("auto_reply batch failed: %s: %s", type(e).__name__, e)
        except Exception as e:  # noqa: BLE001
            await session.rollback()
            log.error("IMAP poll commit failed: %s: %s", type(e).__name__, e)
            log.error("traceback: %s", traceback.format_exc())
            return {"checked": len(raw_items), "new": 0, "errors": errors, "commit_error": str(e)[:200]}

    if new_count:
        log.info("IMAP poll: %d new message(s) stored", new_count)
    if errors:
        log.warning("IMAP poll: %d parse error(s) skipped", errors)

    # Send any scheduled replies whose time has arrived. Runs every tick so
    # the accuracy is bounded by IMAP_POLL_SECONDS (default ~120s).
    try:
        dispatch = await _dispatch_due_scheduled()
    except Exception as e:  # noqa: BLE001
        log.warning("dispatch_due_scheduled failed: %s: %s", type(e).__name__, e)
        dispatch = {"scheduled_error": str(e)[:200]}

    return {
        "checked": len(raw_items), "new": new_count, "errors": errors,
        **{k: v for k, v in dispatch.items() if v},
    }


# ---------- Entrypoint ----------


async def _run_auto_replies_for_new_inbound(async_session, since_seconds: int = 300) -> None:
    """After a poll cycle commits new inbound rows, fetch those that haven't
    been processed by the bot yet and push each through app.auto_reply.

    Runs on the sync SQLAlchemy engine — app.auto_reply is fully synchronous
    (calls smtplib, anthropic HTTP). Executed via asyncio.to_thread so it
    doesn't block the IMAP event loop.
    """
    import asyncio
    from sqlalchemy import create_engine, select as sync_select
    from sqlalchemy.orm import Session as SyncSession
    from app.auto_reply import process_inbound
    from app.config import get_settings as _gs

    s = _gs()
    if not s.auto_responder_enabled:
        return

    sync_url = s.database_url.replace("+asyncpg", "+psycopg") if "+asyncpg" in s.database_url else s.database_url

    def _blocking_work():
        engine = create_engine(sync_url, pool_pre_ping=True)
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=since_seconds)
        processed = 0
        with SyncSession(engine) as sync_s:
            q = sync_select(Message).where(
                Message.direction == "inbound",
                Message.bot_action.is_(None),
                Message.received_at >= cutoff,
            ).limit(20)
            msgs = list(sync_s.execute(q).scalars())
            for m in msgs:
                try:
                    outcome = process_inbound(sync_s, m)
                    sync_s.commit()
                    processed += 1
                    log.info("auto_reply: %s → %s (%s)", (m.from_addr or "?")[:40], outcome, (m.bot_reasoning or "")[:80])
                except Exception as e:  # noqa: BLE001
                    sync_s.rollback()
                    log.warning("auto_reply error for msg %s: %s", m.id, e)
        if processed:
            log.info("auto_reply batch: %d message(s) processed", processed)

    await asyncio.to_thread(_blocking_work)


def run_forever() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    log.info("imap_poller starting")
    s = get_settings()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    while True:
        try:
            summary = loop.run_until_complete(poll_once())
            if summary.get("error"):
                log.warning("poll error: %s", summary["error"])
        except Exception as e:  # noqa: BLE001
            log.exception("poll crashed: %s: %s", type(e).__name__, e)
        sleep_s = max(30, int(s.imap_poll_seconds))
        time.sleep(sleep_s)


if __name__ == "__main__":
    run_forever()
