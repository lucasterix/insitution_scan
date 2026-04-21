"""Auto-reply bot for inbound mail — classifies, then either answers in
Daniel Rupp's voice or forwards the thread to his fallback address.

Triggered from the IMAP poller once per new inbound message. Deterministic
pre-filters skip auto-replies, bulk mail, self-sent mail and anything the
LLM flagged at low confidence. A daily per-sender rate limit prevents
reply loops if we somehow end up in a bounce with another bot.

Three outcomes:
  · auto_reply  — we send a German Sie-form reply in Daniel's name,
                  properly threaded via In-Reply-To/References, recorded
                  as outbound Message in DB.
  · forward     — the raw body + headers are forwarded to
                  AUTO_RESPONDER_FORWARD_TO (default: daniel.rupp@froehlichdienste.de).
  · skip        — handled manually; we just stamp bot_action='skip' and move on.

When AUTO_RESPONDER_DRY_RUN=true nothing leaves the server; we only stamp
bot_action='dry_run' + reasoning so the user can audit decisions in the
inbox before flipping the flag to live.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import llm, mailer
from app.config import get_settings
from app.models import Message, Scan

log = logging.getLogger("auto_reply")


# ─── Deterministic pre-filters ──────────────────────────────────────────────


SELF_ADDR_KEYWORDS = ("daniel.rupp@zdkg.de", "info@zdkg.de", "datenschutz@zdkg.de", "security@zdkg.de")
BOUNCE_PREFIXES = ("mailer-daemon", "postmaster", "no-reply", "noreply", "donotreply", "do-not-reply")
# Loose heuristic: subjects that almost always indicate non-human traffic.
BULK_SUBJECT_HINTS = ("undelivered mail", "delivery status", "automatic reply", "out of office", "abwesenheitsnotiz")


def _is_from_self_or_bot(msg: Message) -> bool:
    fa = (msg.from_addr or "").lower().strip()
    if not fa:
        return True  # no sender → nothing to reply to
    if fa in SELF_ADDR_KEYWORDS:
        return True
    local = fa.split("@", 1)[0]
    if any(local.startswith(p) for p in BOUNCE_PREFIXES):
        return True
    # Common list/bulk indicators we can detect from stored fields
    subj = (msg.subject or "").lower()
    if any(h in subj for h in BULK_SUBJECT_HINTS):
        return True
    return False


def _rate_limited(session: Session, from_addr: str, max_per_day: int = 5) -> bool:
    """True when we've already auto-replied to this sender N times today."""
    if not from_addr:
        return True
    since = datetime.now(timezone.utc) - timedelta(days=1)
    q = select(func.count(Message.id)).where(
        Message.direction == "outbound",
        Message.to_addr.ilike(f"%{from_addr}%"),
        Message.bot_action == "auto_reply",
        Message.received_at >= since,
    )
    count = session.execute(q).scalar() or 0
    return count >= max_per_day


# ─── LLM classifier ─────────────────────────────────────────────────────────


CLASSIFIER_SYSTEM = (
    "Du bist der Assistent von Daniel Rupp, Geschäftsführer der Advanced Analytics GmbH "
    "(Marke: ZDKG — Zentrum für Digitale Kommunikation und Governance, IT-Sicherheit + "
    "Pentesting für MVZ, Arztpraxen, Ämter und Körperschaften des öffentlichen Rechts). "
    "Du bekommst eine eingehende Kunden-E-Mail und entscheidest, wie sie behandelt wird.\n\n"
    "Drei Aktionen:\n"
    "  • auto_reply — du beantwortest die Mail sofort selbst in Daniel Rupps Namen.\n"
    "                 Geeignet für: Routine-Info-Anfragen, allgemeine Rückfragen zur "
    "                 Leistung/Rechtsrahmen, Bestätigungen, Terminvorschläge die flexibel sind.\n"
    "  • forward    — die Mail wird an Daniel weitergeleitet. Geeignet für: konkrete "
    "                 Auftragsanfragen, Vertrags-/Rechnungsfragen, rechtliche Anliegen, "
    "                 Beschwerden, Datenschutzvorfälle, Kooperationen, Presse, alles "
    "                 Persönliche, alles was eine individuelle Entscheidung braucht.\n"
    "  • skip       — nichts tun. Geeignet für: Newsletter, Marketing, Spam, "
    "                 automatisierte Benachrichtigungen, Out-of-Office-Mails.\n\n"
    "REGELN für auto_reply:\n"
    "  - Nur wenn du die Frage eindeutig ohne interne Daten beantworten kannst.\n"
    "  - Keine Preise, keine konkreten Termine, keine Zusagen die Daniel treffen müsste.\n"
    "  - Im Zweifel → forward.\n"
    "  - Antwort in deutschem Sie-Form, 2-4 Absätze, kein Markdown, kein Code-Fence.\n"
    "  - Signatur am Ende genau so:\n\n"
    "      Mit freundlichen Grüßen\n\n"
    "      Daniel Rupp\n"
    "      Geschäftsführer · Advanced Analytics GmbH (ZDKG)\n"
    "      daniel.rupp@zdkg.de · +49 176 43677735\n\n"
    "OUTPUT — striktes JSON, ohne Fences, ohne Kommentar:\n"
    '{\n'
    '  "action": "auto_reply|forward|skip",\n'
    '  "confidence": 0.0-1.0,\n'
    '  "reasoning": "ein-satz-begründung, max 140 zeichen",\n'
    '  "reply_text": "nur bei action=auto_reply; sonst leer string"\n'
    '}'
)


def _classify(msg: Message) -> dict:
    """Call the LLM to classify + optionally draft a reply. Returns a dict with
    keys action/confidence/reasoning/reply_text. Raises on transport errors so
    the caller can decide the fallback."""
    sender = msg.from_addr or "unbekannt"
    subject = msg.subject or "(kein Betreff)"
    body = (msg.body_text or "")[:4000]
    user_prompt = (
        f"Absender: {sender}\n"
        f"Betreff: {subject}\n"
        f"Datum: {msg.received_at.strftime('%d.%m.%Y %H:%M') if msg.received_at else '?'}\n\n"
        f"Inhalt:\n{body}\n\n"
        "Entscheide jetzt die Aktion."
    )
    text = llm.draft(CLASSIFIER_SYSTEM, user_prompt, max_tokens=1500, temperature=0.2, scan_id=msg.scan_id)
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.MULTILINE)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # conservative fallback: route everything to humans on parse error
        log.warning("classifier returned non-JSON, forwarding defensively: %s", text[:200])
        return {"action": "forward", "confidence": 0.0,
                "reasoning": "Klassifizierer-Output nicht parsebar — defensiv weitergeleitet", "reply_text": ""}


# ─── Send helpers ───────────────────────────────────────────────────────────


def _send_auto_reply(msg: Message, body_text: str) -> dict:
    """Send the drafted reply and return the SMTP record. Sets auto-submitted
    headers so downstream mail servers don't bounce into us again."""
    subj = msg.subject or ""
    reply_subject = subj if subj.lower().startswith("re:") else f"Re: {subj}"
    refs = (msg.references or "") + (" " + msg.message_id if msg.message_id else "")
    return mailer.send_offer_email(
        to_email=msg.from_addr,
        subject=reply_subject,
        body_text=body_text,
        attachments=[],
        cc=None,
        in_reply_to=msg.message_id,
        references=refs.strip() or None,
        auto_submitted=True,
    )


def _forward_to_owner(msg: Message, forward_to: str) -> dict:
    """Forward the incoming message body (+ original headers as quote) to the
    fallback address. Not a perfect RFC 5322 forward, but Daniel's inbox will
    show it with the needed context."""
    orig_received = msg.received_at.strftime("%d.%m.%Y %H:%M") if msg.received_at else "?"
    body = (
        f"[Automatisch weitergeleitet vom ZDKG-Bot — ursprünglicher Absender:]\n\n"
        f"Von:     {msg.from_addr}\n"
        f"An:      {msg.to_addr}\n"
        f"Datum:   {orig_received}\n"
        f"Betreff: {msg.subject or '(kein Betreff)'}\n"
        f"\n"
        f"{'─' * 60}\n\n"
        f"{msg.body_text or '(kein Textinhalt)'}\n"
    )
    fwd_subject = f"[ZDKG-Fwd] {msg.subject or '(kein Betreff)'}"
    return mailer.send_offer_email(
        to_email=forward_to,
        subject=fwd_subject,
        body_text=body,
        attachments=[],
        cc=None,
        reply_to=msg.from_addr,  # so replies to the forward go back to the customer
        auto_submitted=True,
    )


# ─── Main entry point ───────────────────────────────────────────────────────


def process_inbound(session: Session, msg: Message) -> Literal["auto_reply", "forward", "skip", "dry_run", "disabled"]:
    """Decide + act. Always stamps bot_* fields so the UI can show what happened."""
    s = get_settings()

    if not s.auto_responder_enabled:
        return "disabled"
    if not mailer.is_enabled() or not llm.is_enabled():
        return "disabled"

    now = datetime.now(timezone.utc)

    # ── pre-filter gates ────
    if _is_from_self_or_bot(msg):
        msg.bot_action = "skip"
        msg.bot_processed_at = now
        msg.bot_reasoning = "Absender ist Bot / Mailer-Daemon / interne Adresse"
        return "skip"

    # Don't re-process
    if msg.bot_action:
        return msg.bot_action  # type: ignore[return-value]

    if msg.from_addr and _rate_limited(session, msg.from_addr):
        msg.bot_action = "skip"
        msg.bot_processed_at = now
        msg.bot_reasoning = "Tageslimit für diesen Absender erreicht"
        return "skip"

    # ── LLM classification ────
    try:
        decision = _classify(msg)
    except llm.BudgetExceeded:
        msg.bot_action = "skip"
        msg.bot_processed_at = now
        msg.bot_reasoning = "LLM-Budget aufgebraucht — manuell prüfen"
        return "skip"
    except Exception as e:  # noqa: BLE001
        log.warning("classifier failed: %s", e)
        msg.bot_action = "skip"
        msg.bot_processed_at = now
        msg.bot_reasoning = f"Klassifizierer-Fehler: {type(e).__name__}"
        return "skip"

    action = str(decision.get("action", "")).lower().strip()
    confidence = float(decision.get("confidence") or 0.0)
    reasoning = str(decision.get("reasoning") or "")[:500]

    msg.bot_confidence = confidence
    msg.bot_reasoning = reasoning
    msg.bot_processed_at = now

    if action not in ("auto_reply", "forward", "skip"):
        msg.bot_action = "skip"
        return "skip"

    # Minimum-confidence gate for auto_reply ONLY. Forward and skip are safe at any confidence.
    min_conf = float(s.auto_responder_min_confidence or 0.0)
    if action == "auto_reply" and confidence < min_conf:
        action = "forward"  # downgrade — safer to bother Daniel than to send a shaky reply

    # ── dry-run early out ────
    if s.auto_responder_dry_run:
        msg.bot_action = "dry_run"
        msg.bot_reasoning = f"[{action}] {reasoning}"
        return "dry_run"

    # ── execute ────
    if action == "skip":
        msg.bot_action = "skip"
        return "skip"

    try:
        if action == "auto_reply":
            reply_text = (decision.get("reply_text") or "").strip()
            if not reply_text:
                # LLM said auto_reply but gave no body — defensively forward.
                _forward_to_owner(msg, s.auto_responder_forward_to)
                msg.bot_action = "forward"
                msg.bot_reasoning = f"{reasoning} · kein Entwurf, daher weitergeleitet"
                return "forward"
            rec = _send_auto_reply(msg, reply_text)
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
                bot_action="auto_reply",
                bot_processed_at=now,
                bot_confidence=confidence,
                bot_reasoning=reasoning,
            ))
            msg.bot_action = "auto_reply"
            return "auto_reply"

        # action == forward
        _forward_to_owner(msg, s.auto_responder_forward_to)
        msg.bot_action = "forward"
        return "forward"

    except Exception as e:  # noqa: BLE001
        log.exception("auto_reply send failed for msg %s: %s", msg.id, e)
        msg.bot_action = "skip"
        msg.bot_reasoning = f"Versand-Fehler — manuell prüfen: {type(e).__name__}"
        return "skip"
