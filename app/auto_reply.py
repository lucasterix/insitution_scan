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
    "Du bekommst eine eingehende E-Mail und entscheidest, wie sie behandelt wird.\n\n"
    "Drei Aktionen — welche passt:\n"
    "  • auto_reply — du schreibst die Antwort und sie wird SOFORT verschickt, "
    "                 in Daniel Rupps Namen. Geeignet für: Routine-Info-Anfragen, "
    "                 Rückfragen zum Leistungsumfang / Rechtsrahmen, höfliche "
    "                 Bestätigungen, flexible Terminvorschläge.\n"
    "  • forward    — du schreibst EBENFALLS eine Antwort, aber SIE WIRD NICHT VERSCHICKT: "
    "                 stattdessen geht der Entwurf + die Original-Mail an Daniel persönlich, "
    "                 damit er die Antwort prüfen und selbst absenden kann. Geeignet für: "
    "                 konkrete Auftragsanfragen, Vertrags-/Rechnungsfragen, rechtliche "
    "                 Anliegen, Beschwerden, Datenschutzvorfälle, Kooperationen, Presse, "
    "                 Persönliches, alles was eine individuelle Entscheidung braucht.\n"
    "  • skip       — keine Antwort nötig, auch NICHT an Daniel weiterleiten. "
    "                 Geeignet für: Newsletter, Marketing, Spam, automatisierte "
    "                 Benachrichtigungen, Out-of-Office-Mails, klare Bots.\n\n"
    "REGELN für den Antwort-Entwurf (reply_text — bei auto_reply UND forward Pflicht, bei skip leer):\n"
    "  - Deutsches Sie-Form, 2-4 Absätze, kein Markdown, kein Code-Fence, keine Präambel.\n"
    "  - Keine konkreten Preise, keine festen Termine, keine harten Zusagen.\n"
    "  - Keine Fakten erfinden — wenn etwas unbekannt ist: höflich rückfragen oder "
    "    ein Gespräch anbieten.\n"
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
    '  "reply_text": "fertiger Antwort-Text bei auto_reply UND forward; leer bei skip"\n'
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


def _forward_to_owner(msg: Message, forward_to: str, draft_text: str, reasoning: str) -> dict:
    """Forward the incoming message + the bot's drafted reply to Daniel.

    The forward is not a raw-mail forward — it's a summary for Daniel to
    review and act on: here's the original, here's the draft I prepared,
    send or edit before sending. Reply-To points at the customer so
    Daniel can hit reply and answer directly."""
    orig_received = msg.received_at.strftime("%d.%m.%Y %H:%M") if msg.received_at else "?"
    bar = "─" * 60
    body = (
        f"[ZDKG-Bot — Review-Anfrage. Der Entwurf wurde NICHT an den Absender versendet.]\n\n"
        f"Einstufung: forward · {reasoning}\n\n"
        f"{bar}\n"
        f"URSPRÜNGLICHE NACHRICHT\n"
        f"{bar}\n\n"
        f"Von:     {msg.from_addr}\n"
        f"An:      {msg.to_addr}\n"
        f"Datum:   {orig_received}\n"
        f"Betreff: {msg.subject or '(kein Betreff)'}\n\n"
        f"{msg.body_text or '(kein Textinhalt)'}\n\n"
        f"{bar}\n"
        f"ENTWURF DES BOTS (bitte prüfen und absenden)\n"
        f"{bar}\n\n"
        f"{draft_text}\n"
    )
    fwd_subject = f"[ZDKG-Review] {msg.subject or '(kein Betreff)'}"
    return mailer.send_offer_email(
        to_email=forward_to,
        subject=fwd_subject,
        body_text=body,
        attachments=[],
        cc=None,
        reply_to=msg.from_addr,
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
    draft_text = (decision.get("reply_text") or "").strip()

    msg.bot_confidence = confidence
    msg.bot_reasoning = reasoning
    msg.bot_processed_at = now

    if action not in ("auto_reply", "forward", "skip"):
        msg.bot_action = "skip"
        return "skip"

    # For auto_reply / forward we need a draft. No draft → nothing to forward → skip.
    if action in ("auto_reply", "forward") and not draft_text:
        msg.bot_action = "skip"
        msg.bot_reasoning = f"{reasoning} · kein Entwurf erstellt — manuell prüfen"
        return "skip"

    # Below the auto-reply confidence threshold we still want Daniel to see the draft,
    # so we downgrade to 'forward'. skip stays skip at any confidence.
    min_conf = float(s.auto_responder_min_confidence or 0.0)
    if action == "auto_reply" and confidence < min_conf:
        action = "forward"

    # Store the draft regardless of action (useful for UI inspection + audit).
    if draft_text:
        msg.bot_draft_text = draft_text

    # ── dry-run early out ────
    # skip in dry-run → just stamp, no forwarding.
    # auto_reply/forward in dry-run → stamp with intended action + draft, no sending.
    if s.auto_responder_dry_run:
        msg.bot_action = "dry_run"
        msg.bot_reasoning = f"[{action}] {reasoning}"
        return "dry_run"

    # ── execute (live) ────
    if action == "skip":
        msg.bot_action = "skip"
        return "skip"

    try:
        if action == "auto_reply":
            rec = _send_auto_reply(msg, draft_text)
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
                bot_draft_text=draft_text,
            ))
            msg.bot_action = "auto_reply"
            return "auto_reply"

        # action == forward — we have a draft, send it + original to Daniel for review
        _forward_to_owner(msg, s.auto_responder_forward_to, draft_text, reasoning)
        msg.bot_action = "forward"
        return "forward"

    except Exception as e:  # noqa: BLE001
        log.exception("auto_reply send failed for msg %s: %s", msg.id, e)
        msg.bot_action = "skip"
        msg.bot_reasoning = f"Versand-Fehler — manuell prüfen: {type(e).__name__}"
        return "skip"
