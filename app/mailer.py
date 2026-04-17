"""SMTP mailer for the "Angebot versenden" feature.

Uses the stdlib smtplib + email modules — no external dependencies.
The sender config comes from `app.config`; disabled entirely when
smtp_host is empty, in which case the UI falls back to a mailto: link.
"""
from __future__ import annotations

import smtplib
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from typing import Iterable

from app.config import get_settings


def is_enabled() -> bool:
    s = get_settings()
    return bool(s.smtp_host and s.mail_from_address)


def send_offer_email(
    *,
    to_email: str,
    subject: str,
    body_text: str,
    attachments: Iterable[tuple[str, bytes, str]],  # (filename, bytes, mime-type)
    reply_to: str | None = None,
    cc: str | None = None,
) -> None:
    """Send a multipart/mixed email with the offer text + attachments.

    Raises RuntimeError when SMTP isn't configured. Raises smtplib.SMTPException
    on transport failures — caller should catch and surface a friendly message.
    """
    s = get_settings()
    if not is_enabled():
        raise RuntimeError("SMTP ist nicht konfiguriert (smtp_host fehlt).")

    msg = EmailMessage()
    msg["From"] = formataddr((s.mail_from_name, s.mail_from_address))
    msg["To"] = to_email.strip()
    if cc:
        msg["Cc"] = cc.strip()
    msg["Subject"] = subject
    msg["Reply-To"] = reply_to or s.mail_reply_to or s.mail_from_address
    msg["Message-ID"] = make_msgid(domain=s.mail_from_address.split("@", 1)[-1] or "zdkg.de")
    msg.set_content(body_text, subtype="plain", charset="utf-8")

    for filename, content, mime in attachments:
        main, _, sub = mime.partition("/")
        msg.add_attachment(
            content,
            maintype=main or "application",
            subtype=sub or "octet-stream",
            filename=filename,
        )

    recipients = [msg["To"]]
    if cc:
        recipients.append(cc.strip())

    if s.smtp_use_ssl:
        with smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=20) as server:
            if s.smtp_user:
                server.login(s.smtp_user, s.smtp_password)
            server.send_message(msg, to_addrs=recipients)
    else:
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=20) as server:
            if s.smtp_use_tls:
                server.starttls()
            if s.smtp_user:
                server.login(s.smtp_user, s.smtp_password)
            server.send_message(msg, to_addrs=recipients)
