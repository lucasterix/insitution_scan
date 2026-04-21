from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    institution_name: Mapped[str] = mapped_column(String(255))
    target_domain: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    # Pentest authorisation + scan mode
    ownership_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    deep_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    rate_limit_test: Mapped[bool] = mapped_column(Boolean, default=False)
    context: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # queued, running, completed, failed
    progress: Mapped[int] = mapped_column(default=0)
    current_step: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Message(Base):
    """Stored e-mail record.

    direction = 'outbound' for things we sent (offer emails etc.)
    direction = 'inbound'  for replies/mails pulled via IMAP.

    `scan_id` is the scan the message is associated with. For outbound it's
    always set. For inbound we fill it when we can match by In-Reply-To or
    by sender domain; otherwise it's NULL and the message only shows in the
    global inbox.
    """
    __tablename__ = "messages"
    __table_args__ = (
        Index("ix_messages_scan_direction_received", "scan_id", "direction", "received_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    direction: Mapped[str] = mapped_column(String(16), index=True)  # inbound | outbound
    message_id: Mapped[str | None] = mapped_column(String(500), nullable=True, unique=True, index=True)
    in_reply_to: Mapped[str | None] = mapped_column(String(500), nullable=True, index=True)
    references: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_addr: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    to_addr: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    cc_addr: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    attachments_meta: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # [{filename, size, mime}]
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    raw_uid: Mapped[str | None] = mapped_column(String(64), nullable=True)  # IMAP UID, for idempotency
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    # Auto-reply bot bookkeeping — populated by app.auto_reply when an inbound
    # message is processed. bot_action ∈ { auto_reply, forward, skip, dry_run }.
    bot_action: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    bot_processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    bot_confidence: Mapped[float | None] = mapped_column(nullable=True)
    bot_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Draft that the bot composed. Persisted for every action except 'skip':
    #   - auto_reply: the text that was actually sent (also stored as outbound Message)
    #   - forward:    the text the bot suggests Daniel sends — delivered in the forward
    #   - dry_run:    the text that WOULD have been sent/forwarded
    bot_draft_text: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanEpisode(Base):
    """Episodic memory of findings per target domain.

    One row per (domain, finding_id). Updated on every completed scan so the
    PDF / UI can show 'diese Schwachstelle besteht seit X Tagen'. When a
    previously-seen finding no longer appears in a later scan, we stamp
    resolved_at — so we can also highlight 'endlich geschlossen' situations.
    """
    __tablename__ = "scan_episodes"
    __table_args__ = (
        Index("ix_episodes_domain_finding", "domain", "finding_id", unique=True),
        Index("ix_episodes_domain_open", "domain", "resolved_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    domain: Mapped[str] = mapped_column(String(255), index=True)
    finding_id: Mapped[str] = mapped_column(String(255), index=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    observation_count: Mapped[int] = mapped_column(default=1)
    scan_id_latest: Mapped[str | None] = mapped_column(String(36), nullable=True)
