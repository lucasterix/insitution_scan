"""Authentication helpers: bcrypt password hashing + session accessors.

The app uses Starlette's SessionMiddleware for signed cookie sessions.
On every unauthenticated request, a middleware redirects to /login (or
/setup when no user exists yet). The middleware itself lives in main.py;
this module only provides the pure helpers.
"""
from __future__ import annotations

from datetime import datetime, timezone

import bcrypt
from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User

SESSION_USER_KEY = "user_id"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


async def user_count(session: AsyncSession) -> int:
    result = await session.execute(select(func.count(User.id)))
    return int(result.scalar() or 0)


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email.lower().strip()))
    return result.scalar_one_or_none()


async def get_current_user(request: Request, session: AsyncSession) -> User | None:
    user_id = request.session.get(SESSION_USER_KEY)
    if not user_id:
        return None
    return await session.get(User, user_id)


def set_session_user(request: Request, user: User) -> None:
    request.session[SESSION_USER_KEY] = user.id


def clear_session(request: Request) -> None:
    request.session.clear()


async def mark_login(session: AsyncSession, user: User) -> None:
    user.last_login_at = datetime.now(timezone.utc)
    await session.commit()
