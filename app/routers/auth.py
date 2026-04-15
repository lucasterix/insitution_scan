"""Login / logout / first-time setup routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import (
    clear_session,
    get_user_by_email,
    hash_password,
    mark_login,
    set_session_user,
    user_count,
    verify_password,
)
from app.db import get_session
from app.models import User

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/login", response_class=HTMLResponse)
async def login_form(
    request: Request,
    session: AsyncSession = Depends(get_session),
    error: str | None = None,
):
    count = await user_count(session)
    if count == 0:
        return RedirectResponse("/setup", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": error})


@router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    user = await get_user_by_email(session, email)
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            request, "login.html", {"error": "E-Mail oder Passwort falsch."}, status_code=401
        )
    set_session_user(request, user)
    await mark_login(session, user)
    return RedirectResponse("/", status_code=303)


@router.get("/logout")
async def logout(request: Request):
    clear_session(request)
    return RedirectResponse("/login", status_code=303)


@router.get("/setup", response_class=HTMLResponse)
async def setup_form(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    count = await user_count(session)
    if count > 0:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "setup.html", {"error": None})


@router.post("/setup")
async def setup_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    display_name: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    count = await user_count(session)
    if count > 0:
        return RedirectResponse("/login", status_code=303)

    error = None
    if not email or "@" not in email:
        error = "Bitte eine gültige E-Mail-Adresse angeben."
    elif len(password) < 10:
        error = "Passwort muss mindestens 10 Zeichen lang sein."
    elif password != password_confirm:
        error = "Die beiden Passwörter stimmen nicht überein."

    if error:
        return templates.TemplateResponse(
            request, "setup.html", {"error": error}, status_code=400
        )

    user = User(
        email=email.lower().strip(),
        password_hash=hash_password(password),
        display_name=display_name.strip() or None,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    set_session_user(request, user)
    return RedirectResponse("/", status_code=303)
