from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.auth import SESSION_USER_KEY, user_count
from app.config import get_settings
from app.db import SessionLocal, init_db
from app.routers import api, auth, pages

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="MVZ Security Scan", lifespan=lifespan)

PUBLIC_PATH_PREFIXES = ("/login", "/logout", "/setup", "/static", "/healthz")


# Register auth middleware FIRST so that after SessionMiddleware is added
# below (and runs outermost), the request flow is Session -> Auth -> App.
@app.middleware("http")
async def require_login_middleware(request: Request, call_next):
    path = request.url.path
    if any(path == p or path.startswith(p + "/") for p in PUBLIC_PATH_PREFIXES):
        return await call_next(request)

    user_id = request.session.get(SESSION_USER_KEY)
    if user_id:
        return await call_next(request)

    # Not authed. Decide whether to push user to /setup or /login.
    async with SessionLocal() as session:
        count = await user_count(session)
    target = "/setup" if count == 0 else "/login"
    return RedirectResponse(target, status_code=303)


# SessionMiddleware MUST be added after the auth middleware so it ends up
# outermost in the Starlette stack (add_middleware prepends). Result stack:
#   Session -> Auth -> FastAPI app
# Without this order, auth middleware runs before the session scope is set.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="mvzscan_session",
    https_only=settings.app_env == "production",
    same_site="lax",
    max_age=60 * 60 * 24 * 14,  # 14 days
)


app.include_router(auth.router)
app.include_router(pages.router)
app.include_router(api.router)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}
