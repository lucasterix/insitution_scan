"""Tiny provider-agnostic LLM client for reply drafts.

Supports Anthropic (Claude) and OpenAI (GPT) via HTTP. Uses httpx directly
to avoid pulling in large vendor SDKs. Both providers are text-in/text-out —
no streaming, no tool use needed here.

Cost-guard (inspired by pentagi's per-agent limits): the client tracks
tokens used in Redis per scan_id and per calendar day. When a budget is
exceeded, `draft()` raises `BudgetExceeded` and the caller falls back to
the plain template.

Falls back gracefully when no key is configured: `is_enabled()` returns False
and callers should use their own template.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.config import get_settings


class BudgetExceeded(RuntimeError):
    """Raised when the configured LLM token budget has been exhausted."""


def _redis():
    # Lazy import so this module stays importable in tests without Redis.
    from app.queue import redis_conn
    return redis_conn


def _budget_keys(scan_id: str | None) -> tuple[str | None, str]:
    """(per-scan key, per-day key). Per-scan is None when scan_id is None."""
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    per_scan = f"llm:budget:scan:{scan_id}" if scan_id else None
    per_day = f"llm:budget:day:{today}"
    return per_scan, per_day


def _check_budget(scan_id: str | None) -> None:
    s = get_settings()
    try:
        r = _redis()
        per_scan_key, per_day_key = _budget_keys(scan_id)
        if per_scan_key and s.llm_budget_tokens_per_scan > 0:
            spent = int(r.get(per_scan_key) or 0)
            if spent >= s.llm_budget_tokens_per_scan:
                raise BudgetExceeded(
                    f"Token-Budget dieses Scans aufgebraucht ({spent}/{s.llm_budget_tokens_per_scan})."
                )
        if s.llm_budget_tokens_per_day > 0:
            spent = int(r.get(per_day_key) or 0)
            if spent >= s.llm_budget_tokens_per_day:
                raise BudgetExceeded(
                    f"Tages-Token-Budget aufgebraucht ({spent}/{s.llm_budget_tokens_per_day})."
                )
    except BudgetExceeded:
        raise
    except Exception:  # noqa: BLE001 — Redis down shouldn't block drafts
        pass


def _record_usage(scan_id: str | None, tokens: int) -> None:
    if tokens <= 0:
        return
    try:
        r = _redis()
        per_scan_key, per_day_key = _budget_keys(scan_id)
        if per_scan_key:
            r.incrby(per_scan_key, tokens)
            r.expire(per_scan_key, 60 * 60 * 24 * 30)  # 30d
        r.incrby(per_day_key, tokens)
        r.expire(per_day_key, 60 * 60 * 26)  # slightly >1d, rotates with calendar
    except Exception:  # noqa: BLE001
        pass


def is_enabled() -> bool:
    s = get_settings()
    return bool(s.llm_api_key and s.llm_provider and s.llm_model)


def draft(
    system: str,
    user: str,
    *,
    max_tokens: int | None = None,
    temperature: float = 0.4,
    scan_id: str | None = None,
) -> str:
    """Synchronous one-shot completion. Returns the model's text output.

    Cost guard: checks the per-scan + per-day Redis budget BEFORE calling,
    records usage AFTER. Raises BudgetExceeded when the ceiling is hit — the
    caller should catch this and render a plain-template fallback.

    Raises RuntimeError when LLM is disabled or misconfigured. Raises
    httpx.HTTPError on transport failures — callers can catch + fall back.
    """
    s = get_settings()
    if not is_enabled():
        raise RuntimeError("LLM nicht konfiguriert (llm_api_key fehlt).")

    _check_budget(scan_id)  # raises BudgetExceeded

    mt = int(max_tokens or s.llm_max_tokens)
    provider = s.llm_provider.lower().strip()

    if provider == "anthropic":
        text, used = _anthropic(s.llm_api_key, s.llm_model, system, user, mt, temperature)
    elif provider == "openai":
        text, used = _openai(s.llm_api_key, s.llm_model, system, user, mt, temperature)
    else:
        raise RuntimeError(f"Unbekannter LLM-Provider: {provider}")

    _record_usage(scan_id, used)
    return text


# ---- providers ----


def _anthropic(api_key: str, model: str, system: str, user: str, max_tokens: int, temperature: float) -> tuple[str, int]:
    """Returns (text, tokens_used). tokens_used sums input + output."""
    resp = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        },
        timeout=60.0,
    )
    resp.raise_for_status()
    data = resp.json()
    text = ""
    for p in data.get("content") or []:
        if p.get("type") == "text":
            text = (p.get("text") or "").strip()
            break
    usage = data.get("usage") or {}
    used = int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
    return text, used


def _openai(api_key: str, model: str, system: str, user: str, max_tokens: int, temperature: float) -> tuple[str, int]:
    """Returns (text, tokens_used). tokens_used is total_tokens from usage."""
    resp = httpx.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        },
        timeout=60.0,
    )
    resp.raise_for_status()
    data = resp.json()
    text = ""
    choices = data.get("choices") or []
    if choices and choices[0].get("message"):
        text = (choices[0]["message"].get("content") or "").strip()
    used = int((data.get("usage") or {}).get("total_tokens", 0))
    return text, used
