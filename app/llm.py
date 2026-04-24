"""Tiny provider-agnostic LLM client for reply drafts.

Supports Anthropic (Claude) and OpenAI (GPT) via HTTP. Uses httpx directly
to avoid pulling in large vendor SDKs. Both providers are text-in/text-out —
no streaming, no tool use needed here.

Cost-guard: the client tracks tokens + Euro cost per scan_id and per
calendar day in Redis. When a limit is exceeded, `draft()` raises
`BudgetExceeded` and the caller falls back to the plain template.

Falls back gracefully when no key is configured: `is_enabled()` returns False
and callers should use their own template.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.config import get_settings


class BudgetExceeded(RuntimeError):
    """Raised when the configured LLM token or EUR budget has been exhausted."""


# (input_usd_per_million, output_usd_per_million) by model-name prefix.
# Match is case-insensitive and first-hit-wins — order matters.
MODEL_PRICING_USD_PER_M: list[tuple[str, tuple[float, float]]] = [
    # Anthropic Claude
    ("claude-opus", (15.00, 75.00)),
    ("claude-sonnet", (3.00, 15.00)),
    ("claude-haiku", (1.00, 5.00)),
    # OpenAI GPT
    ("gpt-4o-mini", (0.15, 0.60)),
    ("gpt-4o", (2.50, 10.00)),
    ("gpt-4-turbo", (10.00, 30.00)),
    ("gpt-4", (30.00, 60.00)),
    ("gpt-3.5", (0.50, 1.50)),
]


def _price(model: str) -> tuple[float, float]:
    """Return (input_usd_per_m, output_usd_per_m) for the given model name."""
    name = (model or "").lower()
    for prefix, p in MODEL_PRICING_USD_PER_M:
        if prefix in name:
            return p
    # Unknown model → conservative Sonnet-class pricing so we don't under-
    # charge and blow the cap silently.
    return (5.00, 15.00)


def _redis():
    # Lazy import so this module stays importable in tests without Redis.
    from app.queue import redis_conn
    return redis_conn


def _budget_keys(scan_id: str | None) -> tuple[str | None, str, str]:
    """(per-scan tokens, per-day tokens, per-day EUR) Redis keys."""
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    per_scan = f"llm:budget:scan:{scan_id}" if scan_id else None
    per_day_tokens = f"llm:budget:day:{today}"
    per_day_eur_centi = f"llm:budget:eurc:day:{today}"  # stored as integer centi-EUR
    return per_scan, per_day_tokens, per_day_eur_centi


def _check_budget(scan_id: str | None) -> None:
    s = get_settings()
    try:
        r = _redis()
        per_scan_key, per_day_key, per_day_eur_key = _budget_keys(scan_id)
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
        if s.llm_budget_eur_per_day > 0:
            spent_centi = int(r.get(per_day_eur_key) or 0)
            cap_centi = int(s.llm_budget_eur_per_day * 100)
            if spent_centi >= cap_centi:
                raise BudgetExceeded(
                    f"EUR-Tagesbudget aufgebraucht (€{spent_centi / 100:.2f}/"
                    f"€{s.llm_budget_eur_per_day:.2f})."
                )
    except BudgetExceeded:
        raise
    except Exception:  # noqa: BLE001 — Redis down shouldn't block drafts
        pass


def _record_usage(
    scan_id: str | None,
    input_tokens: int,
    output_tokens: int,
    model: str,
) -> None:
    total = max(0, input_tokens) + max(0, output_tokens)
    if total <= 0:
        return
    s = get_settings()
    in_p, out_p = _price(model)
    usd = (input_tokens / 1_000_000) * in_p + (output_tokens / 1_000_000) * out_p
    eur = usd * s.llm_usd_to_eur
    eur_centi = int(round(eur * 100))
    try:
        r = _redis()
        per_scan_key, per_day_key, per_day_eur_key = _budget_keys(scan_id)
        if per_scan_key:
            r.incrby(per_scan_key, total)
            r.expire(per_scan_key, 60 * 60 * 24 * 30)  # 30d
        r.incrby(per_day_key, total)
        r.expire(per_day_key, 60 * 60 * 26)
        if eur_centi > 0:
            r.incrby(per_day_eur_key, eur_centi)
            r.expire(per_day_eur_key, 60 * 60 * 26)
    except Exception:  # noqa: BLE001
        pass


def today_usage() -> dict:
    """Read the current day's Redis counters. Used by admin UI."""
    s = get_settings()
    try:
        r = _redis()
        _, per_day_key, per_day_eur_key = _budget_keys(None)
        tokens = int(r.get(per_day_key) or 0)
        eur_centi = int(r.get(per_day_eur_key) or 0)
        return {
            "tokens": tokens,
            "eur_spent": eur_centi / 100,
            "eur_cap": s.llm_budget_eur_per_day,
            "remaining_eur": max(0, s.llm_budget_eur_per_day - eur_centi / 100),
            "tokens_cap": s.llm_budget_tokens_per_day,
        }
    except Exception:  # noqa: BLE001
        return {
            "tokens": 0, "eur_spent": 0, "eur_cap": s.llm_budget_eur_per_day,
            "remaining_eur": s.llm_budget_eur_per_day,
            "tokens_cap": s.llm_budget_tokens_per_day,
        }


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

    Cost guard: checks the per-scan token, per-day token AND per-day EUR
    budget BEFORE calling, records actual usage AFTER. Raises
    BudgetExceeded when any ceiling is hit — caller renders a plain
    template fallback.
    """
    s = get_settings()
    if not is_enabled():
        raise RuntimeError("LLM nicht konfiguriert (llm_api_key fehlt).")

    _check_budget(scan_id)  # raises BudgetExceeded

    mt = int(max_tokens or s.llm_max_tokens)
    provider = s.llm_provider.lower().strip()

    if provider == "anthropic":
        text, in_tok, out_tok = _anthropic(s.llm_api_key, s.llm_model, system, user, mt, temperature)
    elif provider == "openai":
        text, in_tok, out_tok = _openai(s.llm_api_key, s.llm_model, system, user, mt, temperature)
    else:
        raise RuntimeError(f"Unbekannter LLM-Provider: {provider}")

    _record_usage(scan_id, in_tok, out_tok, s.llm_model)
    return text


# ---- providers ----


def _anthropic(api_key: str, model: str, system: str, user: str, max_tokens: int, temperature: float) -> tuple[str, int, int]:
    """Returns (text, input_tokens, output_tokens)."""
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
    return text, int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0))


def _openai(api_key: str, model: str, system: str, user: str, max_tokens: int, temperature: float) -> tuple[str, int, int]:
    """Returns (text, input_tokens, output_tokens)."""
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
    usage = data.get("usage") or {}
    return text, int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))
