"""Tiny provider-agnostic LLM client for reply drafts.

Supports Anthropic (Claude) and OpenAI (GPT) via HTTP. Uses httpx directly
to avoid pulling in large vendor SDKs. Both providers are text-in/text-out —
no streaming, no tool use needed here.

Falls back gracefully when no key is configured: `is_enabled()` returns False
and callers should use their own template.
"""
from __future__ import annotations

import json

import httpx

from app.config import get_settings


def is_enabled() -> bool:
    s = get_settings()
    return bool(s.llm_api_key and s.llm_provider and s.llm_model)


def draft(system: str, user: str, *, max_tokens: int | None = None, temperature: float = 0.4) -> str:
    """Synchronous one-shot completion. Returns the model's text output.

    Raises RuntimeError when LLM is disabled or misconfigured. Raises
    httpx.HTTPError on transport failures — callers can catch + fall back.
    """
    s = get_settings()
    if not is_enabled():
        raise RuntimeError("LLM nicht konfiguriert (llm_api_key fehlt).")

    mt = int(max_tokens or s.llm_max_tokens)
    provider = s.llm_provider.lower().strip()

    if provider == "anthropic":
        return _anthropic(s.llm_api_key, s.llm_model, system, user, mt, temperature)
    if provider == "openai":
        return _openai(s.llm_api_key, s.llm_model, system, user, mt, temperature)
    raise RuntimeError(f"Unbekannter LLM-Provider: {provider}")


# ---- providers ----


def _anthropic(api_key: str, model: str, system: str, user: str, max_tokens: int, temperature: float) -> str:
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
    # Response shape: {content: [{type: "text", text: "..."}], ...}
    parts = data.get("content") or []
    for p in parts:
        if p.get("type") == "text":
            return (p.get("text") or "").strip()
    return ""


def _openai(api_key: str, model: str, system: str, user: str, max_tokens: int, temperature: float) -> str:
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
    choices = data.get("choices") or []
    if choices and choices[0].get("message"):
        return (choices[0]["message"].get("content") or "").strip()
    return ""
