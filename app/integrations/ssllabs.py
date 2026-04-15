"""SSL Labs v3 API client — deep TLS grading.

Docs: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md

Usage:
    client = SSLLabsClient()
    report = client.analyze("example.com")  # blocking poll, returns dict or None

The free API is rate limited: max 25 assessments/hour per client, 1 new every 2s.
We request `fromCache=on&maxAge=24` so we re-use cached results when possible.
"""
from __future__ import annotations

import time
from typing import Any

import httpx

BASE_URL = "https://api.ssllabs.com/api/v3"
USER_AGENT = "MVZ-SelfScan/1.0"

# Hard ceiling so a stuck assessment can never block the worker indefinitely.
MAX_WAIT_SECONDS = 180


class SSLLabsClient:
    def __init__(self, timeout: float = 20.0) -> None:
        self._client = httpx.Client(
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            base_url=BASE_URL,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SSLLabsClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def analyze(self, host: str, use_cache: bool = True) -> dict | None:
        """Kick off an assessment and poll until it is READY or ERROR.

        Returns the full JSON report, or None if the scan could not be completed
        within MAX_WAIT_SECONDS.
        """
        params = {"host": host, "all": "done"}
        if use_cache:
            params["fromCache"] = "on"
            params["maxAge"] = "24"

        try:
            r = self._client.get("/analyze", params=params)
            r.raise_for_status()
            data = r.json()
        except httpx.HTTPError:
            return None

        deadline = time.monotonic() + MAX_WAIT_SECONDS
        while data.get("status") in ("DNS", "IN_PROGRESS"):
            if time.monotonic() > deadline:
                return None
            time.sleep(5)
            try:
                r = self._client.get("/analyze", params={"host": host, "all": "done"})
                r.raise_for_status()
                data = r.json()
            except httpx.HTTPError:
                return None

        if data.get("status") == "READY":
            return data
        return None


def grade_to_severity(grade: str) -> str:
    """Map SSL Labs grades (A+, A, B, C, D, E, F, T, M) to our severity levels."""
    if not grade:
        return "info"
    g = grade.upper().strip()
    if g in ("A+", "A", "A-"):
        return "info"
    if g == "B":
        return "low"
    if g == "C":
        return "medium"
    if g in ("D", "E"):
        return "high"
    if g in ("F", "T", "M"):
        return "critical"
    return "info"
