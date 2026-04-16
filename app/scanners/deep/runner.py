"""Deep-scan runner — wires up all deep modules behind one call.

Executed only when the user checked `deep_scan` on the form. Each module
gets its own try/except so one failing check doesn't break the others.
"""
from __future__ import annotations

from typing import Callable

from app.scanners.base import ScanResult
from app.scanners.deep.active_cors import check_cors
from app.scanners.deep.directory_fuzz import check_directory_fuzz
from app.scanners.deep.graphql_introspection import check_graphql
from app.scanners.deep.host_header_injection import check_host_header
from app.scanners.deep.http_methods import check_http_methods
from app.scanners.deep.js_secrets import check_js_secrets
from app.scanners.deep.mixed_content import check_mixed_content
from app.scanners.deep.nuclei_scan import check_nuclei
from app.scanners.deep.open_redirect import check_open_redirect
from app.scanners.deep.rate_limit_test import check_rate_limits
from app.scanners.deep.openapi_parser import check_openapi
from app.scanners.deep.wayback import check_wayback
from app.scanners.deep.zone_transfer import check_zone_transfer


def run_deep_scan(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    # Ordered roughly by cost: DNS-only checks first, then HTTP-heavy ones.
    # Nuclei runs last because it's the heaviest (up to 180s).
    for fn in (
        check_zone_transfer,
        check_wayback,
        check_graphql,
        check_openapi,
        check_host_header,
        check_mixed_content,
        check_open_redirect,
        check_http_methods,
        check_cors,
        check_js_secrets,
        check_directory_fuzz,
        check_rate_limits,
        check_nuclei,
    ):
        try:
            fn(domain, result, step)
        except Exception as e:  # noqa: BLE001 — one failing module must not kill deep scan
            result.metadata.setdefault("deep_scan_errors", []).append(
                {"module": fn.__name__, "error": f"{type(e).__name__}: {e}"}
            )
