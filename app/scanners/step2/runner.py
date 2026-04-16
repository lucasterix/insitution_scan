"""Step-2 analysis runner.

Runs AFTER the main pipeline (and optionally after deep scan). Each module
reads from result.metadata populated by step-1 scanners and performs
targeted follow-up probes.

Unlike deep scan, step-2 always runs — it's fast because it only probes
what step-1 already found.
"""
from __future__ import annotations

from typing import Callable

from app.scanners.base import ScanResult
from app.scanners.deep.exploit_chain import check_exploit_chains
from app.scanners.step2.api_auth_test import check_api_auth
from app.scanners.step2.dns_rebinding import check_dns_rebinding
from app.scanners.step2.spf_chain import check_spf_chain
from app.scanners.step2.subdomain_takeover import check_subdomain_takeover
from app.scanners.step2.tls_san_expansion import check_tls_san_expansion
from app.scanners.step2.wp_exploit_verify import check_wp_exploit_paths


def run_step2(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    for fn in (
        check_tls_san_expansion,
        check_subdomain_takeover,
        check_dns_rebinding,
        check_spf_chain,
        check_api_auth,
        check_wp_exploit_paths,
        check_exploit_chains,
    ):
        try:
            fn(domain, result, step)
        except Exception as e:  # noqa: BLE001
            result.metadata.setdefault("step2_errors", []).append(
                {"module": fn.__name__, "error": f"{type(e).__name__}: {e}"}
            )
