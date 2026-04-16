"""Subdomain takeover detection.

A CNAME that points to a third-party service (GitHub Pages, S3, Azure,
Heroku, Shopify, etc.) that the owner no longer controls is a "dangling"
CNAME — an attacker can register the target resource and serve arbitrary
content on the victim's subdomain, including phishing pages with valid TLS.

We check each discovered subdomain for a CNAME, then match the CNAME target
against a curated list of takeover-susceptible services, and finally probe
whether the service returns a "not found" page (= claimable).
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import dns.exception
import dns.resolver
import httpx

from app.scanners.base import Finding, ScanResult, Severity

# (cname_contains, service_name, fingerprint_in_body)
TAKEOVER_SIGNATURES: list[tuple[str, str, str]] = [
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("s3.amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("s3-website", "AWS S3 Website", "NoSuchBucket"),
    ("herokuapp.com", "Heroku", "no-such-app"),
    ("herokudns.com", "Heroku", "no-such-app"),
    ("azure-api.net", "Azure API", "not found"),
    ("azurewebsites.net", "Azure Web App", "not found"),
    ("cloudapp.net", "Azure Cloud App", "not found"),
    ("trafficmanager.net", "Azure Traffic Manager", "not found"),
    ("blob.core.windows.net", "Azure Blob", "BlobNotFound"),
    ("shopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("myshopify.com", "Shopify", "Sorry, this shop"),
    ("wordpress.com", "WordPress.com", "Do you want to register"),
    ("ghost.io", "Ghost", "404"),
    ("pantheon.io", "Pantheon", "404"),
    ("zendesk.com", "Zendesk", "Help Center Closed"),
    ("statuspage.io", "Statuspage", "You need to create this StatusPage"),
    ("helpjuice.com", "HelpJuice", "We could not find what you"),
    ("helpscoutdocs.com", "HelpScout", "No settings were found"),
    ("cargo.site", "Cargo", "404"),
    ("feedpress.me", "FeedPress", "The feed has not been found"),
    ("bitbucket.io", "Bitbucket", "Repository not found"),
    ("netlify.app", "Netlify", "Not Found"),
    ("fly.dev", "Fly.io", "not found"),
    ("vercel.app", "Vercel", "404"),
    ("surge.sh", "Surge", "project not found"),
    ("unbouncepages.com", "Unbounce", "The requested URL was not found"),
    ("agilecrm.com", "Agile CRM", "Sorry"),
    ("teamwork.com", "Teamwork", "Oops"),
]


def _resolve_cname(hostname: str) -> str | None:
    try:
        answers = dns.resolver.resolve(hostname, "CNAME", lifetime=3.0)
        for r in answers:
            return str(r.target).rstrip(".").lower()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    return None


def _probe_dangling(hostname: str, cname: str) -> dict | None:
    for cname_pattern, service, fingerprint in TAKEOVER_SIGNATURES:
        if cname_pattern not in cname:
            continue
        try:
            with httpx.Client(timeout=5.0, follow_redirects=True, verify=False) as client:
                r = client.get(f"https://{hostname}")
                body = r.text[:4096]
                if fingerprint.lower() in body.lower():
                    return {
                        "hostname": hostname,
                        "cname": cname,
                        "service": service,
                        "fingerprint": fingerprint,
                        "status": r.status_code,
                    }
        except httpx.HTTPError:
            try:
                with httpx.Client(timeout=5.0, follow_redirects=True, verify=False) as client:
                    r = client.get(f"http://{hostname}")
                    body = r.text[:4096]
                    if fingerprint.lower() in body.lower():
                        return {
                            "hostname": hostname,
                            "cname": cname,
                            "service": service,
                            "fingerprint": fingerprint,
                            "status": r.status_code,
                        }
            except httpx.HTTPError:
                pass
    return None


def check_subdomain_takeover(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Step-2: Subdomain-Takeover-Check", 97)

    subs = list(set(
        (result.metadata.get("subdomains") or []) +
        list((result.metadata.get("subdomain_walk") or {}).get("results", {}).keys())
    ))
    if not subs:
        return

    subs = subs[:50]
    dangling: list[dict] = []

    def task(sub: str) -> None:
        cname = _resolve_cname(sub)
        if not cname:
            return
        hit = _probe_dangling(sub, cname)
        if hit:
            dangling.append(hit)

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(task, s) for s in subs]
        for f in as_completed(futures):
            f.result()

    if not dangling:
        return

    result.metadata["subdomain_takeover"] = dangling

    for d in dangling:
        result.add(Finding(
            id=f"step2.subdomain_takeover.{d['hostname']}",
            title=f"Subdomain-Takeover möglich: {d['hostname']} → {d['service']}",
            description=(
                f"Die Subdomain {d['hostname']} hat einen CNAME auf {d['cname']} "
                f"({d['service']}), aber der Ziel-Service antwortet mit einer "
                "'nicht gefunden'-Seite. Ein Angreifer kann die Ziel-Ressource "
                "beanspruchen und beliebige Inhalte auf der Subdomain der Praxis hosten — "
                "inklusive Phishing-Login-Seiten mit gültigem TLS-Zertifikat."
            ),
            # Takeover requires attacker to register the resource at the target
            # service + host phishing content — non-trivial but cheap. Phishing
            # with valid TLS on a trusted subdomain = severe brand abuse.
            severity=Severity.HIGH,
            category="Step-2 Analyse",
            evidence=d,
            recommendation=(
                f"Entweder den CNAME-Record für {d['hostname']} löschen oder die "
                f"Ressource bei {d['service']} neu anlegen/beanspruchen."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 3 (DNS-Hygiene)",
        ))
