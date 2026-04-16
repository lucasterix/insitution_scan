"""Active subdomain brute force via DNS resolution.

Complements the passive crt.sh enumeration with an active wordlist-based
approach: resolve {word}.{domain} for 200 common subdomain names. Any
that resolves to an A record is alive and gets added to the subdomain list.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import dns.exception
import dns.resolver

from app.scanners.base import Finding, ScanResult, Severity

WORDLIST = (
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin",
    "api", "app", "dev", "test", "stage", "staging", "beta", "demo",
    "portal", "login", "vpn", "remote", "secure", "auth", "sso",
    "cms", "blog", "shop", "store", "cdn", "static", "assets", "media",
    "docs", "doc", "wiki", "help", "support", "status", "monitor",
    "grafana", "kibana", "prometheus", "jenkins", "ci", "cd", "git",
    "gitlab", "bitbucket", "jira", "confluence", "redmine",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "search", "es", "elk", "log", "logs", "syslog",
    "backup", "bak", "old", "legacy", "archive", "temp", "tmp",
    "internal", "intern", "intranet", "private", "corp",
    "exchange", "owa", "autodiscover", "outlook", "office",
    "cpanel", "plesk", "whm", "webmin", "panel",
    "ns", "ns1", "ns2", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "relay", "gateway",
    "proxy", "waf", "firewall", "lb", "loadbalancer",
    "staging1", "staging2", "dev1", "dev2", "test1", "test2",
    "m", "mobile", "wap", "touch",
    "img", "image", "images", "pic", "photos", "video", "videos",
    "upload", "uploads", "download", "downloads", "files", "file",
    "crm", "erp", "hr", "finance", "accounting",
    "patient", "patienten", "termine", "termin", "praxis",
    "befund", "befunde", "rezept", "erezept", "labor",
    "kim", "konnektor", "ti", "pvs", "gematik",
    "samedi", "doctolib", "clickdoc", "cgm", "medistar",
    "turbomed", "albis", "duria", "tomedo",
    "webdav", "caldav", "carddav",
    "chat", "im", "matrix", "mattermost", "slack", "teams",
    "cloud", "nextcloud", "owncloud", "seafile",
    "moodle", "lms", "e-learning",
    "print", "printer", "scan", "scanner",
    "camera", "cam", "cctv", "nvr",
    "voip", "sip", "pbx", "telefon",
    "nas", "storage", "share", "smb",
    "vpn2", "ssl", "ipsec", "wireguard", "openvpn",
    "mx3", "pop3", "imap4", "submission",
    "phpmyadmin", "pma", "adminer", "pgadmin",
    "nagios", "zabbix", "cacti", "icinga", "check",
    "ansible", "puppet", "chef", "salt",
    "docker", "container", "registry", "harbor",
    "k8s", "kubernetes", "rancher", "portainer",
    "vault", "consul", "nomad",
    "sentry", "error", "debug", "trace",
    "api-v1", "api-v2", "api-v3", "rest", "graphql", "gql",
    "webhook", "callback", "notify",
    "sandbox", "playground", "preview",
    "email", "newsletter", "marketing",
    "analytics", "tracking", "tag", "pixel",
    "payment", "pay", "checkout", "billing",
    "health", "healthcheck", "healthz", "readiness", "liveness",
    "ws", "websocket", "socket", "realtime",
    "data", "warehouse", "etl", "pipeline",
)

MAX_WORKERS = 20


def _resolve(fqdn: str) -> list[str] | None:
    try:
        answers = dns.resolver.resolve(fqdn, "A", lifetime=2.0)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None


def brute_subdomains(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step(f"Subdomain-Brute-Force ({len(WORDLIST)} Wörter)", 72)

    known = set(result.metadata.get("subdomains") or [])
    newly_found: dict[str, list[str]] = {}

    def task(word: str) -> None:
        fqdn = f"{word}.{domain}"
        if fqdn in known:
            return
        ips = _resolve(fqdn)
        if ips:
            newly_found[fqdn] = ips

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(task, w) for w in WORDLIST]
        for f in as_completed(futures):
            f.result()

    if not newly_found:
        return

    existing_subs = list(result.metadata.get("subdomains") or [])
    for fqdn in newly_found:
        if fqdn not in existing_subs:
            existing_subs.append(fqdn)
    result.metadata["subdomains"] = existing_subs
    result.metadata["subdomain_brute"] = {
        "wordlist_size": len(WORDLIST),
        "new_found": len(newly_found),
        "results": {k: v for k, v in list(newly_found.items())[:50]},
    }

    result.add(Finding(
        id="dns.brute_force_new_subs",
        title=f"Subdomain-Brute-Force: {len(newly_found)} neue Subdomain(s) entdeckt",
        description=(
            f"Über aktives DNS-Brute-Forcing (Wordlist mit {len(WORDLIST)} gängigen "
            "Subdomain-Präfixen) wurden Subdomains gefunden, die nicht in Certificate "
            "Transparency Logs (crt.sh) auftauchen — ein Indiz für interne/versteckte Dienste."
        ),
        severity=Severity.INFO,
        category="DNS",
        evidence={"new_subdomains": list(newly_found.keys())[:30]},
        recommendation="Jede entdeckte Subdomain manuell prüfen: ist sie gewollt öffentlich? Läuft aktuelle Software?",
    ))
