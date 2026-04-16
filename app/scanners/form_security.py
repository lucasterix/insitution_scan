"""Form security scanner: CSRF token detection + MFA/2FA field detection.

Crawls discovered pages for HTML forms and checks:
1. Login forms (contains <input type="password">) — flags if no CSRF token present.
2. MFA/2FA presence — looks for TOTP/authenticator/OTP fields near login forms.
3. Forms posting to external domains — potential data exfiltration.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from urllib.parse import urlparse

import httpx

from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

FORM_RE = re.compile(r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
ACTION_RE = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
INPUT_RE = re.compile(r'<input[^>]*>', re.IGNORECASE)
TYPE_RE = re.compile(r'type=["\']([^"\']+)["\']', re.IGNORECASE)
NAME_RE = re.compile(r'name=["\']([^"\']+)["\']', re.IGNORECASE)

CSRF_FIELD_NAMES = {
    "csrf", "csrftoken", "csrf_token", "_csrf", "xsrf", "_xsrf",
    "xsrf_token", "authenticity_token", "_token", "token",
    "csrfmiddlewaretoken", "anti-csrf-token", "__requestverificationtoken",
    "nonce", "_wpnonce", "form_token", "form_build_id",
}

MFA_INDICATORS = {
    "totp", "otp", "mfa", "2fa", "two-factor", "authenticator",
    "verification_code", "sms_code", "backup_code", "security_code",
}

LOGIN_PATHS = ("/login", "/signin", "/wp-login.php", "/user/login", "/auth/login",
               "/admin/login", "/administrator", "/account/login")


def _fetch(url: str) -> tuple[str, str] | None:
    try:
        with httpx.Client(
            timeout=4.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}
        ) as client:
            r = client.get(url)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    if "text/html" not in r.headers.get("content-type", "").lower():
        return None
    return url, r.text[:300_000]


def _analyze_html(url: str, html: str, domain: str) -> tuple[list[dict], list[dict], bool, list[dict]]:
    """Return (login_forms, csrf_missing, mfa_detected, external_action) for one page."""
    login_forms_found: list[dict] = []
    csrf_missing: list[dict] = []
    mfa_detected = False
    external_action: list[dict] = []

    for form_match in FORM_RE.finditer(html):
        form_html = form_match.group(0)
        form_body = form_match.group(1)

        if not re.search(r'type=["\']password["\']', form_html, re.IGNORECASE):
            continue

        login_forms_found.append({"url": url})

        has_csrf = False
        for input_match in INPUT_RE.finditer(form_body):
            input_tag = input_match.group(0).lower()
            name_match = NAME_RE.search(input_tag)
            if name_match:
                field_name = name_match.group(1).lower().replace("-", "").replace("_", "")
                if any(csrf_name.replace("-", "").replace("_", "") in field_name for csrf_name in CSRF_FIELD_NAMES):
                    has_csrf = True
                    break
            type_match = TYPE_RE.search(input_tag)
            if type_match and type_match.group(1).lower() == "hidden":
                name_m = NAME_RE.search(input_tag)
                if name_m and any(c in name_m.group(1).lower() for c in ("csrf", "token", "nonce", "xsrf")):
                    has_csrf = True
                    break

        if not has_csrf:
            csrf_missing.append({"url": url})

        if any(indicator in form_html.lower() for indicator in MFA_INDICATORS):
            mfa_detected = True

        action_match = ACTION_RE.search(form_html)
        if action_match:
            action = action_match.group(1)
            if action.startswith("http"):
                action_host = urlparse(action).hostname or ""
                if action_host and not (action_host == domain or action_host.endswith("." + domain)):
                    external_action.append({"url": url, "action": action[:200]})

    return login_forms_found, csrf_missing, mfa_detected, external_action


def check_form_security(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("Form-Security (CSRF/MFA)", 90)

    site_crawl = result.metadata.get("site_crawl") or {}
    pages = site_crawl.get("pages_crawled") or []

    login_urls = [f"https://{domain}{p}" for p in LOGIN_PATHS]
    urls_to_check = list(set(pages + login_urls))[:20]

    login_forms_found: list[dict] = []
    csrf_missing: list[dict] = []
    mfa_detected = False
    external_action: list[dict] = []

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_fetch, u) for u in urls_to_check]
        for fut in as_completed(futures):
            res = fut.result()
            if not res:
                continue
            url, html = res
            lf, cm, mfa, ea = _analyze_html(url, html, domain)
            login_forms_found.extend(lf)
            csrf_missing.extend(cm)
            mfa_detected = mfa_detected or mfa
            external_action.extend(ea)

    if not login_forms_found:
        return

    result.metadata["form_security"] = {
        "login_forms": len(login_forms_found),
        "csrf_missing": len(csrf_missing),
        "mfa_detected": mfa_detected,
        "external_actions": external_action,
    }

    if csrf_missing:
        result.add(Finding(
            id="auth.csrf_token_missing",
            title=f"Login-Formular(e) ohne CSRF-Token ({len(csrf_missing)})",
            description=(
                "Login-Formulare ohne CSRF-Schutz sind anfällig für Cross-Site-Request-Forgery. "
                "Ein Angreifer kann einen eingeloggten Nutzer über eine präparierte Seite dazu "
                "bringen, ungewollte Aktionen auszuführen (z.B. Passwort ändern, Daten exportieren)."
            ),
            severity=Severity.MEDIUM,
            category="Authentifizierung",
            evidence={"forms_without_csrf": csrf_missing[:5]},
            recommendation=(
                "CSRF-Token in jedes Formular einbetten. Frameworks: Django ({% csrf_token %}), "
                "Laravel (@csrf), WordPress (wp_nonce_field). SameSite=Strict auf Session-Cookie setzen."
            ),
        ))

    if not mfa_detected:
        result.add(Finding(
            id="auth.mfa_not_detected",
            title="Kein MFA/2FA-Feld auf Login-Seite erkannt",
            description=(
                "Auf den gefundenen Login-Formularen wurde kein Hinweis auf Multi-Faktor-"
                "Authentifizierung (TOTP, SMS-Code, Authenticator) gefunden. Ohne MFA genügt "
                "ein kompromittiertes Passwort für den Vollzugriff."
            ),
            severity=Severity.MEDIUM,
            category="Authentifizierung",
            recommendation=(
                "MFA/2FA erzwingen — mindestens TOTP (Google Authenticator, Authy). "
                "Bei WordPress: Plugin 'WP 2FA' oder 'Wordfence'. Bei M365: Conditional Access."
            ),
            kbv_ref="KBV IT-Sicherheit §390 SGB V — Anlage 2 (Zugriffskontrolle)",
        ))

    if external_action:
        result.add(Finding(
            id="auth.form_external_action",
            title=f"Login-Formular sendet Daten an externe Domain ({len(external_action)})",
            description=(
                "Ein Formular mit Passwort-Feld hat ein action-Attribut das auf eine externe "
                "Domain zeigt. Das könnte ein Phishing-Indikator oder ein eingebettetes SSO sein — "
                "in beiden Fällen muss es verifiziert werden."
            ),
            severity=Severity.HIGH,
            category="Authentifizierung",
            evidence={"forms": external_action[:5]},
        ))
