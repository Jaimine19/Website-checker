"""
Website Security Checker
------------------------
A Streamlit app that scans a public website in real time and grades its
basic security setup (A-F).

Checks performed (all passive, no attacks):
  1. HTTPS in use                         (20 pts)
  2. HTTP automatically redirects to HTTPS (10 pts)
  3. Valid SSL certificate + expiry date   (20 pts)
  4. Four key security headers             (50 pts)

Safety features (important because the app is public):
  - Blocks private / internal addresses (SSRF protection)
  - Only allows standard web ports (80 and 443)
  - Re-validates every redirect
  - Timeouts on every network call
  - Cooldown between scans + result caching

Website features: dark cybersecurity theme, shareable links (?site=example.com),
single-site scan, and side-by-side comparison of two websites.
"""

import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import TypedDict, cast
from urllib.parse import urljoin, urlparse

import requests
import streamlit as st

# ----------------------------- Types --------------------------------------


class CertResult(TypedDict, total=False):  # noqa: F401  (used as return annotation)
    ok: bool
    days_left: int
    expires: str        # ISO-8601, machine-readable
    expires_label: str  # "DD Mon YYYY", human-readable
    issuer: str
    error: str


# ----------------------------- Settings -----------------------------------

AUTHOR = "Jaimine"

TIMEOUT = 6
MAX_REDIRECTS = 5
COOLDOWN_SECONDS = 3
CACHE_SECONDS = 120
REDIRECT_CODES = {301, 302, 303, 307, 308}
REQUEST_HEADERS = {
    "User-Agent": "WebsiteSecurityChecker/1.0 (educational project)"
}

# (header key, display name, points, why it matters)
SECURITY_HEADERS = [
    (
        "strict-transport-security",
        "Strict-Transport-Security (HSTS)",
        15,
        "Forces browsers to always use HTTPS, which blocks downgrade attacks.",
    ),
    (
        "content-security-policy",
        "Content-Security-Policy (CSP)",
        15,
        "Controls which scripts and resources can load, reducing XSS risk.",
    ),
    (
        "x-frame-options",
        "X-Frame-Options",
        10,
        "Stops other sites from embedding this page in a frame (clickjacking).",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        10,
        "Stops browsers from guessing file types (MIME sniffing attacks).",
    ),
]


class ScanError(Exception):
    """A problem we can explain to the user in plain language."""


# --------------------------- Safety helpers --------------------------------


def resolve_public_ips(host):
    """Look up a hostname and make sure every address is a public one."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise ScanError(f"Could not find '{host}'. Please check the spelling.")

    ips = []
    for info in infos:
        host_str = cast(str, info[4][0])
        ip = ipaddress.ip_address(host_str.split("%")[0])
        if not ip.is_global:
            raise ScanError(
                "For safety, this tool only scans public websites. "
                "Private or internal addresses are blocked."
            )
        if str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise ScanError(f"Could not find '{host}'.")
    return ips


def validate_url(url):
    """Allow only http/https, standard ports, and public hosts."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ScanError("Please enter a valid website address, e.g. example.com")
    try:
        port = parsed.port
    except ValueError:
        raise ScanError("That website address does not look valid.")
    if port not in (None, 80, 443):
        raise ScanError("Only standard web ports (80 and 443) are allowed.")
    resolve_public_ips(parsed.hostname)


# ----------------------------- Scan steps ----------------------------------


def fetch(url):
    """GET a page, following redirects manually so each hop is validated."""
    session = requests.Session()
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        validate_url(current)
        resp = session.get(
            current,
            headers=REQUEST_HEADERS,
            timeout=TIMEOUT,
            allow_redirects=False,
            stream=True,
        )
        try:
            location = resp.headers.get("Location")
            if resp.status_code in REDIRECT_CODES and location:
                current = urljoin(current, location)
                continue
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return current, resp.status_code, headers
        finally:
            resp.close()
    raise ScanError("The website redirected too many times.")


def check_http_redirect(host):
    """Does plain http://host/ send visitors to https://?"""
    try:
        url = f"http://{host}/"
        validate_url(url)
        resp = requests.get(
            url,
            headers=REQUEST_HEADERS,
            timeout=TIMEOUT,
            allow_redirects=False,
            stream=True,
        )
        status = resp.status_code
        location = resp.headers.get("Location", "")
        resp.close()
        return status in REDIRECT_CODES and location.lower().startswith("https://")
    except (ScanError, requests.exceptions.RequestException):
        return False


def check_certificate(host) -> CertResult:
    """Connect on port 443 and read the SSL certificate."""
    try:
        ips = resolve_public_ips(host)
        context = ssl.create_default_context()
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        with socket.create_connection((ips[0], 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert(binary_form=False)

        if not cert:
            raise ssl.SSLError("No certificate returned by peer")
        not_after = cast(str, cert["notAfter"])
        expires = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(not_after), tz=timezone.utc
        )
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 0:
            return {"ok": False, "error": "Certificate has already expired."}
        raw_issuer = cast(tuple[tuple[tuple[str, str], ...], ...], cert.get("issuer", ()))
        issuer = {k: v for rdn in raw_issuer for k, v in rdn}
        issuer_name: str = next(
            (issuer[k] for k in ("organizationName", "commonName") if k in issuer),
            "Unknown",
        )
        return {
            "ok": True,
            "days_left": days_left,
            "expires": expires.isoformat(),
            "expires_label": expires.strftime("%d %b %Y"),
            "issuer": issuer_name,
        }
    except ssl.SSLCertVerificationError as err:
        return {"ok": False, "error": f"Certificate is not trusted ({err.verify_message})."}
    except (ssl.SSLError, OSError, ScanError):
        return {"ok": False, "error": "Could not open a secure HTTPS connection."}


# ----------------------------- Scoring -------------------------------------


def make_check(name, points, max_points, detail, why):
    if points >= max_points:
        status = "pass"
    elif points <= 0:
        status = "fail"
    else:
        status = "warn"
    return {
        "name": name,
        "points": points,
        "max": max_points,
        "status": status,
        "detail": detail,
        "why": why,
    }


def grade_for(score):
    for letter, minimum in (("A", 90), ("B", 75), ("C", 60), ("D", 40)):
        if score >= minimum:
            return letter
    return "F"


def build_checks(final_url, headers, redirect_ok, cert):
    checks = []

    https_ok = urlparse(final_url).scheme == "https"
    checks.append(
        make_check(
            "Uses HTTPS",
            20 if https_ok else 0,
            20,
            "The site loads over HTTPS." if https_ok else "The site loads over plain HTTP.",
            "HTTPS encrypts traffic so attackers on the network cannot read or change it.",
        )
    )

    checks.append(
        make_check(
            "HTTP redirects to HTTPS",
            10 if redirect_ok else 0,
            10,
            "Visitors using http:// are sent to https://."
            if redirect_ok
            else "No automatic redirect from http:// to https:// was found.",
            "Without a redirect, people who type the plain address stay unprotected.",
        )
    )

    if cert["ok"]:
        if cert["days_left"] >= 15:
            points, detail = 20, f"Valid until {cert['expires_label']} ({cert['days_left']} days left)."
        else:
            points, detail = 10, f"Expires soon: {cert['expires_label']} ({cert['days_left']} days left)."
        detail += f" Issued by {cert['issuer']}."
    else:
        points, detail = 0, cert["error"]
    checks.append(
        make_check(
            "Valid SSL certificate",
            points,
            20,
            detail,
            "An expired or untrusted certificate triggers browser warnings and breaks trust.",
        )
    )

    csp = headers.get("content-security-policy", "").lower()
    for key, name, pts, why in SECURITY_HEADERS:
        present = key in headers
        if key == "x-frame-options" and "frame-ancestors" in csp:
            present = True
        checks.append(
            make_check(
                name,
                pts if present else 0,
                pts,
                "Header is present." if present else "Header is missing.",
                why,
            )
        )
    return checks


# ------------------------------ Scanning -----------------------------------


@st.cache_data(ttl=CACHE_SECONDS, show_spinner=False)
def run_scan(raw_input):
    """Run all checks. Always returns a dict and never raises."""
    try:
        candidates = (
            [raw_input]
            if "://" in raw_input
            else [f"https://{raw_input}", f"http://{raw_input}"]
        )

        result = None
        for candidate in candidates:
            try:
                final_url, status, headers = fetch(candidate)
                result = (candidate, final_url, status, headers)
                break
            except requests.exceptions.SSLError:
                raise ScanError(
                    "The site's SSL certificate could not be verified. "
                    "That is itself a security problem."
                )
            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
            ):
                continue
        if result is None:
            raise ScanError("Could not connect to the website. Is the address correct?")

        start_url, final_url, status, headers = result
        start_host = urlparse(start_url).hostname
        final_host = urlparse(final_url).hostname

        redirect_ok = check_http_redirect(start_host)
        cert = check_certificate(final_host)
        checks = build_checks(final_url, headers, redirect_ok, cert)
        score = sum(c["points"] for c in checks)

        return {
            "ok": True,
            "final_url": final_url,
            "status": status,
            "checks": checks,
            "score": score,
            "grade": grade_for(score),
            "scanned_at": datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC"),
        }
    except ScanError as err:
        return {"ok": False, "error": str(err)}
    except Exception:
        return {
            "ok": False,
            "error": "Something went wrong while scanning. Please try another website.",
        }


# --------------------------------- UI / Styles -----------------------------

APP_CSS = """
<style>
/* ── Import ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

/* ── Reset & base ── */
html, body, [class*="css"] {
    font-family: 'Inter', system-ui, sans-serif;
}
#MainMenu, footer, header { visibility: hidden; }

/* ── Hero banner ── */
.hero {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
    border: 1px solid #334155;
    border-radius: 16px;
    padding: 2.5rem 2rem 2rem;
    margin-bottom: 1.5rem;
    text-align: center;
    position: relative;
    overflow: hidden;
}
.hero::before {
    content: '';
    position: absolute;
    inset: 0;
    background: radial-gradient(ellipse at 50% 0%, rgba(56,189,248,0.12) 0%, transparent 70%);
    pointer-events: none;
}
.hero-icon {
    font-size: 3rem;
    display: block;
    margin-bottom: 0.5rem;
    filter: drop-shadow(0 0 18px rgba(56,189,248,0.5));
}
.hero h1 {
    font-size: 2.2rem;
    font-weight: 700;
    background: linear-gradient(90deg, #38bdf8, #818cf8, #38bdf8);
    background-size: 200%;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    animation: shimmer 3s linear infinite;
    margin: 0 0 0.4rem;
}
@keyframes shimmer {
    0%   { background-position: 0% }
    100% { background-position: 200% }
}
.hero p {
    color: #94a3b8;
    font-size: 1rem;
    margin: 0 0 1.5rem;
}
.stat-strip {
    display: flex;
    justify-content: center;
    gap: 2.5rem;
    flex-wrap: wrap;
}
.stat-item {
    text-align: center;
}
.stat-num {
    display: block;
    font-size: 1.6rem;
    font-weight: 700;
    color: #38bdf8;
    font-family: 'JetBrains Mono', monospace;
}
.stat-label {
    font-size: 0.72rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

/* ── Feature cards (intro) ── */
.feat-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 1.4rem 1.2rem;
    text-align: center;
    height: 100%;
    transition: border-color 0.2s, transform 0.2s;
}
.feat-card:hover {
    border-color: #38bdf8;
    transform: translateY(-3px);
}
.feat-card .feat-icon {
    font-size: 2rem;
    margin-bottom: 0.6rem;
    display: block;
}
.feat-card h4 {
    color: #e2e8f0;
    font-size: 0.95rem;
    font-weight: 600;
    margin: 0 0 0.4rem;
}
.feat-card p {
    color: #94a3b8;
    font-size: 0.82rem;
    line-height: 1.5;
    margin: 0;
}

/* ── Check rubric table ── */
.rubric-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
    margin-top: 0.8rem;
}
.rubric-table th {
    background: #1e293b;
    color: #94a3b8;
    font-weight: 600;
    padding: 0.55rem 0.8rem;
    text-align: left;
    border-bottom: 1px solid #334155;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.rubric-table td {
    padding: 0.5rem 0.8rem;
    border-bottom: 1px solid #1e293b;
    color: #cbd5e1;
    vertical-align: middle;
}
.rubric-table tr:last-child td { border-bottom: none; }
.rubric-table tr:hover td { background: rgba(56,189,248,0.04); }
.pts-badge {
    display: inline-block;
    background: rgba(56,189,248,0.15);
    color: #38bdf8;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    border-radius: 6px;
    padding: 0.15rem 0.55rem;
    font-size: 0.78rem;
}

/* ── Grade badge ── */
.grade-wrap {
    display: flex;
    align-items: center;
    gap: 1.5rem;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 16px;
    padding: 1.4rem 1.8rem;
    margin-bottom: 1rem;
}
.grade-badge {
    width: 72px; height: 72px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 2rem; font-weight: 700;
    flex-shrink: 0;
    font-family: 'JetBrains Mono', monospace;
}
.grade-A { background: rgba(34,197,94,0.18);  color: #22c55e; border: 2px solid #22c55e; }
.grade-B { background: rgba(132,204,22,0.18); color: #84cc16; border: 2px solid #84cc16; }
.grade-C { background: rgba(234,179,8,0.18);  color: #eab308; border: 2px solid #eab308; }
.grade-D { background: rgba(249,115,22,0.18); color: #f97316; border: 2px solid #f97316; }
.grade-F { background: rgba(239,68,68,0.18);  color: #ef4444; border: 2px solid #ef4444; }
.grade-info h3 { margin: 0 0 0.2rem; color: #e2e8f0; font-size: 1rem; }
.grade-info .score-text {
    font-size: 1.8rem; font-weight: 700;
    color: #38bdf8;
    font-family: 'JetBrains Mono', monospace;
}
.grade-info .scanned-at { color: #64748b; font-size: 0.78rem; margin-top: 0.3rem; }

/* ── Progress bar ── */
.score-bar-outer {
    background: #1e293b;
    border-radius: 999px;
    height: 10px;
    overflow: hidden;
    margin: 0.6rem 0 1rem;
}
.score-bar-inner {
    height: 100%;
    border-radius: 999px;
    transition: width 0.6s ease;
}
.bar-A { background: linear-gradient(90deg, #22c55e, #4ade80); }
.bar-B { background: linear-gradient(90deg, #84cc16, #bef264); }
.bar-C { background: linear-gradient(90deg, #eab308, #fde047); }
.bar-D { background: linear-gradient(90deg, #f97316, #fb923c); }
.bar-F { background: linear-gradient(90deg, #ef4444, #f87171); }

/* ── Check cards ── */
.check-card {
    border-radius: 10px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.6rem;
    border-left: 4px solid;
    display: flex;
    align-items: flex-start;
    gap: 0.9rem;
}
.check-pass { background: rgba(34,197,94,0.07);  border-color: #22c55e; }
.check-warn { background: rgba(234,179,8,0.07);  border-color: #eab308; }
.check-fail { background: rgba(239,68,68,0.07);  border-color: #ef4444; }
.check-icon { font-size: 1.3rem; flex-shrink: 0; line-height: 1; margin-top: 2px; }
.check-body { flex: 1; min-width: 0; }
.check-title {
    font-weight: 600; color: #e2e8f0; font-size: 0.9rem;
    display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;
}
.check-pts {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem; color: #64748b;
    background: #1e293b; border-radius: 6px;
    padding: 0.1rem 0.45rem;
    white-space: nowrap;
}
.check-detail { color: #94a3b8; font-size: 0.82rem; margin-top: 0.3rem; line-height: 1.5; }
.check-why    { color: #475569; font-size: 0.78rem; margin-top: 0.25rem; font-style: italic; }

/* ── Comparison summary cards ── */
.cmp-header {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 1.4rem 1.5rem;
}
.cmp-site-label {
    font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em;
    color: #64748b; margin-bottom: 0.3rem;
}
.cmp-site-name { font-size: 1.1rem; font-weight: 700; color: #e2e8f0; margin-bottom: 0.8rem; }
.cmp-grade-row { display: flex; align-items: center; gap: 1rem; }
.cmp-score-big {
    font-size: 2rem; font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    color: #38bdf8;
}
.cmp-grade-small {
    width: 46px; height: 46px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.2rem; font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
}
.winner-banner {
    background: linear-gradient(135deg, rgba(34,197,94,0.15), rgba(56,189,248,0.08));
    border: 1px solid rgba(34,197,94,0.3);
    border-radius: 10px;
    padding: 0.9rem 1.2rem;
    color: #86efac;
    font-weight: 600;
    font-size: 0.95rem;
    text-align: center;
    margin-top: 1rem;
}
.tie-banner {
    background: rgba(56,189,248,0.08);
    border: 1px solid rgba(56,189,248,0.25);
    border-radius: 10px;
    padding: 0.9rem 1.2rem;
    color: #7dd3fc;
    font-weight: 600;
    font-size: 0.95rem;
    text-align: center;
    margin-top: 1rem;
}

/* ── Comparison HTML table ── */
.cmp-table-wrap { overflow-x: auto; margin-top: 0.5rem; }
.cmp-table {
    width: 100%; border-collapse: collapse;
    font-size: 0.83rem;
}
.cmp-table th {
    background: #1e293b; color: #94a3b8;
    padding: 0.6rem 0.9rem;
    text-align: left; font-weight: 600;
    border-bottom: 1px solid #334155;
    font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;
    white-space: nowrap;
}
.cmp-table td {
    padding: 0.55rem 0.9rem;
    border-bottom: 1px solid #1e293b;
    color: #cbd5e1; vertical-align: middle;
}
.cmp-table tr:hover td { background: rgba(56,189,248,0.04); }
.cmp-table tr.total-row td {
    background: rgba(56,189,248,0.07);
    font-weight: 700;
    color: #e2e8f0;
    border-top: 1px solid #334155;
}
.cell-pass { color: #4ade80; font-weight: 600; }
.cell-warn { color: #facc15; font-weight: 600; }
.cell-fail { color: #f87171; font-weight: 600; }
.cell-winner { color: #818cf8; font-weight: 600; }
.cell-tie    { color: #64748b; }

/* ── Section heading accent ── */
.section-heading {
    font-size: 1.1rem; font-weight: 700;
    color: #e2e8f0;
    border-left: 3px solid #38bdf8;
    padding-left: 0.7rem;
    margin: 1.4rem 0 0.8rem;
}

/* ── Streamlit overrides ── */
div[data-testid="stTabs"] button {
    font-weight: 600;
    font-size: 0.9rem;
}
div[data-testid="stTextInput"] input {
    border-radius: 8px;
    font-size: 0.95rem;
}
div[data-testid="stForm"] {
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 1.2rem;
    background: #0f172a;
}
.stButton > button, div[data-testid="stFormSubmitButton"] > button {
    border-radius: 8px;
    font-weight: 600;
    letter-spacing: 0.02em;
}
</style>
"""


# --------------------------------- Reports ---------------------------------


def build_report(result):
    """Plain-text report for the download button."""
    lines = [
        "WEBSITE SECURITY REPORT",
        f"Site: {result['final_url']}",
        f"Scanned: {result['scanned_at']}",
        f"Grade: {result['grade']}   Score: {result['score']}/100",
        "",
    ]
    for check in result["checks"]:
        lines.append(f"[{check['status'].upper()}] {check['name']} ({check['points']}/{check['max']})")
        lines.append(f"    {check['detail']}")
    lines += ["", "Generated by Website Security Checker (passive checks only)."]
    return "\n".join(lines)


def build_compare_report(result_a, result_b, label_a, label_b):
    """Plain-text comparison report for the download button."""
    lines = [
        "WEBSITE SECURITY COMPARISON REPORT",
        f"Site A ({label_a}): {result_a['final_url']}",
        f"Site B ({label_b}): {result_b['final_url']}",
        f"Scanned: {result_a['scanned_at']}",
        "",
        f"{'Check':<35} {label_a:^20} {label_b:^20}",
        "-" * 75,
    ]
    b_map = {c["name"]: c for c in result_b["checks"]}
    for check in result_a["checks"]:
        b = b_map.get(check["name"])
        a_cell = f"{check['points']}/{check['max']} ({check['status'].upper()})"
        b_cell = f"{b['points']}/{b['max']} ({b['status'].upper()})" if b else "N/A"
        lines.append(f"{check['name']:<35} {a_cell:^20} {b_cell:^20}")
    lines += [
        "-" * 75,
        f"{'TOTAL SCORE':<35} {result_a['score']:^20} {result_b['score']:^20}",
        f"{'GRADE':<35} {result_a['grade']:^20} {result_b['grade']:^20}",
        "",
        "Generated by Website Security Checker (passive checks only).",
    ]
    return "\n".join(lines)


# --------------------------------- UI helpers ------------------------------


def _grade_color(grade):
    return {"A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316"}.get(grade, "#ef4444")


def _score_bar_html(score, grade):
    color_class = f"bar-{grade}"
    return (
        f'<div class="score-bar-outer">'
        f'<div class="score-bar-inner {color_class}" style="width:{score}%"></div>'
        f'</div>'
    )


def _grade_badge_html(grade, size_class="grade-badge"):
    return f'<div class="{size_class} grade-{grade}">{grade}</div>'


def _check_card_html(check):
    icon = {"pass": "✅", "warn": "⚠️", "fail": "❌"}[check["status"]]
    css = f"check-{check['status']}"
    pts = f"{check['points']}/{check['max']} pts"
    return (
        f'<div class="check-card {css}">'
        f'  <span class="check-icon">{icon}</span>'
        f'  <div class="check-body">'
        f'    <div class="check-title">'
        f'      <span>{check["name"]}</span>'
        f'      <span class="check-pts">{pts}</span>'
        f'    </div>'
        f'    <div class="check-detail">{check["detail"]}</div>'
        f'    <div class="check-why">{check["why"]}</div>'
        f'  </div>'
        f'</div>'
    )


# --------------------------------- UI sections -----------------------------


def show_results(result):
    if not result["ok"]:
        st.error(f"⚠️ {result['error']}")
        return

    score, grade = result["score"], result["grade"]

    # Grade / score header card
    verdict_text = {
        "A": "Excellent security posture.",
        "B": "Good security — minor gaps remain.",
        "C": "Average — several protections missing.",
        "D": "Below average — significant risks present.",
        "F": "Poor — critical protections are missing.",
    }.get(grade, "")

    st.markdown(
        f'<div class="grade-wrap">'
        f'  {_grade_badge_html(grade)}'
        f'  <div class="grade-info">'
        f'    <h3>{verdict_text}</h3>'
        f'    <span class="score-text">{score}<span style="font-size:1rem;color:#64748b">/100</span></span>'
        f'    <div class="scanned-at">🔗 {result["final_url"]}  ·  {result["scanned_at"]}</div>'
        f'  </div>'
        f'</div>'
        f'{_score_bar_html(score, grade)}',
        unsafe_allow_html=True,
    )

    # Check cards
    st.markdown('<div class="section-heading">Security Checks</div>', unsafe_allow_html=True)
    cards_html = "".join(_check_card_html(c) for c in result["checks"])
    st.markdown(cards_html, unsafe_allow_html=True)

    st.download_button(
        "⬇️ Download full report",
        data=build_report(result),
        file_name="security-report.txt",
        mime="text/plain",
    )


def show_comparison(result_a, result_b, label_a, label_b):
    """Render a styled side-by-side comparison."""
    if not result_a["ok"]:
        st.error(f"**{label_a}:** {result_a['error']}")
        return
    if not result_b["ok"]:
        st.error(f"**{label_b}:** {result_b['error']}")
        return

    # ── Summary cards ──
    st.markdown('<div class="section-heading">Summary</div>', unsafe_allow_html=True)
    col_a, col_b = st.columns(2)

    def _summary_card(result, label):
        g = result["grade"]
        color = _grade_color(g)
        badge = _grade_badge_html(g, "cmp-grade-small")
        return (
            f'<div class="cmp-header">'
            f'  <div class="cmp-site-label">Site</div>'
            f'  <div class="cmp-site-name">{label}</div>'
            f'  <div class="cmp-grade-row">'
            f'    {badge}'
            f'    <span class="cmp-score-big" style="color:{color}">{result["score"]}</span>'
            f'    <span style="color:#64748b;font-size:0.85rem">/100</span>'
            f'  </div>'
            f'  {_score_bar_html(result["score"], g)}'
            f'  <div style="color:#64748b;font-size:0.75rem;margin-top:0.3rem">{result["final_url"]}</div>'
            f'</div>'
        )

    col_a.markdown(_summary_card(result_a, label_a), unsafe_allow_html=True)
    col_b.markdown(_summary_card(result_b, label_b), unsafe_allow_html=True)

    # ── Comparison table ──
    st.markdown('<div class="section-heading">Detailed Comparison</div>', unsafe_allow_html=True)

    status_css = {"pass": "cell-pass", "warn": "cell-warn", "fail": "cell-fail"}
    status_icon = {"pass": "✅", "warn": "⚠️", "fail": "❌"}

    b_map = {c["name"]: c for c in result_b["checks"]}
    rows_html = ""
    for ca in result_a["checks"]:
        cb = b_map.get(ca["name"])
        css_a = status_css[ca["status"]]
        css_b = status_css[cb["status"]] if cb else ""
        icon_a = status_icon[ca["status"]]
        icon_b = status_icon[cb["status"]] if cb else "—"
        pts_a = f"{ca['points']}/{ca['max']}"
        pts_b = f"{cb['points']}/{cb['max']}" if cb else "N/A"
        det_a = ca["detail"]
        det_b = cb["detail"] if cb else "—"

        raw_a = ca["points"]
        raw_b = cb["points"] if cb else 0
        if raw_a > raw_b:
            winner_html = f'<span class="cell-winner">✦ {label_a}</span>'
        elif raw_b > raw_a:
            winner_html = f'<span class="cell-winner">✦ {label_b}</span>'
        else:
            winner_html = '<span class="cell-tie">Tie</span>'

        rows_html += (
            f"<tr>"
            f"  <td>{ca['name']}</td>"
            f"  <td class='{css_a}'>{icon_a} {pts_a}</td>"
            f"  <td style='color:#94a3b8'>{det_a}</td>"
            f"  <td class='{css_b}'>{icon_b} {pts_b}</td>"
            f"  <td style='color:#94a3b8'>{det_b}</td>"
            f"  <td>{winner_html}</td>"
            f"</tr>"
        )

    # Totals row
    diff = result_a["score"] - result_b["score"]
    overall_winner = (
        f'<span class="cell-winner">✦ {label_a}</span>' if diff > 0
        else (f'<span class="cell-winner">✦ {label_b}</span>' if diff < 0
              else '<span class="cell-tie">Tie</span>')
    )
    rows_html += (
        f'<tr class="total-row">'
        f'  <td>TOTAL SCORE</td>'
        f'  <td>{result_a["score"]}/100 &nbsp; Grade {result_a["grade"]}</td>'
        f'  <td></td>'
        f'  <td>{result_b["score"]}/100 &nbsp; Grade {result_b["grade"]}</td>'
        f'  <td></td>'
        f'  <td>{overall_winner}</td>'
        f'</tr>'
    )

    table_html = (
        '<div class="cmp-table-wrap">'
        '<table class="cmp-table">'
        '<thead><tr>'
        f'  <th>Check</th>'
        f'  <th>{label_a} Score</th>'
        f'  <th>{label_a} Detail</th>'
        f'  <th>{label_b} Score</th>'
        f'  <th>{label_b} Detail</th>'
        f'  <th>Winner</th>'
        '</tr></thead>'
        f'<tbody>{rows_html}</tbody>'
        '</table>'
        '</div>'
    )
    st.markdown(table_html, unsafe_allow_html=True)

    # ── Verdict banner ──
    if diff > 0:
        verdict = (
            f"🏆 <strong>{label_a}</strong> wins by <strong>{diff} points</strong> "
            f"&nbsp;·&nbsp; Grade {result_a['grade']} vs {result_b['grade']}"
        )
        st.markdown(f'<div class="winner-banner">{verdict}</div>', unsafe_allow_html=True)
    elif diff < 0:
        verdict = (
            f"🏆 <strong>{label_b}</strong> wins by <strong>{abs(diff)} points</strong> "
            f"&nbsp;·&nbsp; Grade {result_b['grade']} vs {result_a['grade']}"
        )
        st.markdown(f'<div class="winner-banner">{verdict}</div>', unsafe_allow_html=True)
    else:
        st.markdown(
            f'<div class="tie-banner">🤝 Both sites are tied — score {result_a["score"]}/100</div>',
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)
    st.download_button(
        "⬇️ Download comparison report",
        data=build_compare_report(result_a, result_b, label_a, label_b),
        file_name="security-comparison.txt",
        mime="text/plain",
    )


def show_intro():
    """Landing content shown before the first scan."""

    # Feature cards
    feat_html = """
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.4rem">
      <div class="feat-card">
        <span class="feat-icon">🔐</span>
        <h4>HTTPS &amp; Redirect</h4>
        <p>Checks whether the site uses encryption and forces visitors to the secure version.</p>
      </div>
      <div class="feat-card">
        <span class="feat-icon">🛡️</span>
        <h4>SSL Certificate</h4>
        <p>Verifies the certificate is trusted, valid, and not about to expire.</p>
      </div>
      <div class="feat-card">
        <span class="feat-icon">📋</span>
        <h4>Security Headers</h4>
        <p>Audits four HTTP headers that defend against XSS, clickjacking, and MIME attacks.</p>
      </div>
    </div>
    """
    st.markdown(feat_html, unsafe_allow_html=True)

    # How it works
    st.markdown('<div class="section-heading">How it works</div>', unsafe_allow_html=True)
    steps_html = """
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.4rem">
      <div class="feat-card">
        <span class="feat-icon">1️⃣</span>
        <h4>Enter a site</h4>
        <p>Type any public website address — no login or account needed.</p>
      </div>
      <div class="feat-card">
        <span class="feat-icon">2️⃣</span>
        <h4>Live scan</h4>
        <p>The app checks HTTPS, the SSL certificate, and security headers in real time.</p>
      </div>
      <div class="feat-card">
        <span class="feat-icon">3️⃣</span>
        <h4>Get a grade</h4>
        <p>Receive an A–F grade, a score out of 100, and a plain-English breakdown.</p>
      </div>
    </div>
    """
    st.markdown(steps_html, unsafe_allow_html=True)

    # Score rubric
    with st.expander("📊 Full scoring breakdown"):
        rubric_html = """
        <table class="rubric-table">
          <thead><tr>
            <th>Check</th><th>Points</th><th>What it verifies</th>
          </tr></thead>
          <tbody>
            <tr><td>Uses HTTPS</td>
                <td><span class="pts-badge">20</span></td>
                <td>The site loads over an encrypted connection</td></tr>
            <tr><td>HTTP → HTTPS redirect</td>
                <td><span class="pts-badge">10</span></td>
                <td>Plain-HTTP visitors are automatically sent to HTTPS</td></tr>
            <tr><td>Valid SSL certificate</td>
                <td><span class="pts-badge">20</span></td>
                <td>Certificate is trusted by browsers and not near expiry</td></tr>
            <tr><td>HSTS header</td>
                <td><span class="pts-badge">15</span></td>
                <td>Browser will always use HTTPS for this domain in future</td></tr>
            <tr><td>CSP header</td>
                <td><span class="pts-badge">15</span></td>
                <td>Restricts which scripts and resources may load</td></tr>
            <tr><td>X-Frame-Options</td>
                <td><span class="pts-badge">10</span></td>
                <td>Prevents the page being embedded in an iframe (clickjacking)</td></tr>
            <tr><td>X-Content-Type-Options</td>
                <td><span class="pts-badge">10</span></td>
                <td>Stops browsers guessing file types (MIME sniffing)</td></tr>
          </tbody>
        </table>
        <p style="color:#64748b;font-size:0.8rem;margin-top:0.8rem">
          <strong style="color:#94a3b8">Grades:</strong>
          &nbsp;A = 90+&nbsp; B = 75+&nbsp; C = 60+&nbsp; D = 40+&nbsp; F = below 40
        </p>
        """
        st.markdown(rubric_html, unsafe_allow_html=True)


def main():
    st.set_page_config(
        page_title="Website Security Checker",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    st.markdown(APP_CSS, unsafe_allow_html=True)

    # Shareable link: ?site=example.com
    if "site_input" not in st.session_state:
        shared = str(st.query_params.get("site", ""))[:200]
        st.session_state["site_input"] = shared
        if shared:
            st.session_state["pending"] = shared

    with st.sidebar:
        st.markdown("## 🔒 Security Checker")
        st.markdown(
            "**Grade scale**\n\n"
            "| Grade | Score |\n|---|---|\n"
            "| A | 90 – 100 |\n| B | 75 – 89 |\n| C | 60 – 74 |\n| D | 40 – 59 |\n| F | 0 – 39 |"
        )
        st.info("Passive checks only — no harmful requests are sent.")

    # ── Hero banner ──
    hero_html = """
    <div class="hero">
      <span class="hero-icon">🔒</span>
      <h1>Website Security Checker</h1>
      <p>Instantly grade the security posture of any public website — or compare two sites side by side.</p>
      <div class="stat-strip">
        <div class="stat-item">
          <span class="stat-num">7</span>
          <span class="stat-label">Checks run</span>
        </div>
        <div class="stat-item">
          <span class="stat-num">100</span>
          <span class="stat-label">Max score</span>
        </div>
        <div class="stat-item">
          <span class="stat-num">A–F</span>
          <span class="stat-label">Grade scale</span>
        </div>
        <div class="stat-item">
          <span class="stat-num">0</span>
          <span class="stat-label">Attacks sent</span>
        </div>
      </div>
    </div>
    """
    st.markdown(hero_html, unsafe_allow_html=True)

    tab_single, tab_compare = st.tabs(["🔍 Single Site", "⚖️ Compare Two Sites"])

    # ------------------------------------------------------------------ #
    #  TAB 1 – Single Site                                                #
    # ------------------------------------------------------------------ #
    with tab_single:
        with st.form("scan_form"):
            raw = st.text_input(
                "🌐 Website address",
                placeholder="e.g. github.com",
                max_chars=200,
                key="site_input",
            )
            submitted = st.form_submit_button("🔍 Scan website", type="primary", use_container_width=True)

        target = st.session_state.pop("pending", None)
        if submitted:
            target = raw

        if target is not None:
            target = target.strip()
            now = time.time()
            if not target:
                st.warning("Please enter a website address.")
            elif now - st.session_state.get("last_scan", 0) < COOLDOWN_SECONDS:
                st.warning("⏳ Please wait a few seconds between scans.")
            else:
                st.session_state["last_scan"] = now
                with st.spinner("🔎 Scanning…"):
                    result = run_scan(target)
                st.session_state["result"] = result
                if result["ok"]:
                    st.query_params["site"] = target

        if "result" in st.session_state:
            show_results(st.session_state["result"])
        else:
            show_intro()

    # ------------------------------------------------------------------ #
    #  TAB 2 – Compare Two Sites                                          #
    # ------------------------------------------------------------------ #
    with tab_compare:
        st.markdown(
            "<p style='color:#94a3b8;margin-bottom:1rem'>"
            "Enter two website addresses to scan them and compare their security posture "
            "in a detailed side-by-side table.</p>",
            unsafe_allow_html=True,
        )

        with st.form("compare_form"):
            col_left, col_right = st.columns(2)
            with col_left:
                site_a = st.text_input(
                    "🌐 Website A", placeholder="e.g. google.com", max_chars=200, key="cmp_a"
                )
            with col_right:
                site_b = st.text_input(
                    "🌐 Website B", placeholder="e.g. example.com", max_chars=200, key="cmp_b"
                )
            compare_submitted = st.form_submit_button(
                "⚖️ Compare websites", type="primary", use_container_width=True
            )

        if compare_submitted:
            site_a = site_a.strip()
            site_b = site_b.strip()
            if not site_a or not site_b:
                st.warning("Please enter both website addresses.")
            elif site_a == site_b:
                st.warning("Please enter two different website addresses.")
            else:
                now = time.time()
                if now - st.session_state.get("last_compare", 0) < COOLDOWN_SECONDS:
                    st.warning("⏳ Please wait a few seconds between scans.")
                else:
                    st.session_state["last_compare"] = now
                    col_sp1, col_sp2 = st.columns(2)
                    with col_sp1:
                        with st.spinner(f"🔎 Scanning {site_a}…"):
                            res_a = run_scan(site_a)
                    with col_sp2:
                        with st.spinner(f"🔎 Scanning {site_b}…"):
                            res_b = run_scan(site_b)
                    st.session_state["compare_result"] = (res_a, res_b, site_a, site_b)

        if "compare_result" in st.session_state:
            res_a, res_b, label_a, label_b = st.session_state["compare_result"]
            show_comparison(res_a, res_b, label_a, label_b)
        else:
            st.markdown(
                '<div style="color:#64748b;text-align:center;padding:2rem 0;">'
                '⚖️ Fill in both fields above and click <strong>Compare websites</strong> '
                'to see the side-by-side security table.'
                '</div>',
                unsafe_allow_html=True,
            )

    # ── Footer ──
    st.markdown(
        f'<div style="text-align:center;color:#475569;font-size:0.78rem;'
        f'padding:1.5rem 0 0.5rem;border-top:1px solid #1e293b;margin-top:1rem">'
        f'Built by <strong style="color:#94a3b8">{AUTHOR}</strong> '
        f'for a cybersecurity bootcamp project &nbsp;·&nbsp; '
        f'Passive checks only — not a full security audit.'
        f'</div>',
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
