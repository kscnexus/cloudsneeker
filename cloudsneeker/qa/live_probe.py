"""Non-destructive black-box probes against a deployed Cloudsneeker stack.

Covers what can be checked without an account: transport security, response
headers, route protection in the web app, API authentication on every
resource, input handling on the sign-in endpoint, CORS, sign-up policy,
sign-in rate limiting and error-message leakage. It never creates data, never
signs in and never sends a password for a real account (it uses random
addresses under example.invalid).

Usage:
    python -I cloudsneeker/qa/live_probe.py \
        --ui https://cloudsneeker.vercel.app \
        --api https://cloudsneeker-api.southindia.cloudapp.azure.com \
        --out results.json

Exit code is 1 when any probe fails.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import ssl
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

import httpx

LEAK_MARKERS = (
    "Traceback",
    'File "/',
    "django.db",
    "psycopg",
    "SECRET_KEY",
    "DJANGO_",
    "/home/prowler",
    "OperationalError",
    "IntegrityError",
)

# Pages that need a session. Dynamic segments get a random UUID.
PROTECTED_PAGES = [
    "/",
    "/findings",
    "/providers",
    "/scans",
    "/scans/config",
    "/compliance",
    "/resources",
    "/attack-paths",
    "/integrations",
    "/integrations/jira",
    "/integrations/slack",
    "/integrations/email",
    "/integrations/bitbucket",
    "/users",
    "/roles",
    "/invitations",
    "/manage-groups",
    "/mutelist",
    "/profile",
    "/alerts",
    "/lighthouse",
    "/application-security",
    "/application-security/findings",
    "/application-security/new",
    "/governance",
    "/governance/library",
    "/governance/findings",
    "/reports",
    "/triage",
    "/settings/security",
    "/settings/audit-log",
    "/settings/content-versions",
    "/settings/release-notes",
    "/operator",
    "/operator/customers",
    "/operator/plans",
    "/trivy",
    "/custodian",
    "/about",
    "/registry",
    "/demo-tree-view",
    "/demo-expandable-table",
]

# API resources that must reject anonymous callers with 401.
PROTECTED_API = [
    "users",
    "users/me",
    "tenants",
    "roles",
    "providers",
    "provider-groups",
    "scans",
    "findings",
    "finding-groups",
    "resources",
    "overviews/providers",
    "compliance-overviews",
    "integrations",
    "lighthouse-configurations",
    "api-keys",
    "mute-rules",
    "processors",
    "tasks",
    "schedules",
    "saml-config",
    "attack-paths-scans",
    "scan-configurations",
    "alerts/rules",
    "alerts/recipients",
    "ingestions",
    "custodian-policies",
    "custodian-library",
    "custodian-runs",
    "trivy-targets",
    "trivy-runs",
    "report-types",
    "report-runs",
    "report-schedules",
    "report-share-links",
    "audit-events",
    "finding-triages",
    "area-findings",
    "email-delivery-config",
    "slack-app-config",
    "entitlements",
    "operator/me",
    "operator/plans",
    "operator/operators",
    "mfa",
    "mfa/policy",
    "sso/policy",
    "content-versions",
    "content-releases",
]


@dataclass
class Result:
    id: str
    area: str
    scenario: str
    expected: str
    actual: str = ""
    status: str = "PASS"  # PASS | FAIL | BLOCKED | INFO
    severity: str = ""
    evidence: dict = field(default_factory=dict)


RESULTS: list[Result] = []


def record(r: Result) -> Result:
    RESULTS.append(r)
    mark = {"PASS": "ok ", "FAIL": "XX ", "BLOCKED": "-- ", "INFO": "ii "}[r.status]
    print(f"{mark} {r.id:<8} {r.scenario[:70]:<70} {r.actual[:90]}")
    return r


def leaks(text: str) -> list[str]:
    return [m for m in LEAK_MARKERS if m in text]


def rand_email() -> str:
    return f"qa-{secrets.token_hex(6)}@example.invalid"


def jsonapi_token_body(email: str, password: str) -> dict:
    return {
        "data": {
            "type": "tokens",
            "attributes": {"email": email, "password": password},
        }
    }


JSONAPI = {"Content-Type": "application/vnd.api+json", "Accept": "application/vnd.api+json"}


# --------------------------------------------------------------------- transport
def probe_tls(host: str, rid: str) -> None:
    r = Result(rid, "Security/TLS", f"TLS on {host}: TLS1.2+ only, valid cert", "TLS1.0/1.1 refused, cert valid")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert = t.getpeercert()
                ver = t.version()
        weak = []
        for name, proto in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            try:
                c.minimum_version = proto
                c.maximum_version = proto
                with socket.create_connection((host, 443), timeout=10) as s:
                    with c.wrap_socket(s, server_hostname=host):
                        weak.append(name)
            except (ssl.SSLError, OSError, ValueError):
                pass
        r.actual = f"negotiated {ver}; expires {cert.get('notAfter')}; weak accepted={weak or 'none'}"
        if weak:
            r.status, r.severity = "FAIL", "Medium"
    except Exception as e:  # noqa: BLE001
        r.status, r.severity, r.actual = "FAIL", "Critical", f"TLS error: {e}"
    record(r)


def probe_http_redirect(c: httpx.Client, base: str, rid: str) -> None:
    http = base.replace("https://", "http://")
    r = Result(rid, "Security/TLS", f"Plain HTTP redirects to HTTPS ({urlparse(base).hostname})", "301/308 to https")
    try:
        resp = c.get(http + "/", follow_redirects=False)
        loc = resp.headers.get("location", "")
        r.actual = f"{resp.status_code} -> {loc}"
        if resp.status_code not in (301, 302, 307, 308) or not loc.startswith("https://"):
            r.status, r.severity = "FAIL", "Medium"
    except Exception as e:  # noqa: BLE001
        r.status, r.severity, r.actual = "FAIL", "Low", f"error: {e}"
    record(r)


def probe_headers(c: httpx.Client, url: str, rid: str, required: dict[str, str]) -> None:
    r = Result(rid, "Security/Headers", f"Security headers on {urlparse(url).netloc}{urlparse(url).path}", ", ".join(required))
    resp = c.get(url, follow_redirects=False)
    missing = []
    for h, must_contain in required.items():
        v = resp.headers.get(h)
        if v is None or (must_contain and must_contain not in v):
            missing.append(h)
    info = []
    csp = resp.headers.get("content-security-policy", "")
    if "'unsafe-eval'" in csp:
        info.append("CSP script-src allows 'unsafe-eval'")
    if "permissions-policy" not in resp.headers:
        info.append("no Permissions-Policy")
    srv = resp.headers.get("server")
    if srv and srv.lower() not in ("vercel",):
        info.append(f"Server header discloses '{srv}'")
    r.actual = f"missing={missing or 'none'}; notes={info or 'none'}"
    if missing:
        r.status, r.severity = "FAIL", "Medium"
    record(r)


# --------------------------------------------------------------------- web app
def probe_ui(c: httpx.Client, ui: str) -> None:
    n = 0
    for page in PROTECTED_PAGES:
        n += 1
        r = Result(f"UI-{n:03d}", "UI/Route protection", f"Anonymous GET {page} redirects to sign-in", "3xx to /sign-in, no app data")
        try:
            resp = c.get(ui + page, follow_redirects=False)
            loc = resp.headers.get("location", "")
            r.actual = f"{resp.status_code} {loc[:60]}"
            ok = resp.status_code in (302, 303, 307, 308) and "/sign-in" in loc
            if not ok and resp.status_code == 404:
                r.status, r.severity = "INFO", ""
                r.actual += " (route not found)"
            elif not ok:
                r.status, r.severity = "FAIL", "High"
        except Exception as e:  # noqa: BLE001
            r.status, r.severity, r.actual = "FAIL", "Medium", str(e)
        record(r)

    def one(rid, scen, exp, fn):
        r = Result(rid, "UI/Public pages", scen, exp)
        try:
            fn(r)
        except Exception as e:  # noqa: BLE001
            r.status, r.severity, r.actual = "FAIL", "Medium", str(e)
        record(r)

    def sign_in(r):
        resp = c.get(ui + "/sign-in")
        r.actual = f"{resp.status_code}, {len(resp.text)} bytes, has form={'password' in resp.text.lower()}"
        if resp.status_code != 200:
            r.status, r.severity = "FAIL", "Critical"
        if "prowler" in resp.text.lower().replace("prowler-", ""):
            r.actual += "; page text mentions 'prowler'"

    def sign_up(r):
        resp = c.get(ui + "/sign-up", follow_redirects=False)
        loc = resp.headers.get("location", "")
        r.actual = f"{resp.status_code} {loc[:60]}"
        if not (resp.status_code in (302, 307, 308) and "/sign-in" in loc):
            r.status, r.severity = "FAIL", "High"

    def not_found(r):
        resp = c.get(ui + f"/no-such-page-{secrets.token_hex(4)}", follow_redirects=False)
        r.actual = f"{resp.status_code}"
        if resp.status_code >= 500:
            r.status, r.severity = "FAIL", "Low"

    def shared_bogus(r):
        resp = c.get(ui + "/shared-reports/" + secrets.token_urlsafe(24), follow_redirects=False)
        r.actual = f"{resp.status_code}; leaks={leaks(resp.text) or 'none'}"
        if resp.status_code >= 500 or leaks(resp.text):
            r.status, r.severity = "FAIL", "Medium"

    def shared_traversal(r):
        resp = c.get(ui + "/shared-reports/..%2F..%2F..%2Fetc%2Fpasswd", follow_redirects=False)
        r.actual = f"{resp.status_code}; passwd={'root:x:' in resp.text}; leaks={leaks(resp.text) or 'none'}"
        if "root:x:" in resp.text or resp.status_code >= 500 or leaks(resp.text):
            r.status, r.severity = "FAIL", "High"

    def session(r):
        resp = c.get(ui + "/api/auth/session")
        body = resp.text.strip()
        r.actual = f"{resp.status_code} body={body[:40]}"
        if body not in ("null", "{}"):
            r.status, r.severity = "FAIL", "High"

    def xss_callback(r):
        payload = '"><script>alert(1)</script>'
        resp = c.get(ui + "/sign-in", params={"callbackUrl": payload, "error": payload})
        reflected = "<script>alert(1)</script>" in resp.text
        r.actual = f"{resp.status_code}; raw payload reflected={reflected}"
        if reflected:
            r.status, r.severity = "FAIL", "High"

    def open_redirect(r):
        resp = c.get(ui + "/sign-in", params={"callbackUrl": "https://evil.example/"}, follow_redirects=False)
        loc = resp.headers.get("location", "")
        r.actual = f"{resp.status_code} {loc[:60]}"
        if "evil.example" in loc:
            r.status, r.severity = "FAIL", "Medium"

    def clickjack(r):
        resp = c.get(ui + "/sign-in")
        csp = resp.headers.get("content-security-policy", "")
        xfo = resp.headers.get("x-frame-options", "")
        r.actual = f"frame-ancestors none={'frame-ancestors' in csp and chr(39)+'none' in csp}; XFO={xfo or 'absent'}"
        if "frame-ancestors" not in csp and not xfo:
            r.status, r.severity = "FAIL", "Medium"

    one("UI-P01", "GET /sign-in renders the sign-in form", "200 with form", sign_in)
    one("UI-P02", "GET /sign-up redirects (self-registration off)", "3xx to /sign-in", sign_up)
    one("UI-P03", "Unknown route returns 404 page, not 5xx", "404", not_found)
    one("UI-P04", "Bogus shared-report token handled", "4xx/200 notice, no leak", shared_bogus)
    one("UI-P05", "Path traversal via shared-report token", "no file read, no 5xx", shared_traversal)
    one("UI-P06", "Anonymous /api/auth/session is empty", "null/{}", session)
    one("UI-P07", "Reflected XSS via sign-in query params", "payload not reflected raw", xss_callback)
    one("UI-P08", "Open redirect via callbackUrl", "no redirect to foreign host", open_redirect)
    one("UI-P09", "Clickjacking protection", "frame-ancestors 'none' or XFO", clickjack)


# --------------------------------------------------------------------- API
def probe_api(c: httpx.Client, api: str, ui: str, rate_attempts: int) -> None:
    v1 = api + "/api/v1"

    def one(rid, area, scen, exp, fn):
        r = Result(rid, area, scen, exp)
        try:
            fn(r)
        except Exception as e:  # noqa: BLE001
            r.status, r.severity, r.actual = "FAIL", "Medium", f"error: {e}"
        record(r)
        return r

    def live(r):
        resp = c.get(api + "/health/live")
        r.actual = f"{resp.status_code} {resp.elapsed.total_seconds():.2f}s"
        if resp.status_code != 200:
            r.status, r.severity = "FAIL", "Critical"

    def ready(r):
        resp = c.get(api + "/health/ready")
        r.actual = f"{resp.status_code} {resp.text[:80]}"
        if resp.status_code != 200:
            r.status, r.severity = "FAIL", "Critical"
        if leaks(resp.text):
            r.status, r.severity = "FAIL", "Medium"

    one("API-H01", "API/Health", "GET /health/live", "200", live)
    one("API-H02", "API/Health", "GET /health/ready (DB, cache)", "200, no internals", ready)

    for i, path in enumerate(PROTECTED_API, 1):
        def check(r, path=path):
            resp = c.get(f"{v1}/{path}", headers={"Accept": "application/vnd.api+json"})
            r.actual = f"{resp.status_code}"
            if resp.status_code != 401:
                r.status, r.severity = "FAIL", "Critical" if resp.status_code == 200 else "Medium"
                r.actual += f" body={resp.text[:80]}"
            if leaks(resp.text):
                r.status, r.severity = "FAIL", "Medium"
        one(f"API-A{i:02d}", "API/AuthN", f"Anonymous GET /{path}", "401", check)

    def forged(alg_none: bool):
        def _f(r):
            hdr = {"alg": "none" if alg_none else "HS256", "typ": "JWT"}
            now = int(time.time())
            payload = {"sub": "00000000-0000-0000-0000-000000000000", "user_id": "00000000-0000-0000-0000-000000000000",
                       "tenant_id": "00000000-0000-0000-0000-000000000000", "token_type": "access",
                       "exp": now + 600, "iat": now, "iss": "https://api.prowler.com", "aud": "https://api.prowler.com"}
            enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
            sig = "" if alg_none else base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
            tok = f"{enc(hdr)}.{enc(payload)}.{sig}"
            resp = c.get(f"{v1}/users/me", headers={"Authorization": f"Bearer {tok}", "Accept": "application/vnd.api+json"})
            r.actual = f"{resp.status_code}"
            if resp.status_code != 401:
                r.status, r.severity = "FAIL", "Critical"
        return _f

    one("API-J01", "API/JWT", "Forged JWT with alg=none", "401", forged(True))
    one("API-J02", "API/JWT", "Forged JWT with random HS256 signature", "401", forged(False))

    def bad_refresh(r):
        resp = c.post(f"{v1}/tokens/refresh", headers=JSONAPI,
                      json={"data": {"type": "tokens-refresh", "attributes": {"refresh": "not-a-token"}}})
        r.actual = f"{resp.status_code}"
        if resp.status_code not in (400, 401) or leaks(resp.text):
            r.status, r.severity = "FAIL", "Medium"

    one("API-J03", "API/JWT", "Refresh with garbage token", "400/401", bad_refresh)

    def bad_login(r):
        resp = c.post(f"{v1}/tokens", headers=JSONAPI, json=jsonapi_token_body(rand_email(), "Wrong-Passw0rd!"))
        r.actual = f"{resp.status_code} {resp.text[:120]}"
        r.evidence["body"] = resp.text[:300]
        if resp.status_code not in (400, 401) or leaks(resp.text):
            r.status, r.severity = "FAIL", "High"

    one("API-L01", "API/Login", "POST /tokens unknown user", "401 generic error", bad_login)

    def empty_login(r):
        resp = c.post(f"{v1}/tokens", headers=JSONAPI, json=jsonapi_token_body("", ""))
        r.actual = f"{resp.status_code} {resp.text[:120]}"
        if resp.status_code not in (400, 401) or leaks(resp.text):
            r.status, r.severity = "FAIL", "Medium"

    one("API-L02", "API/Login", "POST /tokens empty email/password", "400", empty_login)

    def missing_fields(r):
        resp = c.post(f"{v1}/tokens", headers=JSONAPI, json={"data": {"type": "tokens", "attributes": {}}})
        r.actual = f"{resp.status_code}"
        if resp.status_code not in (400, 401) or leaks(resp.text):
            r.status, r.severity = "FAIL", "Medium"

    one("API-L03", "API/Login", "POST /tokens missing attributes", "400", missing_fields)

    def malformed(r):
        resp = c.post(f"{v1}/tokens", headers=JSONAPI, content=b"{not json")
        r.actual = f"{resp.status_code}; leaks={leaks(resp.text) or 'none'}"
        if resp.status_code >= 500 or leaks(resp.text):
            r.status, r.severity = "FAIL", "Medium"

    one("API-L04", "API/Input", "Malformed JSON body", "400, no traceback", malformed)

    def wrong_ct(r):
        resp = c.post(f"{v1}/tokens", headers={"Content-Type": "text/plain"}, content=b"email=a&password=b")
        r.actual = f"{resp.status_code}"
        if resp.status_code >= 500:
            r.status, r.severity = "FAIL", "Low"

    one("API-L05", "API/Input", "Wrong Content-Type", "4xx", wrong_ct)

    sqli = ["' OR '1'='1' --", "admin'--@x.io", "\" OR 1=1 --", "a@b.c'; SELECT pg_sleep(5);--", "{\"$ne\": null}"]
    for i, p in enumerate(sqli, 1):
        def s(r, p=p):
            t0 = time.monotonic()
            resp = c.post(f"{v1}/tokens", headers=JSONAPI, json=jsonapi_token_body(p, p))
            dt = time.monotonic() - t0
            r.actual = f"{resp.status_code} in {dt:.2f}s"
            if resp.status_code in (200, 201) or resp.status_code >= 500 or leaks(resp.text) or dt > 4.5:
                r.status, r.severity = "FAIL", "Critical"
        one(f"API-S{i:02d}", "API/Injection", f"SQL/NoSQL injection in login: {p[:24]}", "400/401, no delay", s)

    def sqli_filter(r):
        resp = c.get(f"{v1}/findings", params={"filter[check_id]": "x' OR 1=1--"})
        r.actual = f"{resp.status_code}"
        if resp.status_code not in (401,) or leaks(resp.text):
            r.status, r.severity = "FAIL", "Medium"

    one("API-S06", "API/Injection", "Injection in filter param (anon)", "401", sqli_filter)

    def oversized(r):
        resp = c.post(f"{v1}/tokens", headers=JSONAPI, json=jsonapi_token_body(rand_email(), "A" * 2_000_000))
        r.actual = f"{resp.status_code} in {resp.elapsed.total_seconds():.2f}s"
        if resp.status_code >= 500 and resp.status_code != 413:
            r.status, r.severity = "FAIL", "Medium"

    one("API-I01", "API/Input", "2 MB password body", "400/401/413", oversized)

    def signup_closed(r):
        body = {"data": {"type": "users", "attributes": {"name": "QA probe", "email": rand_email(),
                                                          "password": "Qa-" + secrets.token_urlsafe(18) + "9!",
                                                          "company_name": "QA"}}}
        resp = c.post(f"{v1}/users", headers=JSONAPI, json=body)
        r.actual = f"{resp.status_code} {resp.text[:100]}"
        if resp.status_code in (200, 201):
            r.status, r.severity = "FAIL", "Critical"
            r.actual += " (ACCOUNT CREATED - delete it)"
        elif resp.status_code != 403:
            r.status, r.severity = "FAIL", "Medium"

    one("API-R01", "API/Registration", "Uninvited POST /users (sign-up off)", "403 signup_closed", signup_closed)

    def cors(origin: str, allowed: bool):
        def _c(r):
            resp = c.options(f"{v1}/tokens", headers={"Origin": origin, "Access-Control-Request-Method": "POST",
                                                      "Access-Control-Request-Headers": "content-type,authorization"})
            acao = resp.headers.get("access-control-allow-origin")
            acac = resp.headers.get("access-control-allow-credentials")
            r.actual = f"{resp.status_code} ACAO={acao} ACAC={acac}"
            if not allowed and acao in (origin, "*"):
                r.status, r.severity = "FAIL", "High"
            if allowed and acao != origin:
                r.status, r.severity = "INFO", ""
                r.actual += " (UI calls the API server-side, so this is informational)"
        return _c

    one("API-C01", "API/CORS", "Preflight from foreign origin", "no ACAO", cors("https://evil.example", False))
    one("API-C02", "API/CORS", "Preflight from the web app origin", "ACAO = UI origin", cors(ui, True))
    one("API-C03", "API/CORS", "Preflight from Origin: null", "no ACAO", cors("null", False))

    def docs_exposed(r):
        a = c.get(f"{v1}/docs")
        b = c.get(f"{v1}/schema")
        r.actual = f"docs={a.status_code} schema={b.status_code}"
        if a.status_code == 200 or b.status_code == 200:
            r.status = "INFO"
            r.actual += " (public API docs/schema; acceptable if intended)"

    one("API-X01", "API/Exposure", "Public OpenAPI docs/schema", "decision", docs_exposed)

    def admin(r):
        resp = c.get(api + "/admin/", follow_redirects=False)
        r.actual = f"{resp.status_code}"
        if resp.status_code in (200, 302):
            r.status, r.severity = "FAIL", "Medium"

    one("API-X02", "API/Exposure", "Django admin not exposed", "404", admin)

    mcp_headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}

    def mcp_list(r):
        resp = c.post(api + "/mcp", headers=mcp_headers, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        r.actual = f"{resp.status_code}; catalogue public={'tools' in resp.text}"
        if resp.status_code == 200 and "tools" in resp.text:
            r.status, r.severity = "INFO", "Low"
            r.actual += " (tool names/schemas only; upstream design)"

    def mcp_call(r):
        resp = c.post(api + "/mcp", headers=mcp_headers, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "cloudsneeker_list_users", "arguments": {}}})
        rejected = "no usable credential" in resp.text or resp.status_code in (401, 403)
        r.actual = f"{resp.status_code}; rejected={rejected}"
        if not rejected:
            r.status, r.severity = "FAIL", "Critical"

    one("API-X03", "API/Exposure", "Anonymous MCP tools/list", "decision", mcp_list)
    one("API-X07", "API/AuthN", "Anonymous MCP tools/call (list users)", "credential error", mcp_call)

    def trace(r):
        resp = c.request("TRACE", f"{v1}/tokens")
        r.actual = f"{resp.status_code}"
        if resp.status_code == 200:
            r.status, r.severity = "FAIL", "Low"

    one("API-X04", "API/Exposure", "HTTP TRACE disabled", "405/4xx", trace)

    def share_bogus(r):
        for t in (secrets.token_urlsafe(24), "..%2F..%2Fetc%2Fpasswd", "' OR 1=1--"):
            resp = c.get(f"{v1}/shared-reports/{t}")
            if resp.status_code >= 500 or "root:x:" in resp.text or leaks(resp.text):
                r.status, r.severity = "FAIL", "High"
            r.actual += f"{resp.status_code} "

    one("API-X05", "API/Shared reports", "Bogus/traversal/injection share tokens", "404, no leak", share_bogus)

    def not_found(r):
        resp = c.get(f"{v1}/no-such-endpoint")
        r.actual = f"{resp.status_code}; leaks={leaks(resp.text) or 'none'}; debug={'DEBUG = True' in resp.text}"
        if resp.status_code >= 500 or "DEBUG = True" in resp.text or "URLconf" in resp.text:
            r.status, r.severity = "FAIL", "High"

    one("API-X06", "API/Exposure", "Unknown endpoint has no debug page", "404 without URL list", not_found)

    def ratelimit(r):
        codes = []
        email = rand_email()
        for _ in range(rate_attempts):
            resp = c.post(f"{v1}/tokens", headers=JSONAPI, json=jsonapi_token_body(email, "Wrong-" + secrets.token_hex(4)))
            codes.append(resp.status_code)
            if resp.status_code == 429:
                break
        r.actual = f"{len(codes)} attempts; 429 seen={429 in codes}; codes={sorted(set(codes))}"
        if 429 not in codes:
            r.status, r.severity = "FAIL", "High"

    one("API-RL1", "Security/Brute force", f"{rate_attempts} wrong passwords for one account", "429 before the end", ratelimit)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ui", required=True)
    ap.add_argument("--api", required=True)
    ap.add_argument("--out", default="live_probe_results.json")
    ap.add_argument("--rate-attempts", type=int, default=40)
    a = ap.parse_args()
    ui, api = a.ui.rstrip("/"), a.api.rstrip("/")

    with httpx.Client(timeout=30, headers={"User-Agent": "cloudsneeker-qa-probe/1.0"}) as c:
        probe_tls(urlparse(ui).hostname, "SEC-T01")
        probe_tls(urlparse(api).hostname, "SEC-T02")
        probe_http_redirect(c, ui, "SEC-T03")
        probe_http_redirect(c, api, "SEC-T04")
        probe_headers(c, ui + "/sign-in", "SEC-H01", {
            "strict-transport-security": "max-age=", "x-content-type-options": "nosniff",
            "content-security-policy": "frame-ancestors", "referrer-policy": ""})
        probe_headers(c, api + "/api/v1/users", "SEC-H02", {
            "strict-transport-security": "max-age=", "x-content-type-options": "nosniff"})
        probe_ui(c, ui)
        probe_api(c, api, ui, a.rate_attempts)

    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in RESULTS], fh, indent=2)
    counts = {s: sum(1 for r in RESULTS if r.status == s) for s in ("PASS", "FAIL", "INFO", "BLOCKED")}
    print(json.dumps(counts))
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
