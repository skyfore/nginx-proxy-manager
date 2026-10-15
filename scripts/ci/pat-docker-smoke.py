#!/usr/bin/env python3
"""Exercise the built Docker image through its real Nginx and HTTP API.

Requires a fresh app on 127.0.0.1:18081 (admin) / :18080 (proxy) and a
Docker-network service named upstream:80 serving pat-docker-smoke-upstream.
The workflow owns container/volume teardown, including on failure. This test
uses only ephemeral credentials, HTTP fixture hosts and no ACME operations.
Never print request/response bodies, credentials, or unfiltered exceptions.
"""

import hashlib
import http.client
import json
import re
import secrets
import sys
import time
from html.parser import HTMLParser

ADMIN_PORT = 18081
PROXY_PORT = 18080
STARTUP_SECONDS = 120
RELOAD_SECONDS = 30
REQUEST_SECONDS = 15
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
UPSTREAM_BODY = b"pat-docker-smoke-upstream\n"
HOST = "pat-smoke.test"
ALIAS = "pat-smoke-updated.test"
TOKEN_FIELDS = {
    "id", "name", "scopes", "visibility", "created_on", "expires_on",
    "revoked_on", "last_used_on",
}
PRIVATE_FIELDS = {
    "token", "secret", "secret_hash", "password", "password_version",
    "dns_provider_credentials", "certificate_key", "totp_secret",
    "totp_pending_secret", "backup_codes", "debug",
}
KNOWN_SECRETS = []


class SmokeFailure(Exception):
    """A diagnostic constructed by this test, containing no server data."""


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def progress(message):
    print(f"PASS: {message}", flush=True)


def request(method, path, *, token=None, body=None, port=ADMIN_PORT, host=None,
            timeout=REQUEST_SECONDS):
    # Use a fixed loopback connection: no environment proxy, DNS or redirects
    # can forward generated credentials outside this disposable Docker stack.
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Accept": "application/json", "Connection": "close"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if host is not None:
        headers["Host"] = host
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    try:
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        require(len(raw) <= MAX_RESPONSE_BYTES, "HTTP response exceeded safety limit")
        return response.status, response.getheader("Content-Type", ""), raw
    except (OSError, http.client.HTTPException):
        raise SmokeFailure(f"{method} {path}: loopback HTTP request failed") from None
    finally:
        connection.close()


def no_secrets(value, label, *, allow_token=False):
    """Check all nested keys and known secret values without exposing either."""
    if isinstance(value, dict):
        for key, item in value.items():
            require(key not in PRIVATE_FIELDS or (allow_token and key == "token"),
                    f"{label}: response exposed a private field")
            if not (allow_token and key == "token"):
                no_secrets(item, label)
    elif isinstance(value, list):
        for item in value:
            no_secrets(item, label)
    elif isinstance(value, str):
        require(not any(secret in value for secret in KNOWN_SECRETS),
                f"{label}: response exposed credential material")


def api(method, path, *, token=None, body=None, expected=200, allow_token=False):
    status, content_type, raw = request(method, "/api" + path, token=token, body=body)
    label = f"{method} /api{path}"
    require(status == expected, f"{label}: expected HTTP {expected}, got {status}")
    require("application/json" in content_type.lower(), f"{label}: expected JSON")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise SmokeFailure(f"{label}: invalid JSON response") from None
    no_secrets(value, label, allow_token=allow_token)
    return value


def wait_for(description, check, seconds):
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SmokeFailure(f"Timed out waiting for {description}")
        try:
            result = check(min(5, remaining))
            if result is not None:
                return result
        except SmokeFailure:
            # Startup/reload failures are transient; do not print response bodies.
            pass
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def healthy(timeout):
    status, content_type, raw = request("GET", "/api/", timeout=timeout)
    if status != 200 or "application/json" not in content_type.lower():
        return None
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        return None
    return value if isinstance(value, dict) and value.get("status") == "OK" else None


class ModuleScripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sources = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "script" and attributes.get("type") == "module":
            self.sources.append(attributes.get("src", ""))


def check_ui():
    status, content_type, raw = request("GET", "/")
    require(status == 200 and "text/html" in content_type.lower(),
            "Admin UI did not serve HTML")
    html = raw.decode("utf-8")
    require("Nginx Proxy Manager" in html and 'id="root"' in html,
            "Admin UI HTML is missing its application shell")
    scripts = ModuleScripts()
    scripts.feed(html)
    assets = [src for src in scripts.sources if re.fullmatch(r"/assets/[A-Za-z0-9_.-]+\.js", src)]
    require(bool(assets), "Admin UI is missing its compiled JavaScript entrypoint")
    for asset in assets:
        status, content_type, raw = request("GET", asset)
        require(status == 200 and "javascript" in content_type.lower() and len(raw) > 100,
                "Admin UI compiled JavaScript asset did not load")


def proxy_check(host, forwarded, timeout):
    status, _, raw = request("GET", "/", port=PROXY_PORT, host=host, timeout=timeout)
    if forwarded:
        return True if status == 200 and raw == UPSTREAM_BODY else None
    # A connection error / 502 is not evidence of successful config deletion.
    return True if status == 200 and raw != UPSTREAM_BODY else None


def wait_proxy(host, forwarded):
    state = "forwarding" if forwarded else "fallback after configuration removal"
    wait_for(f"{host} {state}", lambda timeout: proxy_check(host, forwarded, timeout), RELOAD_SECONDS)


def positive_id(record, label):
    require(isinstance(record, dict), f"{label}: expected an object")
    value = record.get("id")
    require(type(value) is int and value > 0, f"{label}: missing valid ID")
    return value


def token_metadata(jwt, token_id, *, revoked=False, used=False):
    records = api("GET", "/api-tokens", token=jwt)
    require(isinstance(records, list) and len(records) == 1,
            "Token list must contain exactly the single fixture token")
    row = records[0]
    require(isinstance(row, dict) and set(row) == TOKEN_FIELDS,
            "Token list exposed unexpected fields or omitted metadata")
    require(row["id"] == token_id and row["scopes"] == ["proxy_hosts:write"],
            "Token list did not preserve the requested identity and scope")
    require(bool(row["revoked_on"]) == revoked, "Token revocation metadata was incorrect")
    if used:
        require(bool(row["last_used_on"]), "Token usage metadata was not recorded")


def main():
    health = wait_for("admin API readiness", healthy, STARTUP_SECONDS)
    require(health.get("setup") is False,
            "Refusing to run against an initialized instance; use fresh disposable volumes")
    check_ui()
    progress("fresh API health, admin HTML and compiled UI asset")

    password = secrets.token_urlsafe(36)
    KNOWN_SECRETS.append(password)
    identity = "pat-smoke@example.test"
    user = api("POST", "/users", expected=201, body={
        "name": "Disposable PAT smoke test", "nickname": "PAT smoke",
        "email": identity, "auth": {"type": "password", "secret": password},
    })
    user_id = positive_id(user, "First-run user")
    require("admin" in user.get("roles", []), "First-run user did not receive the admin role")
    require(api("GET", "/").get("setup") is True, "First-run setup did not complete")
    login = api("POST", "/tokens", body={"identity": identity, "secret": password}, allow_token=True)
    jwt = login.get("token")
    require(isinstance(jwt, str) and len(jwt.split(".")) == 3,
            "Password login did not return a JWT session")
    KNOWN_SECRETS.append(jwt)
    require(api("GET", "/users/me", token=jwt).get("id") == user_id,
            "JWT session does not identify the fixture user")
    progress("first-run setup and real password/JWT login")

    options = api("GET", "/api-tokens/options", token=jwt)
    require("proxy_hosts:write" in options.get("scopes", []) and options.get("requires_2fa") is False,
            "PAT options do not match the fresh admin account")
    payload = {"name": "Disposable Docker smoke token", "scopes": ["proxy_hosts:write"],
               "expires_in_days": 1, "password": password}
    api("POST", "/api-tokens", token=jwt, expected=403,
        body={**payload, "password": secrets.token_urlsafe(36)})
    created = api("POST", "/api-tokens", token=jwt, body=payload, expected=201, allow_token=True)
    token_id = positive_id(created, "Created PAT")
    pat = created.get("token")
    require(isinstance(pat, str) and re.fullmatch(r"npm_pat_[a-f0-9]{24}\.[A-Za-z0-9_-]{43}", pat),
            "PAT creation did not return the one-time credential in the expected format")
    require(set(created) == TOKEN_FIELDS | {"token"}, "PAT creation returned unexpected fields")
    secret = pat.split(".", 1)[1]
    KNOWN_SECRETS.extend([pat, secret, hashlib.sha256(secret.encode()).hexdigest()])
    token_metadata(jwt, token_id)
    progress("password step-up, scoped PAT creation and metadata-only token listing")

    # A valid password alongside a PAT must still not mint a session or another PAT.
    denied = [
        ("GET", "/tokens", None),
        ("POST", "/tokens", {"identity": identity, "secret": password}),
        ("GET", "/api-tokens", None),
        ("GET", "/api-tokens/options", None),
        ("POST", "/api-tokens", payload),
        ("DELETE", f"/api-tokens/{token_id}", None),
        ("GET", "/users", None),
        ("POST", f"/users/{user_id}/login", {}),
        ("PUT", f"/users/{user_id}/auth", {"type": "password", "current": password, "secret": password}),
        ("GET", f"/users/{user_id}/2fa", None),
        ("GET", "/settings", None),
        ("GET", "/audit-log", None),
        ("GET", "/nginx/certificates", None),
        ("GET", "/nginx/proxy-hosts/future", None),
    ]
    for method, path, body in denied:
        api(method, path, token=pat, body=body, expected=403)
    progress("PAT cannot mint JWTs, manage tokens/accounts/security or exceed its scope")

    wait_proxy(HOST, False)
    wait_proxy(ALIAS, False)
    host = api("POST", "/nginx/proxy-hosts", token=pat, expected=201, body={
        "domain_names": [HOST], "forward_scheme": "http", "forward_host": "upstream",
        "forward_port": 80, "access_list_id": 0, "certificate_id": 0,
        "ssl_forced": False, "hsts_enabled": False, "hsts_subdomains": False,
        "http2_support": False, "block_exploits": False, "caching_enabled": False,
        "allow_websocket_upgrade": False, "advanced_config": "", "locations": [], "meta": {},
    })
    host_id = positive_id(host, "Created proxy host")
    host_path = f"/nginx/proxy-hosts/{host_id}"
    require(not ({"owner", "certificate", "access_list"} & set(host)),
            "PAT response exposed expanded private relations")
    hosts = api("GET", "/nginx/proxy-hosts", token=pat)
    require(isinstance(hosts, list) and [row.get("id") for row in hosts] == [host_id],
            "PAT could not list its created proxy host")
    fetched = api("GET", host_path, token=pat)
    require(fetched.get("domain_names") == [HOST] and fetched.get("forward_host") == "upstream"
            and fetched.get("forward_port") == 80, "PAT read did not match the created upstream")
    wait_proxy(HOST, True)
    progress("PAT create/list/read and actual Nginx forwarding to the Docker upstream")

    api("GET", host_path + "?expand=owner", token=pat, expected=403)
    api("PUT", host_path, token=pat, body={"advanced_config": "return 200;"}, expected=403)
    fetched = api("GET", host_path, token=pat)
    require(fetched.get("advanced_config") == "", "Denied configuration update changed the host")
    updated = api("PUT", host_path, token=pat,
                  body={"domain_names": [HOST, ALIAS], "allow_websocket_upgrade": True})
    require(updated.get("domain_names") == [HOST, ALIAS] and updated.get("allow_websocket_upgrade") is True,
            "PAT update did not persist the changed proxy host")
    wait_proxy(ALIAS, True)
    wait_proxy(HOST, True)
    token_metadata(jwt, token_id, used=True)
    progress("safe update reached live Nginx; arbitrary directives and relation expansion denied")

    require(api("DELETE", host_path, token=pat) is True, "PAT deletion was not acknowledged")
    require(api("GET", "/nginx/proxy-hosts", token=pat) == [], "Deleted host is still listed")
    api("GET", host_path, token=pat, expected=403)
    wait_proxy(HOST, False)
    wait_proxy(ALIAS, False)
    progress("PAT deletion removed the API record and live forwarding configuration")

    revoked = api("DELETE", f"/api-tokens/{token_id}", token=jwt)
    require(revoked == {"revoked": True}, "JWT token revocation was not acknowledged")
    token_metadata(jwt, token_id, revoked=True, used=True)
    api("GET", "/nginx/proxy-hosts", token=pat, expected=401)
    api("GET", "/tokens", token=pat, expected=401)
    require(api("GET", "/users/me", token=jwt).get("id") == user_id,
            "JWT session stopped working after PAT revocation")
    progress("revocation is immediate, rejects credential reuse and preserves the JWT session")
    print("PASS: Docker PAT smoke test completed", flush=True)


if __name__ == "__main__":
    try:
        main()
    except SmokeFailure as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
    except Exception as error:
        # Exception messages and tracebacks can retain credential-bearing input.
        print(f"FAIL: unexpected {type(error).__name__}; details suppressed to protect credentials",
              file=sys.stderr, flush=True)
        sys.exit(1)
