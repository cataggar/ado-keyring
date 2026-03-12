"""Keyring backend for Azure DevOps feeds using browser-based OAuth2."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

import keyring.backend
import keyring.credentials
import requests

# Azure CLI public client
_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
_SCOPE = "499b84ac-1321-427f-aa17-267ca6975798/.default offline_access"
_AUTH_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
_TOKEN_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"

_LOG_PREFIX = "[ado-keyring]"
_HTTP_TIMEOUT = 30  # seconds for all HTTP requests
_CALLBACK_TIMEOUT = 120  # seconds to wait for browser callback


# ── Token cache ──────────────────────────────────────────────────────────────

def _cache_path() -> Path:
    return Path.home() / ".ado-keyring" / "token-cache.json"


def _load_cache() -> Optional[Dict[str, Any]]:
    try:
        return json.loads(_cache_path().read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _save_cache(cache: Dict[str, Any]) -> None:
    path = _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cache, f, indent=2)


# ── URL helpers ──────────────────────────────────────────────────────────────

_DEVOPS_HOSTS = (
    "visualstudio.com",
    "dev.azure.com",
    "pkgs.codedev.ms",
    "pkgs.vsts.me",
)


def _is_devops_url(url: str) -> bool:
    return any(h in url for h in _DEVOPS_HOSTS)


def _extract_org(service_url: str) -> Optional[str]:
    parsed = urlparse(service_url)
    host = parsed.hostname or ""
    if host.endswith("visualstudio.com") or host.endswith("vsts.me") or host.endswith("codedev.ms"):
        return host.split(".")[0]
    elif "dev.azure.com" in host:
        parts = parsed.path.strip("/").split("/")
        return parts[0] if parts and parts[0] else None
    return None


# ── PKCE ─────────────────────────────────────────────────────────────────────

def _generate_pkce() -> Tuple[str, str]:
    verifier_bytes = secrets.token_bytes(32)
    verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=").decode()
    challenge_hash = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(challenge_hash).rstrip(b"=").decode()
    return verifier, challenge


# ── WSL-aware browser opening ────────────────────────────────────────────────

def _is_wsl() -> bool:
    try:
        return "microsoft" in Path("/proc/version").read_text().lower()
    except OSError:
        return False


def _open_browser(url: str) -> None:
    devnull = subprocess.DEVNULL
    attempts: list[Tuple[str, list[str]]] = []

    if _is_wsl():
        attempts = [
            ("wslview", [url]),
            (
                "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                ["-NoProfile", "-Command", f"Start-Process '{url}'"],
            ),
            (
                "/mnt/c/Windows/system32/cmd.exe",
                ["/c", "start", "", url],
            ),
        ]
    elif platform.system() == "Darwin":
        attempts = [("open", [url])]
    else:
        attempts = [("xdg-open", [url])]

    for cmd, args in attempts:
        try:
            result = subprocess.run(
                [cmd, *args], stdin=devnull, stdout=devnull, stderr=devnull
            )
            if result.returncode == 0:
                return
        except FileNotFoundError:
            continue

    raise RuntimeError(
        f"Could not open browser.\nPlease open this URL manually:\n{url}"
    )


# ── OAuth2 browser auth flow ────────────────────────────────────────────────

_SUCCESS_HTML = (
    "<html><head><title>Authentication Successful</title></head>"
    '<body style="font-family:sans-serif;text-align:center;margin-top:80px">'
    "<h1>Authentication Successful</h1>"
    "<p>You can close this tab and return to the terminal.</p>"
    "</body></html>"
)

_ERROR_HTML = (
    "<html><head><title>Authentication Failed</title></head>"
    '<body style="font-family:sans-serif;text-align:center;margin-top:80px">'
    "<h1>Authentication Failed</h1>"
    "<p>An error occurred. You can close this tab.</p>"
    "</body></html>"
)


def _send_html(conn: socket.socket, html: str) -> None:
    response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: text/html\r\n"
        f"Content-Length: {len(html)}\r\n"
        f"Connection: close\r\n\r\n"
        f"{html}"
    )
    conn.sendall(response.encode())
    conn.close()


def _browser_auth() -> Dict[str, Any]:
    verifier, challenge = _generate_pkce()
    state = secrets.token_urlsafe(16)

    # Bind to a random port for the OAuth callback
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    redirect_uri = f"http://localhost:{port}"

    params = urlencode({
        "client_id": _CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": _SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "prompt": "select_account",
    })
    auth_url = f"{_AUTH_URL}?{params}"

    print(f"{_LOG_PREFIX} Opening browser for Azure DevOps authentication...", file=sys.stderr)
    _open_browser(auth_url)

    # Wait for the OAuth callback
    sock.settimeout(_CALLBACK_TIMEOUT)
    try:
        conn, _ = sock.accept()
    except socket.timeout:
        sock.close()
        raise RuntimeError(f"Timed out waiting for browser callback after {_CALLBACK_TIMEOUT}s")
    sock.close()
    data = conn.recv(8192).decode("utf-8", errors="replace")

    # Parse GET /?code=...&state=...
    request_line = data.split("\r\n")[0]
    path = request_line.split(" ")[1] if " " in request_line else ""
    parsed = urlparse(f"http://localhost{path}")
    params_dict = parse_qs(parsed.query)

    if "error" in params_dict:
        _send_html(conn, _ERROR_HTML)
        error = params_dict["error"][0]
        desc = params_dict.get("error_description", [""])[0]
        raise RuntimeError(f"{error}: {desc}")

    code = params_dict.get("code", [None])[0]
    if not code:
        _send_html(conn, _ERROR_HTML)
        raise RuntimeError("Missing 'code' in OAuth callback")

    returned_state = params_dict.get("state", [None])[0]
    if returned_state != state:
        _send_html(conn, _ERROR_HTML)
        raise RuntimeError("OAuth state mismatch — possible CSRF")

    _send_html(conn, _SUCCESS_HTML)

    return _exchange_code(code, redirect_uri, verifier)


def _exchange_code(code: str, redirect_uri: str, verifier: str) -> Dict[str, Any]:
    resp = requests.post(_TOKEN_URL, data={
        "client_id": _CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


# ── Token refresh ────────────────────────────────────────────────────────────

def _refresh_access_token(refresh_token: str) -> Dict[str, Any]:
    resp = requests.post(_TOKEN_URL, data={
        "client_id": _CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": _SCOPE,
    }, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


# ── VssSessionToken exchange ─────────────────────────────────────────────────

def _get_session_token(access_token: str, org: str) -> str:
    url = f"https://vssps.dev.azure.com/{org}/_apis/token/sessiontokens?api-version=5.0-preview.1"
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
        json={"scope": "vso.packaging", "targetAccounts": []},
        timeout=_HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["token"]


# ── Main authenticate logic ─────────────────────────────────────────────────

def _authenticate(service_url: str) -> Optional[Tuple[str, str]]:
    if not _is_devops_url(service_url):
        return None

    org = _extract_org(service_url)
    if not org:
        raise RuntimeError(
            f"Could not extract Azure DevOps org from URL: {service_url}"
        )

    now = int(time.time())
    cache = _load_cache()

    # 1. Check cached session token (5-min buffer)
    if cache:
        st = cache.get("session_tokens", {}).get(org)
        if st and st["expires_at"] > now + 300:
            print(f"{_LOG_PREFIX} Using cached session token for '{org}'", file=sys.stderr)
            return ("VssSessionToken", st["token"])

    # 2. Get a valid access token (refresh or browser)
    token_resp = None
    if cache and cache.get("expires_at", 0) > now + 60:
        pass  # access token still valid
    elif cache and cache.get("refresh_token"):
        print(f"{_LOG_PREFIX} Refreshing access token...", file=sys.stderr)
        try:
            token_resp = _refresh_access_token(cache["refresh_token"])
        except Exception as e:
            print(f"{_LOG_PREFIX} Refresh failed ({e}), falling back to browser", file=sys.stderr)
            token_resp = _browser_auth()
    else:
        print(f"{_LOG_PREFIX} No cached token, starting browser auth...", file=sys.stderr)
        token_resp = _browser_auth()

    # Update cache with fresh access token
    if token_resp:
        prev_sessions = cache.get("session_tokens", {}) if cache else {}
        cache = {
            "access_token": token_resp["access_token"],
            "refresh_token": token_resp.get("refresh_token"),
            "expires_at": now + token_resp.get("expires_in", 3600),
            "session_tokens": prev_sessions,
        }

    assert cache is not None

    # 3. Exchange for VssSessionToken
    print(f"{_LOG_PREFIX} Exchanging for VssSessionToken ({org})...", file=sys.stderr)
    session_token = _get_session_token(cache["access_token"], org)

    cache.setdefault("session_tokens", {})[org] = {
        "token": session_token,
        "expires_at": now + 3000,
    }
    _save_cache(cache)

    print(f"{_LOG_PREFIX} ✓ Authenticated to '{org}'", file=sys.stderr)
    return ("VssSessionToken", session_token)


# ── Keyring backend ─────────────────────────────────────────────────────────

class DevOpsKeyring(keyring.backend.KeyringBackend):
    """Authenticates to Azure DevOps package feeds via browser OAuth2 + PKCE.

    Works on WSL, Linux, and macOS. Tokens are cached to avoid repeated prompts.
    """

    priority = 10  # Higher than artifacts-keyring (9.9)

    def get_password(self, service: str, username: str) -> Optional[str]:
        result = _authenticate(service)
        return result[1] if result else None

    def get_credential(self, service: str, username: str) -> Optional[keyring.credentials.SimpleCredential]:
        result = _authenticate(service)
        if result:
            return keyring.credentials.SimpleCredential(result[0], result[1])
        return None

    def set_password(self, service: str, username: str, password: str) -> None:
        raise NotImplementedError("ado-keyring is read-only")

    def delete_password(self, service: str, username: str) -> None:
        path = _cache_path()
        if path.exists():
            path.unlink()
            print(f"{_LOG_PREFIX} Token cache cleared", file=sys.stderr)

