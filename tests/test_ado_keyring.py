"""Unit tests for ado-keyring."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Dict
from unittest import mock

import pytest

from ado_keyring import (
    AdoKeyring,
    _cache_path,
    _extract_org,
    _generate_pkce,
    _is_devops_url,
    _is_wsl,
    _load_cache,
    _save_cache,
)


# ── _is_devops_url ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "https://myorg.pkgs.visualstudio.com/_packaging/foo/pypi/simple/",
        "https://pkgs.dev.azure.com/myorg/_packaging/feed/pypi/simple/",
        "https://pkgs.codedev.ms/myorg/_packaging/feed/pypi/simple/",
        "https://pkgs.vsts.me/myorg/_packaging/feed/pypi/simple/",
    ],
)
def test_is_devops_url_positive(url: str) -> None:
    assert _is_devops_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://pypi.org/simple/",
        "https://example.com/packages/",
        "https://not-azure.dev.com/feed",
        "",
    ],
)
def test_is_devops_url_negative(url: str) -> None:
    assert _is_devops_url(url) is False


# ── _extract_org ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url, expected_org",
    [
        # Legacy visualstudio.com
        ("https://myorg.pkgs.visualstudio.com/_packaging/feed/pypi/simple/", "myorg"),
        ("https://myorg.pkgs.visualstudio.com/_packaging/feed/pypi/simple/", "myorg"),
        # dev.azure.com
        ("https://pkgs.dev.azure.com/myorg/_packaging/feed/pypi/simple/", "myorg"),
        ("https://dev.azure.com/contoso/_packaging/feed/pypi/simple/", "contoso"),
        # codedev.ms
        ("https://pkgs.codedev.ms/myorg/_packaging/feed/pypi/simple/", "pkgs"),
        # vsts.me
        ("https://pkgs.vsts.me/myorg/_packaging/feed/pypi/simple/", "pkgs"),
    ],
)
def test_extract_org(url: str, expected_org: str) -> None:
    assert _extract_org(url) == expected_org


def test_extract_org_none_for_unknown() -> None:
    assert _extract_org("https://pypi.org/simple/") is None


def test_extract_org_none_for_empty_path() -> None:
    assert _extract_org("https://dev.azure.com/") is None


# ── _generate_pkce ───────────────────────────────────────────────────────────


def test_pkce_verifier_length() -> None:
    verifier, _ = _generate_pkce()
    # 32 bytes → 43 base64url chars (no padding)
    assert len(verifier) == 43


def test_pkce_challenge_matches_verifier() -> None:
    verifier, challenge = _generate_pkce()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    assert challenge == expected


def test_pkce_values_are_unique() -> None:
    pairs = [_generate_pkce() for _ in range(5)]
    verifiers = [v for v, _ in pairs]
    assert len(set(verifiers)) == 5


def test_pkce_no_padding() -> None:
    verifier, challenge = _generate_pkce()
    assert "=" not in verifier
    assert "=" not in challenge


# ── _is_wsl ──────────────────────────────────────────────────────────────────


def test_is_wsl_true() -> None:
    content = "Linux version 5.15.153.1-microsoft-standard-WSL2"
    with mock.patch("ado_keyring.Path.read_text", return_value=content):
        assert _is_wsl() is True


def test_is_wsl_false() -> None:
    content = "Linux version 6.8.0-51-generic (buildd@lcy02-amd64-115)"
    with mock.patch("ado_keyring.Path.read_text", return_value=content):
        assert _is_wsl() is False


def test_is_wsl_oserror() -> None:
    with mock.patch("ado_keyring.Path.read_text", side_effect=OSError):
        assert _is_wsl() is False


# ── Cache I/O ────────────────────────────────────────────────────────────────


def test_save_and_load_cache(tmp_path: Path) -> None:
    cache_file = tmp_path / ".ado-keyring" / "token-cache.json"
    with mock.patch("ado_keyring._cache_path", return_value=cache_file):
        data: Dict[str, Any] = {"access_token": "abc", "expires_at": 9999999999}
        _save_cache(data)
        loaded = _load_cache()
    assert loaded == data


def test_save_cache_permissions(tmp_path: Path) -> None:
    cache_file = tmp_path / ".ado-keyring" / "token-cache.json"
    with mock.patch("ado_keyring._cache_path", return_value=cache_file):
        _save_cache({"token": "secret"})

    file_mode = cache_file.stat().st_mode
    assert stat.S_IMODE(file_mode) == 0o600

    dir_mode = cache_file.parent.stat().st_mode
    assert stat.S_IMODE(dir_mode) == 0o700


def test_load_cache_missing_file(tmp_path: Path) -> None:
    cache_file = tmp_path / "nonexistent" / "token-cache.json"
    with mock.patch("ado_keyring._cache_path", return_value=cache_file):
        assert _load_cache() is None


def test_load_cache_invalid_json(tmp_path: Path) -> None:
    cache_file = tmp_path / "token-cache.json"
    cache_file.write_text("not json!!!")
    with mock.patch("ado_keyring._cache_path", return_value=cache_file):
        assert _load_cache() is None


# ── DevOpsKeyring backend ───────────────────────────────────────────────────


def test_backend_priority() -> None:
    assert AdoKeyring.priority == 10


def test_set_password_raises() -> None:
    backend = AdoKeyring()
    with pytest.raises(NotImplementedError):
        backend.set_password("https://dev.azure.com", "user", "pass")


def test_delete_password_clears_cache(tmp_path: Path) -> None:
    cache_file = tmp_path / ".ado-keyring" / "token-cache.json"
    cache_file.parent.mkdir(parents=True)
    cache_file.write_text('{"token": "old"}')
    with mock.patch("ado_keyring._cache_path", return_value=cache_file):
        backend = AdoKeyring()
        backend.delete_password("https://dev.azure.com/myorg", "user")
    assert not cache_file.exists()


def test_delete_password_no_cache() -> None:
    """delete_password should not raise if cache doesn't exist."""
    with mock.patch("ado_keyring._cache_path", return_value=Path("/tmp/nonexistent/cache.json")):
        backend = AdoKeyring()
        backend.delete_password("https://dev.azure.com/myorg", "user")


def test_get_password_non_devops() -> None:
    backend = AdoKeyring()
    assert backend.get_password("https://pypi.org/simple/", "user") is None


def test_get_credential_non_devops() -> None:
    backend = AdoKeyring()
    assert backend.get_credential("https://pypi.org/simple/", "user") is None
