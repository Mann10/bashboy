"""Shared test isolation: no ambient BashBoy environment, no real config file."""

from __future__ import annotations

import pytest

_ENV_VARS = (
    "BASHBOY_CONFIG",
    "BASHBOY_ENDPOINT",
    "BASHBOY_API_KEY_ENV",
    "BASHBOY_API_KEY_FILE",
    "BASHBOY_FAIL_MODE",
    "BASHBOY_DISABLE",
    "BASHBOY_DEBUG",
    "BASHBOY_REQUIRE_KEY",
    "BASHBOY_POLICY",
    "BASHBOY_POLICY_ORG",
    "BASHBOY_POLICY_USER",
    "BASHBOY_POLICY_PROJECT",
    "CLOCKED_API_KEY",
)


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BASHBOY_CONFIG", str(tmp_path / "bashboy-config.toml"))
    # Never discover a developer's real policy files during the suite.
    monkeypatch.setenv("BASHBOY_POLICY_ORG", str(tmp_path / "policy-org-absent.toml"))
    monkeypatch.setenv("BASHBOY_POLICY_USER", str(tmp_path / "policy-user-absent.toml"))
    monkeypatch.setenv(
        "BASHBOY_POLICY_PROJECT", str(tmp_path / "policy-project-absent.toml")
    )
    # Never let a developer's real ~/.bashboy/credentials leak into the suite.
    monkeypatch.setenv(
        "BASHBOY_API_KEY_FILE", str(tmp_path / "bashboy-api-key-file-absent")
    )
