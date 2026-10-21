"""Classifier pipeline tests: precedence, short-circuits, and fail-closed behaviour."""

from __future__ import annotations

import dataclasses
import os
import subprocess
import sys

import pytest

import bashboy.provider as provider_module
from bashboy.classify import Classification, classify_command
from bashboy.config import Config, load_config, ProviderConfig
from bashboy.provider import ProviderError, Verdict


class SpyProvider:
    def __init__(self, verdict: Verdict | None = None, exc: Exception | None = None) -> None:
        self.verdict = verdict
        self.exc = exc
        self.calls: list[tuple[str, str]] = []

    def classify(self, cwd: str, command: str) -> Verdict:
        self.calls.append((cwd, command))
        if self.exc is not None:
            raise self.exc
        assert self.verdict is not None
        return self.verdict


class ExplodingProvider:
    def classify(self, cwd: str, command: str) -> Verdict:
        raise AssertionError("provider must not be used on this path")


@pytest.fixture
def cfg(tmp_path) -> Config:
    return load_config(tmp_path / "absent.toml")


def test_denylist_short_circuits_and_never_constructs_provider(
    cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*args, **kwargs):
        raise AssertionError("provider constructed on the denylist path")

    monkeypatch.setattr(provider_module, "Provider", explode)
    result = classify_command("rm -rf /", cwd="/home/me", cfg=cfg)
    assert result.decision == "deny"
    assert result.source == "denylist"
    assert result.reason == "recursive delete of a protected path"
    assert result.risk is None


def test_allowlist_short_circuits_and_never_constructs_provider(
    cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*args, **kwargs):
        raise AssertionError("provider constructed on the allowlist path")

    monkeypatch.setattr(provider_module, "Provider", explode)
    result = classify_command("git status", cwd="/home/me", cfg=cfg)
    assert result.decision == "allow"
    assert result.source == "allowlist"
    assert result.reason == "matches allowlist: git status"


def test_model_path_allows_with_risk(cfg: Config) -> None:
    spy = SpyProvider(Verdict("allow", "low", "read-only"))
    result = classify_command("docker run --rm alpine true", cwd="/tmp", cfg=cfg, provider=spy)
    assert result.decision == "allow"
    assert result.source == "model"
    assert result.risk == "low"
    assert result.reason == "read-only"
    assert spy.calls == [("/tmp", "docker run --rm alpine true")]


def test_model_failure_denies_by_default(cfg: Config) -> None:
    spy = SpyProvider(exc=ProviderError("boom"))
    result = classify_command("docker build .", cfg=cfg, provider=spy)
    assert result.decision == "deny"
    assert result.source == "fallback"
    assert "boom" in result.reason


def test_model_failure_can_allow_when_explicitly_configured(cfg: Config) -> None:
    open_cfg = dataclasses.replace(
        cfg, policy=dataclasses.replace(cfg.policy, fail_mode="open")
    )
    result = classify_command(
        "docker build .", cfg=open_cfg, provider=SpyProvider(exc=ProviderError("boom"))
    )
    assert result.decision == "allow"
    assert result.source == "fallback"


def test_unexpected_exception_also_fails_closed(cfg: Config) -> None:
    result = classify_command("docker build .", cfg=cfg, provider=SpyProvider(exc=RuntimeError("!?")))
    assert result.decision == "deny"
    assert result.source == "fallback"


def test_bashboy_disable_allows_without_checks(
    cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BASHBOY_DISABLE", "1")
    result = classify_command("rm -rf /", cfg=cfg, provider=ExplodingProvider())
    assert result.decision == "allow"
    assert result.source == "disabled"
    assert result.reason == "BASHBOY_DISABLE is set"


@pytest.mark.parametrize("value", ["true", "YES", "True"])
def test_bashboy_disable_truthy_variants(
    cfg: Config, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("BASHBOY_DISABLE", value)
    assert classify_command("rm -rf /", cfg=cfg).source == "disabled"


def test_bashboy_disable_false_is_inert(cfg: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BASHBOY_DISABLE", "0")
    assert classify_command("rm -rf /", cfg=cfg).source == "denylist"


@pytest.mark.parametrize("command", ["", "   ", "\n\t "])
def test_blank_command_is_denied(cfg: Config, command: str) -> None:
    result = classify_command(command, cfg=cfg)
    assert result.decision == "deny"
    assert result.source == "fallback"
    assert result.reason == "no command provided"


def test_latency_is_non_negative_int(cfg: Config) -> None:
    result = classify_command("git status", cfg=cfg)
    assert isinstance(result.latency_ms, int)
    assert result.latency_ms >= 0


def test_denylist_can_be_disabled(cfg: Config) -> None:
    no_deny = dataclasses.replace(cfg, policy=dataclasses.replace(cfg.policy, denylist=False))
    spy = SpyProvider(Verdict("allow", None, "ok"))
    result = classify_command("rm -rf /", cfg=no_deny, provider=spy)
    assert result.source == "model"
    assert spy.calls


def test_allowlist_can_be_disabled(cfg: Config) -> None:
    no_allow = dataclasses.replace(cfg, policy=dataclasses.replace(cfg.policy, allowlist=False))
    spy = SpyProvider(Verdict("deny", "high", "nope"))
    result = classify_command("git status", cfg=no_allow, provider=spy)
    assert result.source == "model"
    assert spy.calls


def test_to_dict_key_order() -> None:
    result = Classification("deny", "fallback", "why", "high", 3)
    assert list(result.to_dict()) == ["decision", "source", "reason", "risk", "latency_ms"]


def test_to_dict_values() -> None:
    payload = Classification("allow", "allowlist", "matches allowlist: ls").to_dict()
    assert payload == {
        "decision": "allow",
        "source": "allowlist",
        "reason": "matches allowlist: ls",
        "risk": None,
        "latency_ms": 0,
    }


def test_provider_is_imported_lazily(tmp_path) -> None:
    env = dict(os.environ)
    env["BASHBOY_CONFIG"] = str(tmp_path / "missing.toml")
    for name in ("BASHBOY_DISABLE", "BASHBOY_DEBUG"):
        env.pop(name, None)
    code = (
        "import sys\n"
        "import bashboy.classify as c\n"
        "result = c.classify_command('git status')\n"
        "assert result.source == 'allowlist', result\n"
        "assert 'bashboy.provider' not in sys.modules, sorted(sys.modules)\n"
        "print('lazy ok')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=60
    )
    assert completed.returncode == 0, completed.stderr
    assert "lazy ok" in completed.stdout


def test_env_endpoint_is_used_for_model_path(
    cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BASHBOY_ENDPOINT", "https://example.test/fill")
    monkeypatch.setenv("CLOCKED_API_KEY", "secret")
    cfg = load_config(cfg.path)
    captured: dict[str, object] = {}

    real_provider = provider_module.Provider

    class CapturingProvider(real_provider):
        def __init__(self, provider_cfg: ProviderConfig, transport=None, key=None) -> None:
            captured["endpoint"] = provider_cfg.endpoint
            captured["key"] = key
            super().__init__(provider_cfg, transport=transport, key=key)

        def classify(self, cwd: str, command: str) -> Verdict:
            return Verdict("allow", None, "ok")

    monkeypatch.setattr(provider_module, "Provider", CapturingProvider)
    result = classify_command("docker run --rm alpine true", cfg=cfg)
    assert result.source == "model"
    assert captured["endpoint"] == "https://example.test/fill"
    assert captured["key"] == "secret"


def test_debug_logging_goes_to_stderr(
    cfg: Config, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASHBOY_DEBUG", "1")
    result = classify_command("git status", cfg=cfg)
    assert result.source == "allowlist"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "bashboy:" in captured.err


def test_no_debug_logging_by_default(
    cfg: Config, capsys: pytest.CaptureFixture[str]
) -> None:
    classify_command("git status", cfg=cfg)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_file_sourced_key_reaches_provider(
    cfg: Config, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from bashboy.credentials import write_token

    key_file = tmp_path / "cred"
    write_token(key_file, "file-secret")
    monkeypatch.setenv("BASHBOY_API_KEY_FILE", str(key_file))
    cfg = load_config(cfg.path)
    captured: dict[str, object] = {}

    real_provider = provider_module.Provider

    class CapturingProvider(real_provider):
        def __init__(self, provider_cfg: ProviderConfig, transport=None, key=None) -> None:
            captured["key"] = key
            super().__init__(provider_cfg, transport=transport, key=key)

        def classify(self, cwd: str, command: str) -> Verdict:
            return Verdict("allow", None, "ok")

    monkeypatch.setattr(provider_module, "Provider", CapturingProvider)
    result = classify_command("docker run --rm alpine true", cfg=cfg)
    assert result.source == "model"
    assert captured["key"] == "file-secret"


def test_no_key_reason_mentions_auth_set(cfg: Config) -> None:
    result = classify_command("docker build .", cfg=cfg)
    assert result.decision == "deny"
    assert result.source == "fallback"
    assert "bashboy auth set" in result.reason


def test_debug_logs_key_source_but_not_the_token(
    cfg: Config, tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from bashboy.credentials import write_token

    key_file = tmp_path / "cred"
    write_token(key_file, "file-secret-token")
    monkeypatch.setenv("BASHBOY_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("BASHBOY_DEBUG", "1")
    cfg = load_config(cfg.path)
    spy = SpyProvider(Verdict("allow", None, "ok"))
    classify_command("docker build .", cfg=cfg, provider=spy)
    captured = capsys.readouterr()
    assert "api key source: file" in captured.err
    assert "file-secret-token" not in captured.err
    assert "file-secret-token" not in captured.out
