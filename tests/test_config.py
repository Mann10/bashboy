"""Tests for the configuration loader."""

from __future__ import annotations

import pytest

from bashboy import config


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "BASHBOY_CONFIG",
        "BASHBOY_ENDPOINT",
        "BASHBOY_API_KEY_ENV",
        "BASHBOY_FAIL_MODE",
        "CLOCKED_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def test_missing_file_returns_documented_defaults(tmp_path) -> None:
    cfg = config.load_config(tmp_path / "nope" / "config.toml")
    assert cfg.provider.endpoint == "https://clocked.rezolve.ai/clocked/fill"
    assert cfg.provider.api_key_env == "CLOCKED_API_KEY"
    assert cfg.provider.timeout_ms == 4000
    assert cfg.policy.fail_mode == "closed"
    assert cfg.policy.denylist is True
    assert cfg.policy.allowlist is True
    assert cfg.claude.timeout_s == 15
    assert cfg.opencode.timeout_ms == 15000
    assert cfg.path == tmp_path / "nope" / "config.toml"


def test_default_config_toml_matches_brief() -> None:
    assert "[provider]" in config.DEFAULT_CONFIG_TOML
    assert 'endpoint = "https://clocked.rezolve.ai/clocked/fill"' in config.DEFAULT_CONFIG_TOML
    assert 'api_key_env = "CLOCKED_API_KEY"' in config.DEFAULT_CONFIG_TOML
    assert "timeout_ms = 4000" in config.DEFAULT_CONFIG_TOML
    assert 'fail_mode = "closed"' in config.DEFAULT_CONFIG_TOML
    assert "[integrations.claude]" in config.DEFAULT_CONFIG_TOML
    assert "[integrations.opencode]" in config.DEFAULT_CONFIG_TOML
    assert "# closed | open" in config.DEFAULT_CONFIG_TOML


def test_default_config_toml_round_trips(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(config.DEFAULT_CONFIG_TOML, encoding="utf-8")
    cfg = config.load_config(path)
    assert cfg.provider.timeout_ms == 4000
    assert cfg.claude.timeout_s == 15


def test_toml_values_are_read(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """
[provider]
endpoint = "https://example.test/fill"
api_key_env = "MY_KEY"
timeout_ms = 1234

[policy]
fail_mode = "open"
denylist = false
allowlist = false

[integrations.claude]
timeout_s = 3

[integrations.opencode]
timeout_ms = 99
""",
        encoding="utf-8",
    )
    cfg = config.load_config(path)
    assert cfg.provider.endpoint == "https://example.test/fill"
    assert cfg.provider.api_key_env == "MY_KEY"
    assert cfg.provider.timeout_ms == 1234
    assert cfg.policy.fail_mode == "open"
    assert cfg.policy.denylist is False
    assert cfg.policy.allowlist is False
    assert cfg.claude.timeout_s == 3
    assert cfg.opencode.timeout_ms == 99


def test_unknown_keys_and_missing_sections_are_ignored(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """
unknown = "value"

[provider]
endpoint = "https://example.test/fill"
mystery = 1
""",
        encoding="utf-8",
    )
    cfg = config.load_config(path)
    assert cfg.provider.endpoint == "https://example.test/fill"
    assert cfg.provider.timeout_ms == 4000
    assert cfg.policy.fail_mode == "closed"


def test_malformed_toml_raises_config_error(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("[provider\nendpoint = ", encoding="utf-8")
    with pytest.raises(config.ConfigError) as excinfo:
        config.load_config(path)
    assert "invalid TOML" in str(excinfo.value)


def test_wrong_type_raises_config_error(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('[provider]\ntimeout_ms = "soon"\n', encoding="utf-8")
    with pytest.raises(config.ConfigError):
        config.load_config(path)


def test_non_table_section_raises_config_error(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('provider = "nope"\n', encoding="utf-8")
    with pytest.raises(config.ConfigError):
        config.load_config(path)


def test_invalid_fail_mode_raises(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('[policy]\nfail_mode = "sideways"\n', encoding="utf-8")
    with pytest.raises(config.ConfigError):
        config.load_config(path)


def test_env_overrides_win(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[provider]\nendpoint = "https://file.test/fill"\napi_key_env = "FILE_KEY"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("BASHBOY_ENDPOINT", "https://env.test/fill")
    monkeypatch.setenv("BASHBOY_API_KEY_ENV", "ENV_KEY")
    monkeypatch.setenv("BASHBOY_FAIL_MODE", "open")
    cfg = config.load_config(path)
    assert cfg.provider.endpoint == "https://env.test/fill"
    assert cfg.provider.api_key_env == "ENV_KEY"
    assert cfg.policy.fail_mode == "open"


def test_env_invalid_fail_mode_raises(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BASHBOY_FAIL_MODE", "sometimes")
    with pytest.raises(config.ConfigError):
        config.load_config(tmp_path / "missing.toml")


def test_config_path_uses_env(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "custom.toml"
    monkeypatch.setenv("BASHBOY_CONFIG", str(target))
    assert config.config_path() == target


def test_load_config_uses_env_path(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "custom.toml"
    target.write_text("[provider]\ntimeout_ms = 77\n", encoding="utf-8")
    monkeypatch.setenv("BASHBOY_CONFIG", str(target))
    cfg = config.load_config()
    assert cfg.provider.timeout_ms == 77
    assert cfg.path == target


def test_api_key_reads_environment(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = config.load_config(tmp_path / "missing.toml")
    assert config.api_key(cfg) is None
    monkeypatch.setenv("CLOCKED_API_KEY", "  secret  ")
    assert config.api_key(cfg) == "secret"
    monkeypatch.setenv("CLOCKED_API_KEY", "   ")
    assert config.api_key(cfg) is None


def test_api_key_honours_custom_env_name(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.toml"
    path.write_text('[provider]\napi_key_env = "OTHER_KEY"\n', encoding="utf-8")
    cfg = config.load_config(path)
    monkeypatch.setenv("OTHER_KEY", "abc")
    assert config.api_key(cfg) == "abc"
