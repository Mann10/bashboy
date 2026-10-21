"""Installer tests. Everything runs under tmp_path; the real home is never touched."""

from __future__ import annotations

import json

import pytest

from bashboy.config import ConfigError, load_config
from bashboy.installers.claude import build_handler, install_claude
from bashboy.installers.opencode import PLUGIN_SOURCE, install_opencode

EXPECTED_HANDLER = {
    "type": "command",
    "command": "uvx",
    "args": ["bashboy", "check", "--claude-hook"],
    "timeout": 15,
    "statusMessage": "BashBoy: checking command",
}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


# --- Claude ---------------------------------------------------------------


def test_claude_fresh_file_shape(tmp_path) -> None:
    settings = tmp_path / "settings.json"
    result = install_claude(settings)

    data = read_json(settings)
    assert data["hooks"]["PreToolUse"][0]["matcher"] == "Bash|PowerShell|Read"
    assert data["hooks"]["PreToolUse"][0]["hooks"] == [EXPECTED_HANDLER]
    assert result == data


def test_claude_preserves_unrelated_keys(tmp_path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "model": "opus",
                "hooks": {"PostToolUse": [{"matcher": "Edit", "hooks": []}]},
            }
        ),
        encoding="utf-8",
    )
    install_claude(settings)
    data = read_json(settings)
    assert data["model"] == "opus"
    assert data["hooks"]["PostToolUse"] == [{"matcher": "Edit", "hooks": []}]


def test_claude_replaces_existing_bashboy_handler(tmp_path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash|PowerShell|Read",
                            "hooks": [dict(EXPECTED_HANDLER, statusMessage="stale")],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    install_claude(settings)
    handlers = read_json(settings)["hooks"]["PreToolUse"][0]["hooks"]
    assert len(handlers) == 1
    assert handlers[0]["statusMessage"] == "BashBoy: checking command"


def test_claude_is_byte_idempotent(tmp_path) -> None:
    settings = tmp_path / "settings.json"
    install_claude(settings)
    first = settings.read_bytes()
    install_claude(settings)
    assert settings.read_bytes() == first


def test_claude_writes_backup_of_previous_content(tmp_path) -> None:
    settings = tmp_path / "settings.json"
    original = json.dumps({"model": "opus"}).encode("utf-8")
    settings.write_bytes(original)
    install_claude(settings)
    backup = tmp_path / "settings.json.bak"
    assert backup.read_bytes() == original


def test_claude_dry_run_writes_nothing(tmp_path) -> None:
    settings = tmp_path / "settings.json"
    result = install_claude(settings, dry_run=True)
    assert not settings.exists()
    assert not (tmp_path / "settings.json.bak").exists()
    handler = result["hooks"]["PreToolUse"][0]["hooks"][0]
    assert handler == EXPECTED_HANDLER


def test_claude_from_spec_appears_in_args(tmp_path) -> None:
    result = install_claude(tmp_path / "settings.json", from_spec="/x", dry_run=True)
    args = result["hooks"]["PreToolUse"][0]["hooks"][0]["args"]
    assert args == ["--from", "/x", "bashboy", "check", "--claude-hook"]


def test_claude_rerun_updates_from_spec(tmp_path) -> None:
    settings = tmp_path / "settings.json"
    install_claude(settings, from_spec="/old")
    install_claude(settings, from_spec="/new")
    handlers = read_json(settings)["hooks"]["PreToolUse"][0]["hooks"]
    assert len(handlers) == 1
    assert handlers[0]["args"] == ["--from", "/new", "bashboy", "check", "--claude-hook"]


def test_claude_invalid_json_raises(tmp_path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        install_claude(settings)
    assert settings.read_text(encoding="utf-8") == "{not json"


def test_claude_non_object_json_raises(tmp_path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text("[]", encoding="utf-8")
    with pytest.raises(ConfigError):
        install_claude(settings)


def test_claude_hook_timeout_comes_from_config(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("[integrations.claude]\ntimeout_s = 3\n", encoding="utf-8")
    monkeypatch.setenv("BASHBOY_CONFIG", str(cfg_path))
    result = install_claude(tmp_path / "settings.json", dry_run=True)
    assert result["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == 3


def test_build_handler_default() -> None:
    assert build_handler() == EXPECTED_HANDLER


# --- OpenCode -------------------------------------------------------------


def test_opencode_writes_plugin_and_config(tmp_path) -> None:
    base = tmp_path / "opencode"
    result = install_opencode(base)

    plugin_path = base / "plugins" / "bashboy.ts"
    assert plugin_path.exists()
    source = plugin_path.read_text(encoding="utf-8")
    assert "execute.before" in source
    assert "tool.execute.before" in source
    assert 'new Error("BashBoy blocked this command: "' in source
    assert "shell: false" in source
    assert "could not verify this command" in source

    config = read_json(base / "opencode.json")
    assert config["$schema"] == "https://opencode.ai/config.json"
    assert config["plugins"] == [str(plugin_path)]
    assert result["plugin_path"] == str(plugin_path)
    assert result["config"] == config


def test_opencode_preserves_entries_and_is_idempotent(tmp_path) -> None:
    base = tmp_path / "opencode"
    base.mkdir()
    (base / "opencode.json").write_text(
        json.dumps({"$schema": "https://opencode.ai/config.json", "plugin": ["other-plugin"]}),
        encoding="utf-8",
    )
    install_opencode(base)
    first = (base / "opencode.json").read_bytes()
    install_opencode(base)
    second = (base / "opencode.json").read_bytes()

    assert first == second
    config = read_json(base / "opencode.json")
    assert config["plugin"][0] == "other-plugin"
    assert config["plugin"].count(str(base / "plugins" / "bashboy.ts")) == 1
    assert "plugins" not in config


def test_opencode_dry_run_writes_nothing(tmp_path) -> None:
    base = tmp_path / "opencode"
    result = install_opencode(base, dry_run=True)
    assert not (base / "plugins" / "bashboy.ts").exists()
    assert not (base / "opencode.json").exists()
    assert result["config"]["plugins"] == [str(base / "plugins" / "bashboy.ts")]
    assert "execute.before" in result["plugin_source"]


def test_opencode_invalid_json_raises(tmp_path) -> None:
    base = tmp_path / "opencode"
    base.mkdir()
    (base / "opencode.json").write_text("{nope", encoding="utf-8")
    with pytest.raises(ConfigError):
        install_opencode(base)
    assert not (base / "plugins" / "bashboy.ts").exists()


def test_opencode_backs_up_existing_config(tmp_path) -> None:
    base = tmp_path / "opencode"
    base.mkdir()
    original = json.dumps({"$schema": "https://opencode.ai/config.json"}).encode("utf-8")
    (base / "opencode.json").write_bytes(original)
    install_opencode(base)
    assert (base / "opencode.json.bak").read_bytes() == original


def test_plugin_source_constant_is_complete() -> None:
    assert "Plugin.define" in PLUGIN_SOURCE
    assert "execute.before" in PLUGIN_SOURCE
    assert "tool.execute.before" in PLUGIN_SOURCE
    assert "BashBoy blocked this command: " in PLUGIN_SOURCE
    assert "TIMEOUT_MS_PLACEHOLDER" not in PLUGIN_SOURCE
    assert PLUGIN_SOURCE.count('"uvx"') == 1


def test_plugin_source_uses_configured_timeout(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("[integrations.opencode]\ntimeout_ms = 9999\n", encoding="utf-8")
    monkeypatch.setenv("BASHBOY_CONFIG", str(cfg_path))
    result = install_opencode(tmp_path / "oc", dry_run=True)
    assert "const TIMEOUT_MS = 9999" in result["plugin_source"]


def test_installers_refuse_bad_config(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("[provider\n", encoding="utf-8")
    monkeypatch.setenv("BASHBOY_CONFIG", str(cfg_path))
    with pytest.raises(ConfigError):
        install_claude(tmp_path / "settings.json", dry_run=True)
    with pytest.raises(ConfigError):
        install_opencode(tmp_path / "oc", dry_run=True)


def test_load_config_is_used_by_defaults(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BASHBOY_CONFIG", str(tmp_path / "missing.toml"))
    cfg = load_config()
    assert cfg.claude.timeout_s == 15
