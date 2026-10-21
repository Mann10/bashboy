"""CLI tests: exit codes, stdout contracts, config commands, and debug hygiene."""

from __future__ import annotations

import json

import pytest

from bashboy import cli
from bashboy.config import DEFAULT_CONFIG_TOML


def run(argv: list[str]) -> int:
    return cli.main(argv)


def test_check_deny_plain(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["check", "--command", "rm -rf /"])
    out = capsys.readouterr().out
    assert code == 1
    assert out.startswith("deny (denylist): ")


def test_check_allow_plain(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["check", "--command", "git status"])
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("allow (allowlist): ")


def test_check_json_allow(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["check", "--command", "git status", "--json"])
    out = capsys.readouterr().out
    assert code == 0
    payload = json.loads(out)
    assert payload["decision"] == "allow"
    assert payload["source"] == "allowlist"


def test_check_json_keys_are_exact(capsys: pytest.CaptureFixture[str]) -> None:
    run(["check", "--command", "git status", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert list(payload) == ["decision", "source", "reason", "risk", "latency_ms"]


def test_check_ambiguous_without_key_falls_back(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["check", "--command", "docker run --rm alpine sh", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["decision"] == "deny"
    assert payload["source"] == "fallback"


def test_check_compound_injection_is_denied(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["check", "--command", "ls; rm -rf /", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["source"] == "denylist"


def test_check_requires_command(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["check"])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "--command" in captured.err


def test_check_cwd_flag(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["check", "--command", "rm -rf *", "--cwd", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    # Not at a filesystem root, so the wildcard denylist rule must not fire.
    assert payload["source"] == "fallback"


def test_check_claude_hook_reads_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO('{"tool_input":{"command":"rm -rf /"}}'))
    code = cli.main(["check", "--claude-hook"])
    out = capsys.readouterr().out
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_check_claude_hook_allows_silently(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO('{"tool_input":{"command":"git status"}}'))
    code = cli.main(["check", "--claude-hook"])
    assert code == 0
    assert capsys.readouterr().out == ""


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["version"])
    out = capsys.readouterr().out
    assert code == 0
    assert "bashboy 0.1.0" in out


def test_selftest_without_key(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["selftest"])
    out = capsys.readouterr().out
    assert code == 0
    assert "PASS" in out
    assert "FAIL" not in out


def test_config_path(tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "cfg.toml"
    monkeypatch.setenv("BASHBOY_CONFIG", str(target))
    code = run(["config", "path"])
    assert code == 0
    assert capsys.readouterr().out.strip() == str(target)


def test_config_init_and_refusal(tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "nested" / "cfg.toml"
    monkeypatch.setenv("BASHBOY_CONFIG", str(target))

    assert run(["config", "init"]) == 0
    assert target.read_text(encoding="utf-8") == DEFAULT_CONFIG_TOML
    assert "wrote" in capsys.readouterr().out

    assert run(["config", "init"]) == 1
    assert "already exists" in capsys.readouterr().out

    assert run(["config", "init", "--force"]) == 0
    assert target.exists()


def test_config_show(tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "cfg.toml"
    target.write_text('[policy]\nfail_mode = "open"\n', encoding="utf-8")
    monkeypatch.setenv("BASHBOY_CONFIG", str(target))
    code = run(["config", "show"])
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("# source: ")
    assert 'fail_mode = "open"' in out
    assert "[provider]" in out


def test_config_error_exits_two(tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "broken.toml"
    target.write_text("[provider\n", encoding="utf-8")
    monkeypatch.setenv("BASHBOY_CONFIG", str(target))
    code = run(["check", "--command", "git status"])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "bashboy:" in captured.err


def test_debug_output_stays_off_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASHBOY_DEBUG", "1")
    code = run(["check", "--command", "git status", "--json"])
    captured = capsys.readouterr()
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["source"] == "allowlist"
    assert captured.out.count("\n") == 1
    assert "bashboy:" in captured.err
