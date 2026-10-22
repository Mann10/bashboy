"""CLI tests: exit codes, stdout contracts, config commands, and debug hygiene."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import bashboy.provider as provider_module
from bashboy import __version__, cli, credentials
from bashboy.config import DEFAULT_CONFIG_TOML
from bashboy.provider import ProviderError


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


def test_check_ambiguous_without_key_uses_local_rules(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = run(["check", "--command", "docker run --rm alpine sh", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["decision"] == "allow"
    assert payload["source"] == "local-only"


def test_check_require_key_without_key_denies(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BASHBOY_REQUIRE_KEY", "1")
    code = run(["check", "--command", "docker run --rm alpine sh", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["source"] == "fallback"


def test_rules_lists_destructive_and_env(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["rules"])
    out = capsys.readouterr().out
    assert code == 0
    assert "destructive:" in out
    assert "env:" in out
    assert "rm-protected-path" in out
    assert "env-dotenv" in out


def test_rules_json_contract(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["rules", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["rules"]
    assert set(payload["rules"][0]) == {"id", "category", "reason", "example"}


def test_rules_category_filter(capsys: pytest.CaptureFixture[str]) -> None:
    run(["rules", "--category", "env", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["rules"]
    assert {rule["category"] for rule in payload["rules"]} == {"env"}


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
    assert code == 0
    # Not at a filesystem root, so the wildcard denylist rule must not fire.
    assert payload["source"] == "local-only"


def test_check_wildcard_at_root_is_denied(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["check", "--command", "rm -rf *", "--cwd", "/", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["source"] == "denylist"


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
    assert f"bashboy {__version__}" in out


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


# --- auth -----------------------------------------------------------------

SENTINEL = "sk-bb-sentinel-DO-NOT-LEAK"


def credential_file(tmp_path) -> str:
    return str(tmp_path / "cred")


def patch_verify(monkeypatch: pytest.MonkeyPatch, *, exc: Exception | None = None) -> None:
    """Never let a CLI test touch the network."""

    def fake_verify(cfg, key, cwd=None):
        if exc is not None:
            raise exc
        return provider_module.Verdict("allow", None, "ok")

    monkeypatch.setattr(provider_module, "verify_key", fake_verify)


def test_auth_set_stdin_writes_and_validates(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    patch_verify(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO(SENTINEL + "\n"))
    target = credential_file(tmp_path)

    code = run(["auth", "set", "--stdin", "--file", target, "--force"])
    captured = capsys.readouterr()

    assert code == 0
    assert "provider: ok" in captured.out
    assert Path(target).read_text(encoding="utf-8") == SENTINEL + "\n"
    assert SENTINEL not in captured.out
    assert SENTINEL not in captured.err


def test_auth_set_refuses_existing_without_force(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    patch_verify(monkeypatch)
    target = Path(credential_file(tmp_path))
    target.write_text("original\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(SENTINEL + "\n"))

    code = run(["auth", "set", "--stdin", "--file", str(target)])
    captured = capsys.readouterr()

    assert code == 1
    assert "--force" in captured.err
    assert target.read_text(encoding="utf-8") == "original\n"


def test_auth_set_force_overwrites(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    patch_verify(monkeypatch)
    target = Path(credential_file(tmp_path))
    target.write_text("original\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(SENTINEL + "\n"))

    assert run(["auth", "set", "--stdin", "--file", str(target), "--force"]) == 0
    assert target.read_text(encoding="utf-8") == SENTINEL + "\n"
    capsys.readouterr()


def test_auth_set_empty_stdin_writes_nothing(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    patch_verify(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("   \n"))
    target = Path(credential_file(tmp_path))

    code = run(["auth", "set", "--stdin", "--file", str(target)])
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert not target.exists()


def test_auth_set_validation_failure_keeps_the_file(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    patch_verify(monkeypatch, exc=ProviderError("endpoint refused"))
    monkeypatch.setattr("sys.stdin", io.StringIO(SENTINEL + "\n"))
    target = Path(credential_file(tmp_path))

    code = run(["auth", "set", "--stdin", "--file", str(target), "--force"])
    captured = capsys.readouterr()

    assert code == 2
    assert "provider: FAILED (" in captured.out
    assert target.read_text(encoding="utf-8") == SENTINEL + "\n"


def test_auth_set_interactive_prompts_twice_and_mismatch_writes_nothing(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = Path(credential_file(tmp_path))
    prompts: list[str] = []

    def fake_getpass(prompt: str = "") -> str:
        prompts.append(prompt)
        return SENTINEL if len(prompts) == 1 else "something-else"

    monkeypatch.setattr(cli, "_getpass", fake_getpass)

    code = run(["auth", "set", "--file", str(target)])
    captured = capsys.readouterr()

    assert code == 2
    assert len(prompts) == 2
    assert not target.exists()
    assert SENTINEL not in captured.out
    assert SENTINEL not in captured.err


def test_auth_set_interactive_match_writes(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_verify(monkeypatch)
    target = Path(credential_file(tmp_path))
    monkeypatch.setattr(cli, "_getpass", lambda prompt="": SENTINEL)

    assert run(["auth", "set", "--file", str(target)]) == 0
    assert target.read_text(encoding="utf-8") == SENTINEL + "\n"
    capsys.readouterr()


def test_auth_status_reports_without_network(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = Path(credential_file(tmp_path))
    credentials.write_token(target, SENTINEL)
    if os.name == "nt":
        # %TEMP% ACLs vary by machine/sandbox; simulate a clean owner-only ACL.
        monkeypatch.setattr(credentials, "_windows_extra_principals", lambda path: [])

    def explode(*args, **kwargs):
        raise AssertionError("auth status must not call the provider without --check")

    monkeypatch.setattr(provider_module, "verify_key", explode)

    code = run(["auth", "status", "--file", str(target)])
    captured = capsys.readouterr()

    assert code == 0
    assert "config: " in captured.out
    assert "endpoint: " in captured.out
    assert f"credential file: {target}" in captured.out
    assert f"key source: file {target} (owner-only)" in captured.out
    assert "key: present" in captured.out
    assert "permissions: " in captured.out
    assert SENTINEL not in captured.out
    assert SENTINEL not in captured.err


def test_auth_status_refusal_is_reported_not_raised(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    if os.name == "nt":
        pytest.skip("POSIX permission refusal only")
    target = Path(credential_file(tmp_path))
    target.write_text(SENTINEL + "\n", encoding="utf-8")
    os.chmod(target, 0o644)

    code = run(["auth", "status", "--file", str(target)])
    captured = capsys.readouterr()

    assert code == 0
    assert "chmod 600" in captured.out
    assert "key: refused" in captured.out
    assert SENTINEL not in captured.out


def test_auth_status_check_reports_provider(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_verify(monkeypatch)
    target = Path(credential_file(tmp_path))
    credentials.write_token(target, SENTINEL)

    code = run(["auth", "status", "--file", str(target), "--check"])
    captured = capsys.readouterr()

    assert code == 0
    assert "provider: ok (allow)" in captured.out
    assert SENTINEL not in captured.out


def test_auth_status_check_failure_still_exits_zero(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_verify(monkeypatch, exc=ProviderError("boom"))
    target = Path(credential_file(tmp_path))
    credentials.write_token(target, SENTINEL)

    code = run(["auth", "status", "--file", str(target), "--check"])
    captured = capsys.readouterr()

    assert code == 0
    assert "provider: FAILED (" in captured.out


def test_auth_status_without_key_reports_absent(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASHBOY_API_KEY_FILE", str(tmp_path / "absent"))
    code = run(["auth", "status"])
    captured = capsys.readouterr()
    assert code == 0
    assert "key source: none" in captured.out
    assert "key: absent" in captured.out


def test_auth_clear_force_removes_and_missing_is_noop(
    tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = Path(credential_file(tmp_path))
    credentials.write_token(target, SENTINEL)

    assert run(["auth", "clear", "--file", str(target), "--force"]) == 0
    assert not target.exists()
    assert "removed" in capsys.readouterr().out

    assert run(["auth", "clear", "--file", str(target), "--force"]) == 0
    assert "no credential file" in capsys.readouterr().out


def test_auth_clear_prompt_no_keeps_the_file(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = Path(credential_file(tmp_path))
    credentials.write_token(target, SENTINEL)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    code = run(["auth", "clear", "--file", str(target)])
    captured = capsys.readouterr()

    assert code == 1
    assert "aborted" in captured.out
    assert target.exists()


def test_auth_clear_prompt_yes_removes(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = Path(credential_file(tmp_path))
    credentials.write_token(target, SENTINEL)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")

    assert run(["auth", "clear", "--file", str(target)]) == 0
    assert not target.exists()
    capsys.readouterr()


def test_auth_without_action_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["auth"])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "usage" in captured.err


def test_config_show_includes_api_key_file(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "cfg.toml"
    target.write_text("[provider]\n", encoding="utf-8")
    monkeypatch.setenv("BASHBOY_CONFIG", str(target))
    monkeypatch.setenv("BASHBOY_API_KEY_FILE", str(tmp_path / "cred"))
    code = run(["config", "show"])
    out = capsys.readouterr().out
    assert code == 0
    assert "api_key_file = " in out
    assert "cred" in out
    assert SENTINEL not in out


def test_auth_output_never_contains_the_token(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    patch_verify(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO(SENTINEL + "\n"))
    target = Path(credential_file(tmp_path))

    assert run(["auth", "set", "--stdin", "--file", str(target), "--force"]) == 0
    set_output = capsys.readouterr()
    assert run(["auth", "status", "--file", str(target)]) == 0
    status_output = capsys.readouterr()

    for captured in (set_output, status_output):
        assert SENTINEL not in captured.out
        assert SENTINEL not in captured.err


# --- policy ---------------------------------------------------------------

DENY_PROD_POLICY = """\
version = 1

[[rule]]
id = "no-prod-db"
action = "deny"
match = '(?i)\\bpsql\\b.*\\bprod'
reason = "Production database access is prohibited"
"""


def explicit_policy(tmp_path, text: str = DENY_PROD_POLICY) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_policy_path_reports_every_source(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASHBOY_POLICY_ORG", str(tmp_path / "org.toml"))
    monkeypatch.setenv("BASHBOY_POLICY_USER", str(tmp_path / "user.toml"))
    monkeypatch.setenv("BASHBOY_POLICY_PROJECT", str(tmp_path / "project.toml"))
    code = run(["policy", "path"])
    out = capsys.readouterr().out
    assert code == 0
    assert "org:" in out
    assert "user:" in out
    assert "project:" in out
    assert "missing" in out


def test_policy_show_json(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASHBOY_POLICY", str(explicit_policy(tmp_path)))
    code = run(["policy", "show", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["sources"][0]["source"] == "explicit"
    assert payload["sources"][0]["exists"] is True
    assert payload["flags"] == {
        "immutable": False,
        "disable_escape_hatch": False,
        "require_key": False,
    }
    assert payload["rules"][0]["id"] == "no-prod-db"
    assert payload["rules"][0]["action"] == "deny"
    assert payload["rules"][0]["match"] == "(?i)\\bpsql\\b.*\\bprod"


def test_policy_show_text(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASHBOY_POLICY", str(explicit_policy(tmp_path)))
    code = run(["policy", "show"])
    out = capsys.readouterr().out
    assert code == 0
    assert "sources:" in out
    assert "flags:" in out
    assert "no-prod-db" in out
    assert "Production database access is prohibited" in out


def test_policy_test_plain_and_json(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASHBOY_POLICY", str(explicit_policy(tmp_path)))

    assert run(["policy", "test", "psql prod"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("deny (policy no-prod-db from explicit): ")

    assert run(["policy", "test", "psql prod", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "matched": True,
        "decision": "deny",
        "rule": "no-prod-db",
        "source": "explicit",
        "reason": "Production database access is prohibited",
    }


def test_policy_test_without_a_match(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASHBOY_POLICY", str(explicit_policy(tmp_path)))
    assert run(["policy", "test", "ls"]) == 0
    assert capsys.readouterr().out == "no policy match\n"

    assert run(["policy", "test", "ls", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "matched": False,
        "decision": None,
        "rule": None,
        "source": None,
        "reason": None,
    }


def test_policy_test_requires_a_command(capsys: pytest.CaptureFixture[str]) -> None:
    code = run(["policy", "test"])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "requires a command" in captured.err


def test_policy_show_and_test_report_parse_errors(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASHBOY_POLICY", str(explicit_policy(tmp_path, "version = 1\n[[rule]\n")))
    assert run(["policy", "show"]) == 2
    assert "bashboy:" in capsys.readouterr().err

    assert run(["policy", "test", "ls"]) == 2
    assert "bashboy:" in capsys.readouterr().err


def test_policy_init_user(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "nested" / "policy.toml"
    monkeypatch.setenv("BASHBOY_POLICY_USER", str(target))
    assert run(["policy", "init", "--scope", "user"]) == 0
    assert target.read_text(encoding="utf-8").startswith("version = 1")
    assert "wrote" in capsys.readouterr().out


def test_policy_init_project(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(["policy", "init", "--scope", "project", "--cwd", str(tmp_path)]) == 0
    target = tmp_path / ".bashboy" / "policy.toml"
    assert target.exists()
    assert "wrote" in capsys.readouterr().out


def test_policy_init_org_includes_flags(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "org-policy.toml"
    monkeypatch.setenv("BASHBOY_POLICY_ORG", str(target))
    assert run(["policy", "init", "--scope", "org"]) == 0
    text = target.read_text(encoding="utf-8")
    assert "[policy]" in text
    assert "immutable = true" in text
    assert "disable_escape_hatch = true" in text
    assert "require_key = true" in text
    captured = capsys.readouterr()
    assert "wrote" in captured.out
    assert "MDM" in captured.err


def test_policy_init_refuses_to_overwrite(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "policy.toml"
    target.write_text("version = 1\n", encoding="utf-8")
    monkeypatch.setenv("BASHBOY_POLICY_USER", str(target))

    assert run(["policy", "init", "--scope", "user"]) == 1
    assert "already exists" in capsys.readouterr().out
    assert target.read_text(encoding="utf-8") == "version = 1\n"

    assert run(["policy", "init", "--scope", "user", "--force"]) == 0
    assert "wrote" in capsys.readouterr().out

