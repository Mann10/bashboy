"""Claude Code PreToolUse hook adapter tests (no subprocesses, no network)."""

from __future__ import annotations

import io
import json

import pytest

from bashboy.hooks.claude import (
    deny_payload,
    parse_hook_cwd,
    parse_hook_payload,
    run_hook,
)


def invoke(raw: str) -> tuple[int, str]:
    out = io.StringIO()
    code = run_hook(io.StringIO(raw), out)
    return code, out.getvalue()


def test_deny_payload_shape() -> None:
    payload = deny_payload("because")
    assert payload == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "because",
        }
    }


def test_denylisted_command_emits_deny_payload() -> None:
    code, out = invoke(json.dumps({"tool_input": {"command": "rm -rf /"}}))
    assert code == 0
    body = json.loads(out)
    assert body["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert body["hookSpecificOutput"]["permissionDecisionReason"]


def test_allowlisted_command_emits_nothing() -> None:
    code, out = invoke(json.dumps({"tool_input": {"command": "git status"}}))
    assert code == 0
    assert out == ""


def test_missing_command_emits_nothing() -> None:
    code, out = invoke(json.dumps({"tool_input": {}}))
    assert code == 0
    assert out == ""


def test_blank_command_emits_nothing() -> None:
    code, out = invoke(json.dumps({"tool_input": {"command": "   "}}))
    assert code == 0
    assert out == ""


@pytest.mark.parametrize("raw", ["not json", "", "{", "null", "[]", '{"tool_input": "x"}'])
def test_malformed_input_emits_nothing(raw: str) -> None:
    code, out = invoke(raw)
    assert code == 0
    assert out == ""


def test_tool_name_is_ignored_but_command_is_classified() -> None:
    code, out = invoke(
        json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
    )
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_read_dotenv_is_denied() -> None:
    code, out = invoke(
        json.dumps({"tool_name": "Read", "tool_input": {"file_path": "C:/proj/.env"}})
    )
    assert code == 0
    body = json.loads(out)["hookSpecificOutput"]
    assert body["permissionDecision"] == "deny"
    assert ".env" in body["permissionDecisionReason"]


def test_read_dotenv_variant_is_denied() -> None:
    code, out = invoke(
        json.dumps({"tool_name": "read", "tool_input": {"path": "app/.env.local"}})
    )
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_read_dotenv_template_is_allowed() -> None:
    code, out = invoke(
        json.dumps({"tool_name": "Read", "tool_input": {"file_path": ".env.example"}})
    )
    assert code == 0
    assert out == ""


def test_read_other_file_is_allowed() -> None:
    code, out = invoke(
        json.dumps({"tool_name": "Read", "tool_input": {"file_path": "README.md"}})
    )
    assert code == 0
    assert out == ""


def test_read_without_path_is_allowed() -> None:
    code, out = invoke(json.dumps({"tool_name": "Read", "tool_input": {}}))
    assert code == 0
    assert out == ""


def test_cmd_alias_is_accepted() -> None:
    code, out = invoke(json.dumps({"tool_input": {"cmd": "rm -rf /"}}))
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_internal_error_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import bashboy.hooks.claude as hook_module

    def boom(*args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(hook_module, "classify_command", boom)
    code, out = invoke(json.dumps({"tool_input": {"command": "git status"}}))
    assert code == 0
    payload = json.loads(out)["hookSpecificOutput"]
    assert payload["permissionDecision"] == "deny"
    assert "internal error" in payload["permissionDecisionReason"].lower()


def test_parse_hook_payload_variants() -> None:
    assert parse_hook_payload('{"tool_input":{"command":" ls "}}') == "ls"
    assert parse_hook_payload('{"tool_input":{"cmd":"ls"}}') == "ls"
    assert parse_hook_payload('{"tool_input":{"command":""}}') is None
    assert parse_hook_payload("nope") is None
    assert parse_hook_payload("{}") is None


def test_parse_hook_cwd_reads_top_level() -> None:
    assert parse_hook_cwd('{"cwd":"/home/me","tool_input":{"command":"ls"}}') == "/home/me"


def test_parse_hook_cwd_falls_back_to_tool_input() -> None:
    assert parse_hook_cwd('{"tool_input":{"cwd":"/tmp"}}') == "/tmp"


def test_parse_hook_cwd_absent() -> None:
    assert parse_hook_cwd("{}") is None
    assert parse_hook_cwd("not json") is None
