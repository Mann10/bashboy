"""Claude Code ``PreToolUse`` hook adapter.

Contract (from Claude Code hooks):

* read one JSON object from stdin;
* **deny** -> print a ``hookSpecificOutput`` payload with
  ``permissionDecision: "deny"``;
* **allow** -> print *nothing* so the host's normal permission flow continues;
* always exit 0, even on malformed input or an internal error (fail closed:
  an internal error emits a deny payload).

Two tools are inspected: shell tools (``Bash``/``PowerShell``) are classified,
and ``Read`` is refused when the target is a dotenv file. Other tools are left
alone.
"""

from __future__ import annotations

import json
from typing import TextIO

from ..classify import classify_command
from ..rules import check_env_read


def _load(raw: str) -> dict | None:
    try:
        payload = json.loads(raw)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def parse_hook_payload(raw: str) -> str | None:
    """Return the command from a hook payload, or ``None``. Never raises."""
    payload = _load(raw)
    if payload is None:
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    for key in ("command", "cmd"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def parse_hook_cwd(raw: str) -> str | None:
    """Return the working directory from a hook payload, or ``None``.

    Claude Code carries ``cwd`` at the top level; some hosts nest it under
    ``tool_input``. Both are accepted.
    """
    payload = _load(raw)
    if payload is None:
        return None
    candidates = [payload.get("cwd")]
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        candidates.append(tool_input.get("cwd"))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def deny_payload(reason: str) -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _emit_deny(stdout: TextIO, reason: str) -> None:
    stdout.write(json.dumps(deny_payload(reason)) + "\n")
    stdout.flush()


def _tool_name(payload: dict) -> str:
    value = payload.get("tool_name")
    return value.strip().lower() if isinstance(value, str) else ""


def run_hook(stdin: TextIO, stdout: TextIO) -> int:
    """Classify the command on stdin, emit a deny payload only when denying."""
    try:
        raw = stdin.read()
        payload = _load(raw)
        if payload is None:
            return 0
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            return 0

        if _tool_name(payload) == "read":
            target = tool_input.get("file_path") or tool_input.get("path")
            hit = check_env_read(target)
            if hit is not None:
                _emit_deny(stdout, hit.reason)
            return 0

        command = parse_hook_payload(raw)
        if not command:
            return 0
        result = classify_command(command, cwd=parse_hook_cwd(raw))
        if result.decision == "deny":
            _emit_deny(stdout, result.reason)
        return 0
    except Exception as exc:  # noqa: BLE001 - fail closed, but never break the host
        try:
            _emit_deny(stdout, f"BashBoy internal error: {type(exc).__name__}")
        except Exception:
            pass
        return 0
