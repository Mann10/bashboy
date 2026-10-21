"""Claude Code ``PreToolUse`` hook adapter.

Contract (from Claude Code hooks):

* read one JSON object from stdin;
* **deny** -> print a ``hookSpecificOutput`` payload with
  ``permissionDecision: "deny"``;
* **allow** -> print *nothing* so the host's normal permission flow continues;
* always exit 0, even on malformed input or an internal error (fail closed:
  an internal error emits a deny payload).
"""

from __future__ import annotations

import json
from typing import TextIO

from ..classify import classify_command


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


def run_hook(stdin: TextIO, stdout: TextIO) -> int:
    """Classify the command on stdin, emit a deny payload only when denying."""
    try:
        raw = stdin.read()
        command = parse_hook_payload(raw)
        if not command:
            return 0
        result = classify_command(command, cwd=parse_hook_cwd(raw))
        if result.decision == "deny":
            stdout.write(json.dumps(deny_payload(result.reason)) + "\n")
            stdout.flush()
        return 0
    except Exception as exc:  # noqa: BLE001 - fail closed, but never break the host
        try:
            reason = f"BashBoy internal error: {type(exc).__name__}"
            stdout.write(json.dumps(deny_payload(reason)) + "\n")
            stdout.flush()
        except Exception:
            pass
        return 0
