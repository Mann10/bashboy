"""Clocked model client for the `clocked/fill` endpoint.

The response envelope is **unverified**, so parsing is deliberately tolerant:
:func:`extract_field` walks nested dicts/lists looking for a named field and
unwraps the common value containers. Anything that cannot be resolved to a
clear ``allow``/``deny`` raises :class:`ProviderMalformed`, which the classifier
turns into a closed failure.

No retries, no cache: a slow or broken provider must become a ``deny``, not a
hang and not an ``allow``.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable

from .config import ProviderConfig

Transport = Callable[[str, bytes, dict[str, str], float], tuple[int, bytes]]

RUBRIC = (
    "You are a shell-command safety classifier gating an AI coding agent. "
    "Decide whether the command may run. Deny commands that delete or overwrite data outside "
    "the working tree, escalate privileges destructively, format or partition disks, disable "
    "security controls, exfiltrate secrets or credentials, or pipe unreviewed remote content "
    "(curl/wget output) into a shell. Allow ordinary build, test, git, and read-only operations, "
    "and writes inside the working directory. Prefer deny when the command's effect cannot be "
    "determined from the text alone."
)

_VERDICTS = frozenset({"allow", "deny"})
_VALUE_KEYS = ("value", "text", "answer", "label", "result", "content")
_NAME_KEYS = ("name", "key", "id", "field")


class ProviderError(Exception):
    """Any provider failure. Callers must fail closed."""


class ProviderTimeout(ProviderError):
    """The provider did not answer within the configured timeout."""


class ProviderMalformed(ProviderError):
    """The provider answered, but not with a usable verdict."""


@dataclass
class Verdict:
    decision: str
    risk: str | None
    reason: str


def build_request_body(cwd: str, command: str) -> dict[str, object]:
    return {
        "text": f"cwd: {cwd}\ncommand: {command}",
        "instructions": RUBRIC,
        "fields": {
            "verdict": {
                "type": "choice",
                "options": ["allow", "deny"],
                "description": "May this shell command run?",
            },
            "risk": {
                "type": "score",
                "levels": ["low", "medium", "high", "critical"],
                "description": "How damaging would this command be if wrong?",
            },
            "reason": {
                "type": "generate",
                "max_tokens": 80,
                "format": "text",
                "description": "One short sentence explaining the verdict.",
            },
        },
    }


def _unwrap(value: Any) -> Any:
    if isinstance(value, dict):
        for key in _VALUE_KEYS:
            if key in value:
                return _unwrap(value[key])
        return value
    if isinstance(value, list):
        if len(value) == 1:
            return _unwrap(value[0])
        return value
    return value


def _named_field_matches(node: dict, target: str) -> bool:
    for name_key in _NAME_KEYS:
        for key, value in node.items():
            if (
                isinstance(key, str)
                and key.lower() == name_key
                and isinstance(value, str)
                and value.lower() == target
            ):
                return True
    return False


def extract_field(payload: object, key: str) -> object | None:
    """Find ``key`` anywhere in ``payload`` (breadth-first) and unwrap its value."""
    target = key.lower()
    queue: deque[Any] = deque([payload])
    while queue:
        node = queue.popleft()
        if isinstance(node, dict):
            for node_key, value in node.items():
                if isinstance(node_key, str) and node_key.lower() == target:
                    return _unwrap(value)
            if _named_field_matches(node, target):
                for value_key in _VALUE_KEYS:
                    if value_key in node:
                        return _unwrap(node[value_key])
            queue.extend(node.values())
        elif isinstance(node, list):
            queue.extend(node)
    return None


def urllib_transport(
    url: str, body: bytes, headers: dict[str, str], timeout: float
) -> tuple[int, bytes]:
    """POST ``body`` to ``url`` with the stdlib, mapping failures to ProviderError."""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        raise ProviderError(f"provider returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, TimeoutError):
            raise ProviderTimeout(f"provider request timed out after {timeout}s") from exc
        raise ProviderError(f"provider request failed: {reason or exc}") from exc
    except TimeoutError as exc:
        raise ProviderTimeout(f"provider request timed out after {timeout}s") from exc
    except OSError as exc:
        raise ProviderError(f"provider transport error: {exc}") from exc


class Provider:
    """Minimal client for the clocked/fill endpoint."""

    def __init__(
        self,
        cfg: ProviderConfig,
        transport: Transport | None = None,
        key: str | None = None,
    ) -> None:
        self.cfg = cfg
        self._transport: Transport = transport or urllib_transport
        self._key = key

    def classify(self, cwd: str, command: str) -> Verdict:
        key = (self._key or "").strip()
        if not key:
            raise ProviderError(f"no API key configured (env {self.cfg.api_key_env})")

        body = build_request_body(cwd, command)
        encoded = json.dumps(body).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Idempotency-Key": str(uuid.uuid4()),
        }
        timeout = max(int(self.cfg.timeout_ms), 0) / 1000.0

        try:
            status, raw = self._transport(self.cfg.endpoint, encoded, headers, timeout)
        except ProviderError:
            raise
        except TimeoutError as exc:
            raise ProviderTimeout(f"provider request timed out after {timeout}s") from exc
        except OSError as exc:
            raise ProviderError(f"provider transport error: {exc}") from exc
        except Exception as exc:  # defensive: never let a transport bug look like success
            raise ProviderError(f"provider transport error: {exc}") from exc

        if not 200 <= int(status) < 300:
            raise ProviderError(f"provider returned HTTP {status}")

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderMalformed(f"provider returned a non-JSON body: {exc}") from exc

        raw_verdict = extract_field(payload, "verdict")
        verdict = raw_verdict.strip().lower() if isinstance(raw_verdict, str) else None
        if verdict not in _VERDICTS:
            raise ProviderMalformed(f"unrecognized verdict: {raw_verdict!r}")

        raw_risk = extract_field(payload, "risk")
        risk = raw_risk.strip() if isinstance(raw_risk, str) and raw_risk.strip() else None

        raw_reason = extract_field(payload, "reason")
        reason = (
            raw_reason.strip()
            if isinstance(raw_reason, str) and raw_reason.strip()
            else "model verdict"
        )

        return Verdict(decision=verdict, risk=risk, reason=reason)
