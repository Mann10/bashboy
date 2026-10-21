"""Verdict pipeline: fast local paths first, model second, fail closed.

Precedence is fixed and auditable:

1. ``BASHBOY_DISABLE`` -- allow, source ``disabled`` (documented escape hatch).
2. Blank command -- deny, source ``fallback``.
3. Denylist -- deny, source ``denylist``.
4. Allowlist -- allow, source ``allowlist``.
5. Model -- allow/deny, source ``model``; any failure becomes ``fallback``.

The provider is imported lazily inside branch 5 so the fast paths never pay for
``urllib`` or ``json`` at startup.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass

from .config import Config, api_key, load_config
from .rules import check_allowlist, check_denylist

_TRUTHY = frozenset({"1", "true", "yes"})


def log(msg: str) -> None:
    """Write a diagnostic line to stderr, but only when ``BASHBOY_DEBUG`` is truthy.

    Never pass the API key, an ``Authorization`` header, or a full request body.
    """
    value = os.environ.get("BASHBOY_DEBUG", "")
    if value.strip().lower() in _TRUTHY:
        print(f"bashboy: {msg}", file=sys.stderr)


def _enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


@dataclass(frozen=True)
class Classification:
    """The final verdict the CLI prints and the hooks act on."""

    decision: str
    source: str
    reason: str
    risk: str | None = None
    latency_ms: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "latency_ms", int(self.latency_ms))

    def to_dict(self) -> dict[str, object]:
        # Key order is part of the CLI contract; keep it stable.
        return {
            "decision": self.decision,
            "source": self.source,
            "reason": self.reason,
            "risk": self.risk,
            "latency_ms": self.latency_ms,
        }

def _elapsed_ms(started: float) -> int:
    return max(int((time.perf_counter() - started) * 1000), 0)


def classify_command(
    command: str,
    cwd: str | None = None,
    cfg: Config | None = None,
    provider: object | None = None,
) -> Classification:
    """Classify ``command``. Never raises for provider problems; fails closed."""
    started = time.perf_counter()
    if cfg is None:
        cfg = load_config()

    if _enabled("BASHBOY_DISABLE"):
        latency = _elapsed_ms(started)
        log(f"BASHBOY_DISABLE is set: allowing without checks (latency={latency}ms)")
        return Classification("allow", "disabled", "BASHBOY_DISABLE is set", None, latency)

    if not isinstance(command, str) or not command.strip():
        return Classification("deny", "fallback", "no command provided", None, _elapsed_ms(started))

    if cfg.policy.denylist:
        hit = check_denylist(command, cwd)
        if hit is not None:
            latency = _elapsed_ms(started)
            log(f"denylist hit: {hit.reason} (latency={latency}ms)")
            return Classification("deny", "denylist", hit.reason, None, latency)

    if cfg.policy.allowlist:
        label = check_allowlist(command)
        if label is not None:
            latency = _elapsed_ms(started)
            log(f"allowlist hit: {label} (latency={latency}ms)")
            return Classification(
                "allow", "allowlist", f"matches allowlist: {label}", None, latency
            )

    from .provider import Provider

    target_cwd = cwd or os.getcwd()
    try:
        model = provider if provider is not None else Provider(cfg.provider, key=api_key(cfg))
        verdict = model.classify(target_cwd, command)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 - every failure must map to a verdict
        fail_open = cfg.policy.fail_mode == "open"
        decision = "allow" if fail_open else "deny"
        latency = _elapsed_ms(started)
        log(f"classifier unavailable: {exc} (latency={latency}ms)")
        return Classification(
            decision, "fallback", f"classifier unavailable: {exc}", None, latency
        )

    latency = _elapsed_ms(started)
    log(
        f"model verdict {verdict.decision} from {cfg.provider.endpoint} "
        f"(latency={latency}ms)"
    )
    return Classification(verdict.decision, "model", verdict.reason, verdict.risk, latency)
