"""Configuration loading for BashBoy.

The config file is optional: a missing file means "documented defaults". A file
that exists but cannot be parsed is a hard error (exit 2 at the CLI), never a
silent fallback to defaults -- silently loosening policy would be worse than
refusing to run.

The API *token* is never read from, or written to, the config file -- only the
path to a per-user credential file is. The token itself is resolved at call time
from the environment or that file (see :func:`resolve_api_key`).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .credentials import permissions, read_token

DEFAULT_CONFIG_TOML = """\
[provider]
endpoint = "https://clocked.rezolve.ai/clocked/fill"
api_key_env = "CLOCKED_API_KEY"
api_key_file = "~/.bashboy/credentials"
timeout_ms = 4000

[policy]
fail_mode = "closed"   # closed | open
denylist = true
allowlist = true

[integrations.claude]
timeout_s = 15

[integrations.opencode]
timeout_ms = 15000
"""

FAIL_MODES = ("closed", "open")

DEFAULT_ENDPOINT = "https://clocked.rezolve.ai/clocked/fill"
DEFAULT_API_KEY_ENV = "CLOCKED_API_KEY"
DEFAULT_API_KEY_FILE = "~/.bashboy/credentials"
DEFAULT_TIMEOUT_MS = 4000
DEFAULT_CLAUDE_TIMEOUT_S = 15
DEFAULT_OPENCODE_TIMEOUT_MS = 15000


class ConfigError(Exception):
    """Raised when the configuration file or environment is unusable."""


@dataclass(frozen=True)
class ProviderConfig:
    endpoint: str = DEFAULT_ENDPOINT
    api_key_env: str = DEFAULT_API_KEY_ENV
    api_key_file: Path = field(default_factory=lambda: Path(DEFAULT_API_KEY_FILE).expanduser())
    timeout_ms: int = DEFAULT_TIMEOUT_MS


@dataclass(frozen=True)
class PolicyConfig:
    fail_mode: str = "closed"
    denylist: bool = True
    allowlist: bool = True


@dataclass(frozen=True)
class ClaudeIntegration:
    timeout_s: int = DEFAULT_CLAUDE_TIMEOUT_S


@dataclass(frozen=True)
class OpencodeIntegration:
    timeout_ms: int = DEFAULT_OPENCODE_TIMEOUT_MS


@dataclass(frozen=True)
class Config:
    provider: ProviderConfig
    policy: PolicyConfig
    claude: ClaudeIntegration
    opencode: OpencodeIntegration
    path: Path


def config_path() -> Path:
    """Return the config file location: ``BASHBOY_CONFIG`` or ``~/.bashboy/config.toml``."""
    override = os.environ.get("BASHBOY_CONFIG")
    if override and override.strip():
        return Path(override.strip()).expanduser()
    return Path.home() / ".bashboy" / "config.toml"


def _table(parent: dict, key: str, where: Path) -> dict:
    value = parent.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{where}: [{key}] must be a table")
    return value


def _as_str(table: dict, key: str, default: str, where: Path) -> str:
    if key not in table:
        return default
    value = table[key]
    if not isinstance(value, str):
        raise ConfigError(f"{where}: '{key}' must be a string")
    return value


def _as_int(table: dict, key: str, default: int, where: Path) -> int:
    if key not in table:
        return default
    value = table[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}: '{key}' must be an integer")
    return int(value)


def _as_bool(table: dict, key: str, default: bool, where: Path) -> bool:
    if key not in table:
        return default
    value = table[key]
    if not isinstance(value, bool):
        raise ConfigError(f"{where}: '{key}' must be true or false")
    return value


def _resolve_key_file_path(value: str, where: Path) -> Path:
    """Validate and expand ``api_key_file`` (no existence check: see D-09)."""
    text = value.strip()
    if not text:
        raise ConfigError(f"{where}: 'api_key_file' must not be empty")
    path = Path(text).expanduser()
    if not path.is_absolute():
        raise ConfigError(
            f"{where}: 'api_key_file' must be absolute or start with ~ (got {value!r})"
        )
    return path


def load_config(path: Path | None = None) -> Config:
    """Load configuration, applying documented defaults and environment overrides."""
    target = Path(path) if path is not None else config_path()

    raw = b""
    try:
        raw = target.read_bytes()
    except FileNotFoundError:
        raw = b""
    except OSError as exc:
        raise ConfigError(f"cannot read {target}: {exc}") from exc

    data: dict = {}
    if raw:
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError(f"{target}: not valid UTF-8: {exc}") from exc
        try:
            data = tomllib.loads(decoded)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{target}: invalid TOML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{target}: top-level value must be a table")

    provider_tbl = _table(data, "provider", target)
    policy_tbl = _table(data, "policy", target)
    integrations_tbl = _table(data, "integrations", target)
    claude_tbl = _table(integrations_tbl, "claude", target)
    opencode_tbl = _table(integrations_tbl, "opencode", target)

    raw_key_file = os.environ.get("BASHBOY_API_KEY_FILE") or _as_str(
        provider_tbl, "api_key_file", DEFAULT_API_KEY_FILE, target
    )
    api_key_file = _resolve_key_file_path(raw_key_file, target)

    provider = ProviderConfig(
        endpoint=_as_str(provider_tbl, "endpoint", DEFAULT_ENDPOINT, target),
        api_key_env=_as_str(provider_tbl, "api_key_env", DEFAULT_API_KEY_ENV, target),
        api_key_file=api_key_file,
        timeout_ms=_as_int(provider_tbl, "timeout_ms", DEFAULT_TIMEOUT_MS, target),
    )
    policy = PolicyConfig(
        fail_mode=_as_str(policy_tbl, "fail_mode", "closed", target),
        denylist=_as_bool(policy_tbl, "denylist", True, target),
        allowlist=_as_bool(policy_tbl, "allowlist", True, target),
    )
    claude = ClaudeIntegration(
        timeout_s=_as_int(claude_tbl, "timeout_s", DEFAULT_CLAUDE_TIMEOUT_S, target),
    )
    opencode = OpencodeIntegration(
        timeout_ms=_as_int(opencode_tbl, "timeout_ms", DEFAULT_OPENCODE_TIMEOUT_MS, target),
    )

    env_endpoint = os.environ.get("BASHBOY_ENDPOINT")
    if env_endpoint and env_endpoint.strip():
        provider = ProviderConfig(
            endpoint=env_endpoint.strip(),
            api_key_env=provider.api_key_env,
            api_key_file=provider.api_key_file,
            timeout_ms=provider.timeout_ms,
        )

    env_key_env = os.environ.get("BASHBOY_API_KEY_ENV")
    if env_key_env and env_key_env.strip():
        provider = ProviderConfig(
            endpoint=provider.endpoint,
            api_key_env=env_key_env.strip(),
            api_key_file=provider.api_key_file,
            timeout_ms=provider.timeout_ms,
        )

    env_fail_mode = os.environ.get("BASHBOY_FAIL_MODE")
    if env_fail_mode and env_fail_mode.strip():
        policy = PolicyConfig(
            fail_mode=env_fail_mode.strip(),
            denylist=policy.denylist,
            allowlist=policy.allowlist,
        )

    if policy.fail_mode not in FAIL_MODES:
        raise ConfigError(
            f"{target}: fail_mode must be one of {', '.join(FAIL_MODES)} (got {policy.fail_mode!r})"
        )

    return Config(
        provider=provider,
        policy=policy,
        claude=claude,
        opencode=opencode,
        path=target,
    )


def resolve_api_key(cfg: Config) -> tuple[str | None, str]:
    """Return ``(token, source_label)`` using the locked precedence order.

    1. the environment variable named by ``[provider].api_key_env``;
    2. ``BASHBOY_API_KEY_FILE`` (collapsed into ``api_key_file`` at load time);
    3. ``[provider].api_key_file`` from the config file;
    4. the default ``~/.bashboy/credentials``;
    5. nothing -- ``(None, "none")``.

    ``CredentialPermissionError`` propagates: callers decide how to fail closed.
    The label never contains the token.
    """
    raw = os.environ.get(cfg.provider.api_key_env)
    if raw is not None and raw.strip():
        return raw.strip(), f"env {cfg.provider.api_key_env}"

    token = read_token(cfg.provider.api_key_file)
    if token:
        state = permissions(cfg.provider.api_key_file)
        return token, f"file {cfg.provider.api_key_file} ({state.label})"
    return None, "none"


def api_key(cfg: Config) -> str | None:
    """Return the resolved API key, or ``None`` when nothing is configured."""
    return resolve_api_key(cfg)[0]
