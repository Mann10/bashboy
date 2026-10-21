"""Configuration loading for BashBoy.

The config file is optional: a missing file means "documented defaults". A file
that exists but cannot be parsed is a hard error (exit 2 at the CLI), never a
silent fallback to defaults -- silently loosening policy would be worse than
refusing to run.

The API key is never read from, or written to, the config file. It is resolved
from the environment at call time.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG_TOML = """\
[provider]
endpoint = "https://clocked.rezolve.ai/clocked/fill"
api_key_env = "CLOCKED_API_KEY"
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
DEFAULT_TIMEOUT_MS = 4000
DEFAULT_CLAUDE_TIMEOUT_S = 15
DEFAULT_OPENCODE_TIMEOUT_MS = 15000


class ConfigError(Exception):
    """Raised when the configuration file or environment is unusable."""


@dataclass(frozen=True)
class ProviderConfig:
    endpoint: str = DEFAULT_ENDPOINT
    api_key_env: str = DEFAULT_API_KEY_ENV
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

    provider = ProviderConfig(
        endpoint=_as_str(provider_tbl, "endpoint", DEFAULT_ENDPOINT, target),
        api_key_env=_as_str(provider_tbl, "api_key_env", DEFAULT_API_KEY_ENV, target),
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
            timeout_ms=provider.timeout_ms,
        )

    env_key_env = os.environ.get("BASHBOY_API_KEY_ENV")
    if env_key_env and env_key_env.strip():
        provider = ProviderConfig(
            endpoint=provider.endpoint,
            api_key_env=env_key_env.strip(),
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


def api_key(cfg: Config) -> str | None:
    """Return the API key from the environment named by the config, or ``None``."""
    raw = os.environ.get(cfg.provider.api_key_env)
    if raw is None:
        return None
    raw = raw.strip()
    return raw or None
