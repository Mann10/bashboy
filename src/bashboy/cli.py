"""Command-line interface.

stdout is reserved for verdict output (``--json``), hook payloads, and installer
JSON in dry-run mode. Diagnostics go to stderr so ``| jq`` and hooks stay clean.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from pathlib import Path

from . import __version__
from .classify import classify_command, log
from .config import (
    DEFAULT_CONFIG_TOML,
    Config,
    ConfigError,
    api_key,
    config_path,
    load_config,
)


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def render_config(cfg: Config) -> str:
    lines = [
        f"# source: {cfg.path}",
        "[provider]",
        f'endpoint = "{cfg.provider.endpoint}"',
        f'api_key_env = "{cfg.provider.api_key_env}"',
        f"timeout_ms = {cfg.provider.timeout_ms}",
        "",
        "[policy]",
        f'fail_mode = "{cfg.policy.fail_mode}"',
        f"denylist = {_toml_bool(cfg.policy.denylist)}",
        f"allowlist = {_toml_bool(cfg.policy.allowlist)}",
        "",
        "[integrations.claude]",
        f"timeout_s = {cfg.claude.timeout_s}",
        "",
        "[integrations.opencode]",
        f"timeout_ms = {cfg.opencode.timeout_ms}",
    ]
    return "\n".join(lines) + "\n"


# --- check ----------------------------------------------------------------


def _cmd_check(args: argparse.Namespace) -> int:
    if args.claude_hook:
        from .hooks.claude import run_hook

        return run_hook(sys.stdin, sys.stdout)

    if args.command_text is None:
        print("bashboy: --command is required (or use --claude-hook)", file=sys.stderr)
        return 2

    cfg = load_config()
    log(f"config: {cfg.path}")
    result = classify_command(args.command_text, cwd=args.cwd, cfg=cfg)

    if args.json:
        print(json.dumps(result.to_dict()))
    else:
        print(f"{result.decision} ({result.source}): {result.reason}")
    return 0 if result.decision == "allow" else 1


# --- config ---------------------------------------------------------------


def _cmd_config(args: argparse.Namespace) -> int:
    path = config_path()
    if args.action is None or args.action == "path":
        print(path)
        return 0

    if args.action == "show":
        cfg = load_config()
        sys.stdout.write(render_config(cfg))
        return 0

    if args.action == "init":
        if path.exists() and not args.force:
            print(f"{path} already exists; re-run with --force to overwrite")
            return 1
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(DEFAULT_CONFIG_TOML, encoding="utf-8")
        print(f"wrote {path}")
        return 0

    print(f"bashboy: unknown config action {args.action!r}", file=sys.stderr)
    return 2


# --- install --------------------------------------------------------------

_DEFAULT_CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"


def _cmd_install(args: argparse.Namespace) -> int:
    both = args.all or (not args.claude and not args.opencode)
    run_claude = args.claude or both
    run_opencode = args.opencode or both

    try:
        from .installers.claude import install_claude
        from .installers.opencode import install_opencode
    except ImportError as exc:  # pragma: no cover - installers ship with the package
        print(f"bashboy: installers unavailable: {exc}", file=sys.stderr)
        return 2

    results: dict[str, dict] = {}
    try:
        if run_claude:
            results["claude"] = install_claude(
                args.settings, from_spec=args.from_spec, dry_run=args.dry_run
            )
        if run_opencode:
            results["opencode"] = install_opencode(args.config_dir, dry_run=args.dry_run)
    except (ConfigError, OSError, ValueError) as exc:
        print(f"bashboy: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        if run_claude and run_opencode:
            print(json.dumps({"claude": results["claude"], "opencode": results["opencode"]}))
        elif run_claude:
            print(json.dumps(results["claude"]))
        else:
            print(json.dumps(results["opencode"]))
        return 0

    if run_claude:
        settings = Path(args.settings) if args.settings else _DEFAULT_CLAUDE_SETTINGS
        print(f"claude: settings updated at {settings}")
    if run_opencode:
        print(f"opencode: plugin written to {results['opencode']['plugin_path']}")
    return 0


# --- selftest / version ---------------------------------------------------


class _FailingProvider:
    """Stand-in provider used by ``selftest`` to prove the fail-closed path."""

    def classify(self, cwd: str, command: str) -> object:
        raise RuntimeError("selftest: simulated provider outage")


def _cmd_selftest(args: argparse.Namespace) -> int:
    cfg = load_config()
    checks: list[tuple[str, bool]] = []

    deny_result = classify_command("rm -rf /", cfg=cfg)
    checks.append(
        ("deny 'rm -rf /' -> deny/denylist",
         deny_result.decision == "deny" and deny_result.source == "denylist")
    )

    allow_result = classify_command("git status", cfg=cfg)
    checks.append(
        ("allow 'git status' -> allow/allowlist",
         allow_result.decision == "allow" and allow_result.source == "allowlist")
    )

    fallback = classify_command("docker run --rm alpine sh", cfg=cfg, provider=_FailingProvider())
    checks.append(
        ("provider outage -> deny/fallback",
         fallback.decision == "deny" and fallback.source == "fallback")
    )

    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}")
    passed = sum(1 for _, ok in checks if ok)
    print(f"{passed}/{len(checks)} checks passed")

    key = api_key(cfg)
    if key:
        try:
            from .provider import Provider

            verdict = Provider(cfg.provider, key=key).classify(os.getcwd(), "git status")
            print(f"provider: ok ({verdict.decision})")
        except Exception as exc:  # noqa: BLE001 - reported, never fatal
            print(f"provider: FAILED ({exc})")
    else:
        print("provider: skipped (no API key)")

    return 0 if passed == len(checks) else 1


def _cmd_version(args: argparse.Namespace) -> int:
    print(f"bashboy {__version__} (python {platform.python_version()})")
    return 0


# --- parser ---------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bashboy",
        description="Classify shell commands as allow or deny before an agent runs them.",
    )
    sub = parser.add_subparsers(dest="subcommand")

    check = sub.add_parser("check", help="classify a command")
    check.add_argument("--command", dest="command_text", default=None, help="command to classify")
    check.add_argument("--cwd", default=os.getcwd(), help="working directory for the command")
    check.add_argument("--json", action="store_true", help="emit one JSON verdict object")
    check.add_argument(
        "--claude-hook",
        action="store_true",
        help="read a Claude Code PreToolUse payload from stdin",
    )
    check.set_defaults(handler=_cmd_check)

    install = sub.add_parser("install", help="install host integrations")
    install.add_argument("--claude", action="store_true", help="install the Claude Code hook")
    install.add_argument("--opencode", action="store_true", help="install the OpenCode plugin")
    install.add_argument("--all", action="store_true", help="install both integrations")
    install.add_argument("--dry-run", action="store_true", help="print what would be written")
    install.add_argument("--from", dest="from_spec", default=None, help="uvx --from SPEC")
    install.add_argument("--settings", default=None, help="Claude settings.json path")
    install.add_argument("--config-dir", default=None, help="OpenCode config directory")
    install.set_defaults(handler=_cmd_install)

    config = sub.add_parser("config", help="inspect or create the config file")
    config.add_argument("action", nargs="?", choices=["path", "show", "init"], default="path")
    config.add_argument("--force", action="store_true", help="overwrite an existing config")
    config.set_defaults(handler=_cmd_config)

    selftest = sub.add_parser("selftest", help="run offline self-checks")
    selftest.set_defaults(handler=_cmd_selftest)

    version = sub.add_parser("version", help="print the version")
    version.set_defaults(handler=_cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help(sys.stderr)
        return 2
    try:
        return int(handler(args))
    except ConfigError as exc:
        print(f"bashboy: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("bashboy: interrupted", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
