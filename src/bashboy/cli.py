"""Command-line interface.

stdout is reserved for verdict output (``--json``), hook payloads, and installer
JSON in dry-run mode. Diagnostics go to stderr so ``| jq`` and hooks stay clean.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import platform
import sys
from getpass import getpass as _getpass
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
    resolve_api_key,
)
from .credentials import (
    CredentialError,
    CredentialExistsError,
    CredentialPermissionError,
    clear_token,
    permissions,
    write_token,
)


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _toml_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_config(cfg: Config) -> str:
    lines = [
        f"# source: {cfg.path}",
        "[provider]",
        f'endpoint = "{cfg.provider.endpoint}"',
        f'api_key_env = "{cfg.provider.api_key_env}"',
        f"api_key_file = {_toml_string(str(cfg.provider.api_key_file))}",
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


# --- rules ----------------------------------------------------------------


def _cmd_rules(args: argparse.Namespace) -> int:
    from .rules import RULES

    selected = [
        rule for rule in RULES if args.category == "all" or rule.category == args.category
    ]
    if args.json:
        payload = {
            "rules": [
                {
                    "id": rule.id,
                    "category": rule.category,
                    "reason": rule.reason,
                    "example": rule.example,
                }
                for rule in selected
            ]
        }
        print(json.dumps(payload))
        return 0

    current = None
    for rule in selected:
        if rule.category != current:
            current = rule.category
            print(f"{current}:")
        print(f"  {rule.id:<28} {rule.reason}")
        print(f"  {'':<28} e.g. {rule.example}")
    return 0


# --- policy ---------------------------------------------------------------


def _policy_init_target(scope: str, cwd: str) -> Path:
    from .policy import org_policy_path, user_policy_path

    if scope == "org":
        return org_policy_path()
    if scope == "project":
        return Path(cwd) / ".bashboy" / "policy.toml"
    return user_policy_path()


def _cmd_policy(args: argparse.Namespace) -> int:
    from .policy import (
        ORG_TEMPLATE,
        TEMPLATE,
        PolicyError,
        evaluate_policy,
        load_policy,
        policy_paths,
    )

    if args.action == "path":
        for source, path in policy_paths(args.cwd):
            state = "exists" if path.is_file() else "missing"
            print(f"{source}: {path} ({state})")
        return 0

    if args.action == "init":
        target = _policy_init_target(args.scope, args.cwd)
        if target.exists() and not args.force:
            print(f"{target} already exists; re-run with --force to overwrite")
            return 1
        template = ORG_TEMPLATE if args.scope == "org" else TEMPLATE
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(template, encoding="utf-8")
        except OSError as exc:
            print(f"bashboy: cannot write {target}: {exc}", file=sys.stderr)
            return 2
        print(f"wrote {target}")
        if args.scope == "org":
            print(
                "note: the system policy is normally admin-owned; "
                "deploy it with your MDM/configuration tool",
                file=sys.stderr,
            )
        return 0

    try:
        policy = load_policy(args.cwd)
    except PolicyError as exc:
        print(f"bashboy: {exc}", file=sys.stderr)
        return 2

    if args.action == "show":
        if args.json:
            payload = {
                "flags": dataclasses.asdict(policy.flags),
                "sources": [
                    {"source": source, "path": str(path), "exists": exists}
                    for source, path, exists in policy.sources
                ],
                "rules": [
                    {
                        "id": rule.id,
                        "action": rule.action,
                        "source": rule.source,
                        "path": str(rule.path),
                        "reason": rule.reason,
                        "match": rule.regex.pattern if rule.regex is not None else None,
                        "contains": rule.contains,
                        "cwd": rule.cwd,
                        "ignored": rule.ignored,
                    }
                    for rule in policy.rules
                ],
            }
            print(json.dumps(payload))
            return 0

        print("sources:")
        for source, path, exists in policy.sources:
            print(f"  {source:<8} {path} ({'exists' if exists else 'missing'})")
        flags = policy.flags
        print(
            "flags: "
            f"immutable={_toml_bool(flags.immutable)} "
            f"disable_escape_hatch={_toml_bool(flags.disable_escape_hatch)} "
            f"require_key={_toml_bool(flags.require_key)}"
        )
        if not policy.rules:
            print("rules: none")
            return 0
        print("rules:")
        for rule in policy.rules:
            detail = (
                f"match={rule.regex.pattern!r}"
                if rule.regex is not None
                else f"contains={rule.contains!r}"
            )
            if rule.cwd is not None:
                detail += f" cwd={rule.cwd!r}"
            suffix = f" [ignored: {rule.ignored}]" if rule.ignored else ""
            print(
                f"  {rule.source:<8} {rule.id:<24} {rule.action:<5} "
                f"{detail} -- {rule.reason}{suffix}"
            )
        return 0

    # action == "test"
    if not args.command:
        print("bashboy: policy test requires a command", file=sys.stderr)
        return 2
    hit = evaluate_policy(policy, args.command, args.cwd)
    if args.json:
        print(
            json.dumps(
                {
                    "matched": hit is not None,
                    "decision": hit.decision if hit is not None else None,
                    "rule": hit.rule_id if hit is not None else None,
                    "source": hit.source if hit is not None else None,
                    "reason": hit.reason if hit is not None else None,
                }
            )
        )
        return 0
    if hit is None:
        print("no policy match")
    else:
        print(f"{hit.decision} (policy {hit.rule_id} from {hit.source}): {hit.reason}")
    return 0


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


# --- auth -----------------------------------------------------------------


def _credential_target(args: argparse.Namespace, cfg: Config) -> Path:
    override = getattr(args, "file", None)
    if override:
        return Path(override).expanduser().resolve()
    return cfg.provider.api_key_file


def _cmd_auth(args: argparse.Namespace) -> int:
    print(
        "usage: bashboy auth {set,status,clear} ... (see `bashboy auth --help`)",
        file=sys.stderr,
    )
    return 2


def _cmd_auth_set(args: argparse.Namespace) -> int:
    cfg = load_config()
    path = _credential_target(args, cfg)

    if args.stdin:
        token = sys.stdin.read().strip()
    else:
        token = _getpass("Clocked API key (input hidden): ").strip()
        if token:
            confirm = _getpass("Repeat to confirm (input hidden): ").strip()
            if confirm != token:
                print("bashboy: tokens did not match", file=sys.stderr)
                return 2
    if not token:
        print("bashboy: no token provided", file=sys.stderr)
        return 2

    try:
        write_token(path, token, overwrite=args.force)
    except CredentialExistsError as exc:
        print(f"bashboy: {exc}", file=sys.stderr)
        return 1
    except (CredentialError, OSError) as exc:
        print(f"bashboy: {exc}", file=sys.stderr)
        return 2

    print(f"saved {path}")
    print(f"permissions: {permissions(path).detail}")

    if os.environ.get(cfg.provider.api_key_env, "").strip():
        print(
            f"note: {cfg.provider.api_key_env} is set and takes precedence over the file",
            file=sys.stderr,
        )

    from .provider import verify_key  # lazy: keeps `bashboy --help` fast

    try:
        verdict = verify_key(cfg.provider, token)
    except Exception as exc:  # noqa: BLE001 - reported, never fatal
        print(f"provider: FAILED ({exc})")
        return 2
    print(f"provider: ok ({verdict.decision})")
    return 0


def _cmd_auth_status(args: argparse.Namespace) -> int:
    cfg = load_config()
    path = _credential_target(args, cfg)
    if path != cfg.provider.api_key_file:
        # `--file` must drive resolution too, not just the reported path.
        cfg = dataclasses.replace(
            cfg, provider=dataclasses.replace(cfg.provider, api_key_file=path)
        )
    # The only place the Windows ACL is probed: never on the `check` hot path.
    state = permissions(path, probe_acl=True)

    print(f"config: {cfg.path}")
    print(f"endpoint: {cfg.provider.endpoint}")
    print(f"credential file: {path}")
    print(f"permissions: {state.detail}")
    if state.label == "extra-principals":
        log(f"credential file ACL: {state.detail}")

    try:
        key, source = resolve_api_key(cfg)
    except CredentialPermissionError as exc:
        key, source = None, f"refused ({exc})"
    except CredentialError as exc:
        key, source = None, f"unreadable ({exc})"
    if key and state.label in {"extra-principals", "unverified"}:
        # The probe above is more specific than the hot-path label in `source`.
        source = f"file {path} ({state.label})"
    print(f"key source: {source}")
    if key:
        print("key: present")
    elif source.startswith(("refused", "unreadable")):
        print("key: refused")
    else:
        print("key: absent")
        print("mode: local rules only (unknown commands are not sent to the model)")

    if args.check:
        if key:
            from .provider import verify_key  # lazy: opt-in network call only

            try:
                verdict = verify_key(cfg.provider, key)
            except Exception as exc:  # noqa: BLE001 - reported, never fatal
                print(f"provider: FAILED ({exc})")
            else:
                print(f"provider: ok ({verdict.decision})")
        else:
            print("provider: skipped (no API key)")
    return 0


def _cmd_auth_clear(args: argparse.Namespace) -> int:
    cfg = load_config()
    path = _credential_target(args, cfg)
    if not path.is_file():
        print(f"no credential file at {path}")
        return 0

    if not args.force:
        answer = input(f"delete {path}? [y/N] ")
        if answer.strip().lower() not in {"y", "yes"}:
            print("aborted")
            return 1

    try:
        clear_token(path)
    except OSError as exc:
        print(f"bashboy: {exc}", file=sys.stderr)
        return 2
    print(f"removed {path}")
    return 0


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
            results["opencode"] = install_opencode(
                args.config_dir, from_spec=args.from_spec, dry_run=args.dry_run
            )
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

    rules = sub.add_parser("rules", help="list the built-in destructive and env rules")
    rules.add_argument("--json", action="store_true", help="emit one JSON object")
    rules.add_argument(
        "--category",
        choices=["all", "destructive", "env"],
        default="all",
        help="show only one category",
    )
    rules.set_defaults(handler=_cmd_rules)

    policy = sub.add_parser(
        "policy", help="inspect and test the layered org/user/project policy"
    )
    policy.add_argument(
        "action",
        nargs="?",
        choices=["path", "show", "test", "init"],
        default="path",
        help="path (default), show, test, or init",
    )
    policy.add_argument(
        "command", nargs="?", default=None, help="command to evaluate for `policy test`"
    )
    policy.add_argument("--json", action="store_true", help="emit one JSON object")
    policy.add_argument("--cwd", default=os.getcwd(), help="working directory for matching")
    policy.add_argument(
        "--scope",
        choices=["user", "project", "org"],
        default="user",
        help="target for `policy init`",
    )
    policy.add_argument("--force", action="store_true", help="overwrite an existing file")
    policy.set_defaults(handler=_cmd_policy)

    install = sub.add_parser("install", help="install host integrations")
    install.add_argument("--claude", action="store_true", help="install the Claude Code hook")
    install.add_argument("--opencode", action="store_true", help="install the OpenCode plugin")
    install.add_argument("--all", action="store_true", help="install both integrations")
    install.add_argument("--dry-run", action="store_true", help="print what would be written")
    install.add_argument(
        "--from",
        dest="from_spec",
        default=None,
        help="uvx --from SPEC for Claude and OpenCode",
    )
    install.add_argument("--settings", default=None, help="Claude settings.json path")
    install.add_argument("--config-dir", default=None, help="OpenCode config directory")
    install.set_defaults(handler=_cmd_install)

    config = sub.add_parser("config", help="inspect or create the config file")
    config.add_argument("action", nargs="?", choices=["path", "show", "init"], default="path")
    config.add_argument("--force", action="store_true", help="overwrite an existing config")
    config.set_defaults(handler=_cmd_config)

    auth = sub.add_parser("auth", help="manage the Clocked API key file")
    auth.set_defaults(handler=_cmd_auth)
    auth_sub = auth.add_subparsers(dest="auth_action")

    auth_set = auth_sub.add_parser("set", help="save the API key to the credential file")
    auth_set.add_argument("--file", default=None, help="credential file path")
    auth_set.add_argument("--stdin", action="store_true", help="read the key from stdin")
    auth_set.add_argument("--force", action="store_true", help="overwrite an existing file")
    auth_set.set_defaults(handler=_cmd_auth_set)

    auth_status = auth_sub.add_parser("status", help="show the key source and file permissions")
    auth_status.add_argument("--file", default=None, help="credential file path")
    auth_status.add_argument("--check", action="store_true", help="make one live provider call")
    auth_status.set_defaults(handler=_cmd_auth_status)

    auth_clear = auth_sub.add_parser("clear", help="delete the credential file")
    auth_clear.add_argument("--file", default=None, help="credential file path")
    auth_clear.add_argument("--force", action="store_true", help="skip the confirmation prompt")
    auth_clear.set_defaults(handler=_cmd_auth_clear)

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
    except (ConfigError, CredentialError) as exc:
        print(f"bashboy: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("bashboy: interrupted", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
