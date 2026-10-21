# BashBoy

[![PyPI](https://img.shields.io/pypi/v/bashboy.svg)](https://pypi.org/project/bashboy/)
[![Python](https://img.shields.io/pypi/pyversions/bashboy.svg)](https://pypi.org/project/bashboy/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

BashBoy is a small, dependency-free Python CLI that classifies a shell command as
`allow` or `deny` **before** a coding agent runs it. It sits in front of Claude Code
(`PreToolUse` hook) and OpenCode (plugin) and answers one question: is this command
safe to run unattended?

> **BashBoy only narrows; `allow` means *no objection*.** It never approves a tool
> call. When BashBoy says `allow` it prints nothing (Claude) or returns normally
> (OpenCode), and the host's normal permission flow still applies. There is no
> `ask` verdict, no auto-approve path, and no way for BashBoy to widen permissions.

Three layers, in order:

1. **Local fast paths** (no network): a structural allowlist for single read-only
   commands, and a hard denylist for destructive and secret-reading ones.
2. **Model classification** against the Clocked (`clocked/fill`) endpoint for everything
   else, when a key is configured.
3. **Host adapters** that express denial only.

Without a Clocked key, step 2 is skipped: known-bad commands are still denied, and
everything else produces **no objection**, so the host's own permission flow decides.
Set `BASHBOY_REQUIRE_KEY=1` to deny unknown commands instead. Anything the model path
cannot answer clearly becomes `deny`.

## Install

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/) (recommended; `pipx` works too).

```bash
uv tool install bashboy     # install the `bashboy` command
uvx bashboy --help          # or run without installing
pipx install bashboy        # pipx alternative
```

Verify the install:

```bash
bashboy version             # bashboy 0.4.0
bashboy selftest            # offline checks; reports provider: ok when the key works
```

From a local checkout (for development, before a release is published):

```bash
uvx --from /path/to/BashBoy bashboy check --command "git status"
uvx --from /path/to/BashBoy bashboy install --claude
```

The package has **zero runtime dependencies** — everything is the Python standard
library. `pytest` is a development-only dependency.

### API key

The token is resolved at call time; the first hit wins:

| # | Source | Notes |
|---|--------|-------|
| 1 | `CLOCKED_API_KEY` (or the variable named by `[provider].api_key_env`) | Process environment; wins over everything |
| 2 | `BASHBOY_API_KEY_FILE` | Full path to a credential file |
| 3 | `[provider].api_key_file` in `config.toml` | `~` is expanded |
| 4 | `~/.bashboy/credentials` | Default per-user file |
| 5 | nothing | Local rules only: known-bad commands are denied, everything else gets no objection; `BASHBOY_REQUIRE_KEY=1` turns that into a deny |

GUI-launched hosts (Claude Code desktop, OpenCode's background service) do not
inherit a shell profile, so a variable exported in a terminal is invisible to
them. `setx` fixes that by exposing the key to every process on the machine. A
per-user credential file is the middle ground: one host-agnostic location, no
machine-wide secret, and rotation is a single file write.

```bash
bashboy auth set                    # prompt twice; input is never echoed
bashboy auth status                 # path, source, presence, permissions
bashboy auth status --check         # + one live provider call
bashboy auth clear                  # delete after confirmation

# provisioning / CI
echo "$CLOCKED_API_KEY" | bashboy auth set --stdin --force
```

On Windows, `getpass` reads raw keystrokes with echo off, and pasting into that
prompt is unreliable — Ctrl+V can land nothing or drop characters. If the
prompt seems to ignore your paste, put the key on the clipboard and pipe it
instead (it never touches shell history):

```powershell
Get-Clipboard | bashboy auth set --stdin --force
```

`auth set` writes the file atomically, creates `~/.bashboy` with mode `0700` on
POSIX, and sets the file itself to `0600`. The token is never accepted as a
command-line argument — it would land in shell history and process listings — and
it is never printed, logged, or stored in `config.toml` (which is shareable and
gets pasted into issues). `auth status` never prints the value and makes no
network call unless you pass `--check`.

Permission policy:

- **POSIX:** any group/other permission bit (`mode & 0o077`) is refused with a
  message naming `chmod 600 <path>`, and the model path fails closed. Failing
  closed beats silently consuming a leaked secret.
- **Windows:** the file lives under your user profile, whose default ACL is
  owner-only. `bashboy auth status` inspects the ACL with `icacls` and reports
  any extra principals; it warns but still uses the key, because inherited
  entries are normal. The ACL probe never runs on the `bashboy check` hot path.

The token is read from the file at call time, so rotating it needs no host
restart. A missing or empty file simply means "no key": BashBoy keeps enforcing
the built-in rules and skips the model, so `bashboy rules` shows exactly what is
still blocked. For CI or a strict machine, `BASHBOY_REQUIRE_KEY=1` makes an
unknown command a `deny` (`source: "fallback"`) instead.

## Quick start

```bash
bashboy check --command "rm -rf /"
# deny (denylist): recursive delete of a protected path

bashboy check --command "git status"
# allow (allowlist): matches allowlist: git status

bashboy check --command "docker run --rm alpine sh" --json
# {"decision": "deny", "source": "fallback", "reason": "classifier unavailable: no API key configured (set CLOCKED_API_KEY or run `bashboy auth set`)", ...}
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0`  | `allow` |
| `1`  | `deny` |
| `2`  | configuration or usage error (never a silent allow) |

`--json` prints exactly one object, in this key order:

```json
{"decision":"deny","source":"denylist","reason":"recursive delete of a protected path","risk":null,"latency_ms":0}
```

`source` is one of `denylist`, `allowlist`, `model`, `local-only`, `fallback`,
`disabled`. `--cwd DIR` supplies the working directory used for context (default:
current directory).

## Built-in rules

```bash
bashboy rules                  # grouped listing with an example per rule
bashboy rules --category env   # only the secret-related rules
bashboy rules --json           # {"rules":[{"id","category","reason","example"}]}
```

The denylist covers filesystem-root and system-directory deletes, wildcard deletes
at a root, drive-root deletes (PowerShell, `rd /s`, `del /s`, Git Bash `/c/`),
`mkfs`/`wipefs`/`blkdiscard`, raw writes to block devices, fork bombs, root
`chmod`/`chown`, power control, `find / -delete`, and `.env` access. The env rules
also block bare `printenv`/`env`/`set`/`export -p`, `/proc/*/environ`, and
PowerShell `Env:` dumps, because those expose every secret in the process
environment.

Rules run before the allowlist, so `cat .env` is denied even though `cat` is
allowlisted. Denials cost zero network calls.

## Configuration

Optional file at `~/.bashboy/config.toml` (override with `BASHBOY_CONFIG`).
Create it with `bashboy config init`; inspect with `bashboy config show`.
A missing file means these defaults:

```toml
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
```

Malformed TOML is a hard error (exit 2) from `check` — the gate never silently
loosens because a file failed to parse.

| Variable | Effect |
|----------|--------|
| `BASHBOY_CONFIG` | Path to the config file (default `~/.bashboy/config.toml`) |
| `BASHBOY_ENDPOINT` | Overrides `[provider].endpoint` |
| `BASHBOY_API_KEY_ENV` | Name of the environment variable holding the key |
| `BASHBOY_API_KEY_FILE` | Path to the credential file; overrides `[provider].api_key_file` |
| `BASHBOY_FAIL_MODE` | `closed` (default) or `open`; anything else is an error |
| `BASHBOY_DISABLE` | `1`/`true`/`yes` disables **all** checks (see below) |
| `BASHBOY_DEBUG` | `1`/`true`/`yes` writes diagnostics to stderr only |

## Claude Code setup

```bash
bashboy install --claude
```

This merges a `PreToolUse` hook into `~/.claude/settings.json` (override with
`--settings PATH`). Unrelated keys and unrelated hook events are preserved; an
existing BashBoy handler is updated in place, so re-running never duplicates it.
The previous file is copied to `settings.json.bak` and the new file is written
atomically.

The exact entry it writes:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Read",
        "hooks": [
          {
            "type": "command",
            "command": "uvx",
            "args": ["bashboy", "check", "--claude-hook"],
            "timeout": 15,
            "statusMessage": "BashBoy: checking command"
          }
        ]
      }
    ]
  }
}
```

Options:

```bash
bashboy install --claude --dry-run     # print the resulting JSON, write nothing
bashboy install --claude --settings ./settings.json
bashboy install --claude --from /path/to/BashBoy
```

`--from SPEC` rewrites the argv to
`["--from", SPEC, "bashboy", "check", "--claude-hook"]`, so `uvx` runs the given
local checkout. Use it only for a checkout or an unreleased build; a normal
published install needs no `--from`. The path is written verbatim as a single
argv element — never interpolated into a shell string.

The hook reads one JSON object on stdin. On `deny` it prints the
`hookSpecificOutput` envelope with `permissionDecision: "deny"`; on `allow`, blank
input, or malformed input it prints nothing and exits `0` so the host's normal
permission flow continues.

The same hook also covers the `Read` tool: a read of `.env`, `.env.local`, or any
`.env.*` file is denied, while templates (`.env.example`, `.env.sample`,
`.env.template`) are allowed.

## OpenCode setup

```bash
bashboy install --opencode
```

This writes two files under `~/.config/opencode` (override with `--config-dir DIR`):

- `plugins/bashboy.ts` — the generated plugin;
- `opencode.json` — registers the plugin's absolute path.

`opencode.json` is created with `{"$schema": "https://opencode.ai/config.json"}` if
absent. Existing keys and existing plugin entries are preserved, the BashBoy path
is appended only once, and the previous config is backed up before an atomic write.
OpenCode V2 documents the key as `plugins`; V1 used `plugin`. BashBoy reads
whichever key already exists, preserves it, defaults to `plugins` when neither is
present, and never writes both.

The plugin hooks both API generations with one shared helper:

- **V2:** `Plugin.define({ id: "bashboy", setup })` registering
  `ctx.tool.hook("execute.before", ...)`, reading `event.input.command`.
- **V1 fallback:** `server()` returning `"tool.execute.before"`, reading
  `output.args.command`.

It acts only for the `bash`/`shell` tools and runs
`uvx bashboy check --json --command <cmd> --cwd <dir>` via
`execFile(..., { shell: false, timeout: 15000, windowsHide: true })`. The command is
a single argv element; it is never passed through a shell and never concatenated
into a command line. On `deny` it throws
`Error("BashBoy blocked this command: <reason>")`. If `uvx` is missing, the exit is
non-zero without parseable JSON, the JSON is invalid, the call times out, or the
verdict is unexpected, it throws
`Error("BashBoy could not verify this command: <detail>")` — fail closed.

`bashboy install --opencode --dry-run` prints one JSON object with
`plugin_path`, `plugin_source`, and the would-be `config`, and writes nothing.

## Escape hatch

> **`BASHBOY_DISABLE=1` disables all checks.** Commands are allowed with
> `source: "disabled"` and no denylist, allowlist, or model evaluation runs.
> For emergencies and CI debugging only. Never set it in an agent's environment
> or in a shell that an agent controls.

```bash
BASHBOY_DISABLE=1 bashboy check --command "rm -rf /"   # allow (disabled)
```

## Privacy

For model classification, the **command text and the working directory** are sent
to the configured Clocked endpoint over HTTPS (`text: "cwd: <cwd>\ncommand: <cmd>"`).
Nothing else is transmitted; no files are uploaded.

Fast-path verdicts (`denylist`, `allowlist`, `disabled`) never leave the machine.
There is no analytics, no audit log, no cache, and no telemetry. The API key is
read at call time from the environment or the credential file, sent only as the
`Authorization` header, and never logged, persisted in `config.toml`, or included
in `config show`.

## Clocked envelope

The live envelope is verified (`clocked-1.0`): `verdict`, `risk`, and `reason` are
nested under `fields`, each with a `value`. Parsing is still deliberately tolerant
(`extract_field` walks nested objects and arrays breadth-first, and unwraps
`value`/`text`/`answer`/`label`/`result`/`content` containers). If the response
cannot be resolved to a clear `allow` or `deny`, the verdict is `deny` with
`source: "fallback"`. Report envelope mismatches with the raw (redacted) response
so the parser can be extended.

## Limitations

- The structural allowlist is conservative by design: any operator, substitution,
  redirection, or chaining disqualifies a command. False negatives go to the model
  when a key is configured; without one they produce no objection.
- The denylist is a fast path, not a complete policy. It catches literal destructive
  patterns and payloads hidden behind `;`, `&&`, `||`, `|`, newlines, `$(...)`, and
  backticks — but it does not decode base64, `r''m`-style quoting, or other
  obfuscation. Such commands are not allowlisted and therefore reach the model
  (which fails closed) or, without a key, produce no objection.
- **Local-only mode** (no key) is not a complete gate: unknown commands are not
  classified by BashBoy at all. Use `BASHBOY_REQUIRE_KEY=1` if you need a deny
  instead of handing the decision back to the host.
- Dotenv protection is command-position based: `cat .env`, `cp .env /tmp`, and
  `echo x > .env` are denied, while `git commit -m "fix .env handling"` is not.
  The Claude Code `Read` guard is path based. OpenCode's `read` tool is not gated.
- PowerShell/bash parity is best-effort. The allowlist covers a small bash-oriented
  set; PowerShell users should expect more commands to reach the model.
- `git reset --hard` is intentionally **not** denied: it is recoverable via the
  reflog. `git clean -fdx /` at a filesystem root is denied.
- `--from SPEC` is trusted input: a user who runs `install --from <path>` is
  explicitly pointing BashBoy at that checkout.
- v1 has no audit log; the host's own transcript remains the record.

## Development

```bash
uv run pytest          # offline; no network access required
uv run bashboy selftest
```

Layout:

```
src/bashboy/
  cli.py            check / install / config / auth / selftest / version
  config.py         TOML defaults, env overrides, API key resolution
  credentials.py    credential file read/write/clear + permission checks
  rules.py          structural allowlist + hard denylist (pure)
  provider.py       Clocked client, tolerant envelope parser
  classify.py       verdict pipeline (fast paths -> model -> fail closed)
  hooks/claude.py   Claude Code PreToolUse adapter
  installers/       Claude settings.json and OpenCode plugin installers
tests/              offline test suite
```

There are **no runtime dependencies beyond the standard library**. The provider is
imported lazily inside the model branch so the hook path stays fast, and the
installers are imported lazily by `install` only.
