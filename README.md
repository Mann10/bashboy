# BashBoy

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
   commands, and a hard denylist for destructive ones.
2. **Model classification** against the Clocked (`clocked/fill`) endpoint for everything
   else.
3. **Host adapters** that express denial only.

Anything the fast paths do not recognise goes to the model. Anything the model path
cannot answer clearly becomes `deny`.

## Install

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
uv tool install bashboy     # install once
uvx bashboy --help          # or run without installing
```

From a local checkout (uvx resolves the project from the path):

```bash
uvx --from /path/to/BashBoy bashboy check --command "git status"
uvx --from /path/to/BashBoy bashboy install --claude
```

The package has **zero runtime dependencies** — everything is the Python standard
library. `pytest` is a development-only dependency.

The API key is read from the environment (default `CLOCKED_API_KEY`). It is never
written to disk:

```bash
export CLOCKED_API_KEY=...        # bash
$env:CLOCKED_API_KEY = "..."      # PowerShell
```

## Quick start

```bash
bashboy check --command "rm -rf /"
# deny (denylist): recursive delete of a protected path

bashboy check --command "git status"
# allow (allowlist): matches allowlist: git status

bashboy check --command "docker run --rm alpine sh" --json
# {"decision": "deny", "source": "fallback", "reason": "classifier unavailable: no API key ...", ...}
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

`source` is one of `denylist`, `allowlist`, `model`, `fallback`, `disabled`.
`--cwd DIR` supplies the working directory used for context (default: current
directory).

## Configuration

Optional file at `~/.bashboy/config.toml` (override with `BASHBOY_CONFIG`).
Create it with `bashboy config init`; inspect with `bashboy config show`.
A missing file means these defaults:

```toml
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
```

Malformed TOML is a hard error (exit 2) from `check` — the gate never silently
loosens because a file failed to parse.

| Variable | Effect |
|----------|--------|
| `BASHBOY_CONFIG` | Path to the config file (default `~/.bashboy/config.toml`) |
| `BASHBOY_ENDPOINT` | Overrides `[provider].endpoint` |
| `BASHBOY_API_KEY_ENV` | Name of the environment variable holding the key |
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
        "matcher": "Bash|PowerShell",
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
local checkout. The path is written verbatim as a single argv element — never
interpolated into a shell string.

The hook reads one JSON object on stdin. On `deny` it prints the
`hookSpecificOutput` envelope with `permissionDecision: "deny"`; on `allow`, blank
input, or malformed input it prints nothing and exits `0` so the host's normal
permission flow continues.

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
read from the environment at call time, sent only as the `Authorization` header,
and never logged, persisted, or included in `config show`.

## Known limitation: unverified Clocked envelope

The response shape of the Clocked (`clocked/fill`) endpoint is **unverified**. Parsing
is deliberately tolerant (`extract_field` walks nested objects and arrays
breadth-first, and unwraps `value`/`text`/`answer`/`label`/`result`/`content`
containers). If the response cannot be resolved to a clear `allow` or `deny`, the
verdict is `deny` with `source: "fallback"`. Report envelope mismatches with the
raw (redacted) response so the parser can be extended.

## Limitations

- The structural allowlist is conservative by design: any operator, substitution,
  redirection, or chaining disqualifies a command. False negatives simply go to the
  model.
- The denylist is a fast path, not a complete policy. It catches literal destructive
  patterns and payloads hidden behind `;`, `&&`, `||`, `|`, newlines, `$(...)`, and
  backticks — but it does not decode base64, `r''m`-style quoting, or other
  obfuscation. Such commands are not allowlisted and therefore reach the model,
  which fails closed.
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
  cli.py            check / install / config / selftest / version
  config.py         TOML defaults, env overrides, API key lookup
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
