# BashBoy — Implementation Brief (locked decisions)

This brief is orchestrator-supplied context. Treat every decision here as locked unless it is
technically impossible. The planner turns this into `261021-hu8-PLAN.md`; the executor implements it.

## Product

`bashboy` is a Python CLI, installed/run with `uv` / `uvx`, that classifies a shell command as
**allow** or **deny** before the host agent executes it.

It has three layers:

1. **Local fast paths** (no network): hard denylist and hard allowlist.
2. **Model classification** (JEV API) for everything else.
3. **Host adapters**: Claude Code `PreToolUse` hook and OpenCode plugin.

BashBoy only ever *narrows* what may run. `allow` means "no objection" — the host's normal
permission flow still applies. It must never auto-approve a tool call.

## Locked decisions

| Area | Decision |
|------|----------|
| Runtime deps | None. Stdlib only (`urllib.request`, `json`, `tomllib`, `argparse`, `subprocess`). |
| Python | `requires-python = ">=3.10"` |
| Verdict | Binary: `allow` \| `deny`. No `ask`. |
| Failure | Fail **closed**: provider error, timeout, HTTP error, malformed response → `deny`. |
| Escape hatch | `BASHBOY_DISABLE=1` → allow, source `disabled`. Must be documented loudly. |
| Config | `~/.bashboy/config.toml` (override with `BASHBOY_CONFIG`). Created by `bashboy config init`. |
| Logging | stderr only, and only when `BASHBOY_DEBUG=1`. No audit log or cache in v1. |
| Allowlist scope | Only a **single simple command** with no operators, redirections, substitutions, or chaining. |
| Denylist scope | Applied to the raw command and to every `;`/`&&`/`||`/`|`/newline segment. |

## Layout

```
pyproject.toml
README.md
src/bashboy/__init__.py
src/bashboy/__main__.py
src/bashboy/cli.py
src/bashboy/config.py
src/bashboy/rules.py
src/bashboy/provider.py
src/bashboy/classify.py
src/bashboy/installers/__init__.py
src/bashboy/installers/claude.py
src/bashboy/installers/opencode.py
src/bashboy/hooks/__init__.py
src/bashboy/hooks/claude.py
tests/...
```

## CLI contract

```
bashboy check --command "<cmd>" [--cwd DIR] [--json] [--claude-hook]
bashboy install [--claude] [--opencode] [--all] [--dry-run] [--from SPEC]
bashboy config [path|show|init]
bashboy selftest
bashboy version
```

- `check` plain: exit `0` allow, `1` deny. Human line on stdout: `allow (allowlist): ...` / `deny (denylist): ...`.
- `check --json`: one JSON object on stdout, exit code still 0/1.
- `check --claude-hook`: read the Claude Code hook payload from stdin, exit `0` always.
  - deny → print `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"<reason>"}}`
  - allow → print nothing (normal permission flow continues).
  - Missing/blank `tool_input.command` → exit 0, no output.
- `selftest`: run fast-path assertions plus a provider round-trip when a key is configured;
  never require the network to exit 0 for the local checks.

Verdict JSON:

```json
{"decision":"deny","source":"denylist","reason":"recursive delete of /","risk":null,"latency_ms":0}
```

`source` ∈ `denylist` | `allowlist` | `model` | `fallback` | `disabled`.

## Config shape

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

Env overrides: `BASHBOY_CONFIG`, `BASHBOY_ENDPOINT`, `BASHBOY_API_KEY_ENV`, `BASHBOY_FAIL_MODE`,
`BASHBOY_DISABLE`, `BASHBOY_DEBUG`. Unknown/missing keys fall back to defaults; malformed TOML is a
clear error (exit 2) from `check`, never a silent allow.

## JEV provider contract (unverified envelope — be tolerant)

Request `POST <endpoint>`:

```json
{
  "text": "cwd: <cwd>\ncommand: <command>",
  "instructions": "<safety rubric>",
  "fields": {
    "verdict": {"type": "choice", "options": ["allow", "deny"], "description": "..."},
    "risk": {"type": "score", "levels": ["low", "medium", "high", "critical"], "description": "..."},
    "reason": {"type": "generate", "max_tokens": 80, "format": "text", "description": "..."}
  }
}
```

Headers: `Authorization: Bearer <key>`, `Content-Type: application/json`,
`Idempotency-Key: <uuid4>`. Timeout from config.

Rubric (in `instructions`): deny commands that delete or overwrite data outside the working tree,
escalate privileges destructively, format/partition disks, disable security controls, exfiltrate
secrets, or pipe unreviewed remote content into a shell. Allow ordinary build/test/git/read
operations and writes inside the working directory. Prefer `deny` when the command's effect cannot
be determined from the text.

Response parsing: the envelope is **unknown**. Implement `extract_field(payload, key)` that walks
nested dicts/lists and, for a matched key, unwraps common value containers (`value`, `text`,
`answer`, `label`, `result`, `content`). Verdict is normalized case-insensitively; anything other
than `allow`/`deny` is malformed → fallback deny. Add fixture-based tests for: flat object, nested
under `fields`, nested under `result.fields`, list-of-objects, and missing verdict.

Provider transport must be injectable so tests never touch the network.

## Fast-path rules

Allowlist (regex on the whole command, no shell metacharacters anywhere):
`ls`, `pwd`, `cd`, `cat`, `head`, `tail`, `wc`, `grep`, `rg`, `find`, `echo`, `which`, `whoami`,
`date`, `git status`, `git diff`, `git log`, `git show`, `git branch`, `uv --version`,
`python --version`, `node --version`.

Denylist (case-insensitive, must cover at least):
- `rm -rf /`, `rm -rf ~`, `rm -rf $HOME`, `rm -rf *` at root
- `mkfs`, `fdisk`, `parted`, `diskpart`, `format c:`
- `dd ... of=/dev/...`, `> /dev/sd*`, `shred /dev/*`
- fork bomb `:(){ :|:& };:`
- `chmod -R 777 /`, `chown -R ... /`
- `shutdown`, `reboot`, `halt`, `poweroff`
- `Remove-Item -Recurse` against a drive root
- `git clean -fdx /`, `git reset --hard` is allowed (recoverable via reflog) — do not deny

The denylist must catch payloads hidden in compound commands: `ls; rm -rf /`, `echo $(rm -rf /)`,
`true && mkfs.ext4 /dev/sda`.

## Claude Code integration

`bashboy install --claude` merges into `~/.claude/settings.json` (override `--settings PATH`):

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

- `--from SPEC` swaps `["bashboy", ...]` for `["--from", SPEC, "bashboy", ...]` so a local checkout
  can be installed with `uvx --from /path/to/BashBoy`.
- Preserve every unrelated key; back up to `settings.json.bak`; atomic write; idempotent (no
  duplicate handler on re-run); `--dry-run` prints the resulting JSON without writing.

## OpenCode integration

V2 API (from the official docs):

```ts
import { Plugin } from "@opencode/plugin"

export default {
  ...Plugin.define({
    id: "bashboy",
    async setup(ctx) {
      await ctx.tool.hook("execute.before", async (event) => { /* ... */ })
    },
  }),
  async server() { return { "tool.execute.before": async (input, output) => { /* ... */ } } },
}
```

- `bashboy install --opencode` writes `~/.config/opencode/plugins/bashboy.ts` and adds the plugin
  path to `plugins` in `~/.config/opencode/opencode.json` (create the file with `$schema` if absent,
  preserve existing entries, idempotent, backup, atomic write).
- Plugin reads `event.input.command` for the `bash`/`shell` tool, runs
  `uvx bashboy check --json --command <cmd> --cwd <dir>`, parses JSON, and throws
  `new Error("BashBoy blocked this command: " + reason)` on deny. Allow → return.
- Handle: uvx not found, non-zero exit without JSON, invalid JSON, timeout → throw (fail closed).
- The V1 `server()` fallback uses the same helper.
- Windows: use `execFile("uvx", [...])`, `shell: false`.

## Testing

`uv run pytest` must pass offline. Required coverage:

1. Rule tests: every denylist pattern; allowlist positives; compound-injection cases.
2. Classifier tests: denylist short-circuits (provider never called), allowlist short-circuits,
   model path, fail-closed on exception/timeout/malformed, `BASHBOY_DISABLE`.
3. Provider parsing fixtures (five envelopes above) + request body/headers assertions with a fake
   transport.
4. Claude hook adapter: deny payload, allow (empty stdout), blank command, malformed stdin.
5. Installer tests against a temp `HOME`: fresh file, merge+preserve, idempotent re-run, dry-run.

## Acceptance

- `uv run bashboy check --command "rm -rf /" --json` → `decision=deny`, `source=denylist`, <100 ms.
- `uv run bashboy check --command "git status" --json` → `decision=allow`, `source=allowlist`.
- `uv run bashboy check --command "docker run --rm alpine sh"` with no API key → deny, `source=fallback`.
- `bashboy install --claude --dry-run` prints a valid settings object.
- README documents: install, env var, config, Claude Code setup, OpenCode setup, escape hatch,
  privacy (command + cwd leave the machine), and the known unverified JEV envelope.

## Constraints

- 1–3 tasks, atomic commits, no network in tests.
- Do not add dependencies. Do not add a web UI. Do not auto-approve.
- Keep the hook path fast: no imports that cost >50 ms at startup; lazy-import the provider.
