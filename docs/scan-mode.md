# ScanMode router (DL-011c Option C)

Product modes route scrub / delivery posture without changing DeBERTa weights.

| Mode | How selected | Scrub | Notes |
|---|---|---|---|
| `user_chat` | default; `source:user`; or explicit | off | FP-safe chat path; CLF_ESCALATE not enabled by this land |
| `untrusted_content` | `source:email\|file\|web\|mcp_result\|…` or explicit | on | ActionGuard remains strict (DL-004) |
| `security_research` | **explicit only** (never inferred) | on if `source≠user` | Response `meta.advisory: true`; scores/flags unchanged in v1 |

## Request

```json
{ "text": "...", "source": "email", "mode": "untrusted_content" }
```

- `mode` optional on `/v1/scan` and `/v1/wrap`
- Explicit `mode` wins over `source`
- `security_research` must be explicit

## Response

Enforcement annotation still uses top-level `mode: "enforce"|"monitor"`.
Resolved ScanMode is echoed under **`meta`** to avoid collision:

```json
{
  "meta": {
    "mode": "user_chat",
    "modeSource": "default"
  }
}
```

`modeSource` is `explicit` | `inferred_from_source` | `default`.

## Claims

High catch claims apply to **untrusted_content** pipelines; chat FP targets apply to **user_chat**.
Do not quote deepset catch % as the chat default.
