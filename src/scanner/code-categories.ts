/**
 * Job categories whose messages legitimately contain code, and the inbound regex
 * labels that are pure code-content constructs (NOT prompt-injection phrasing).
 *
 * For a job in CODE_CATEGORIES, the inbound scan drops ONLY the CODE_CONTENT_LABELS
 * matches from the regex layer, so a code-review agent (and the code it is asked to
 * review) is not scored as instruction_override and hard-blocked. Every injection /
 * exfiltration / weapon pattern is NOT in CODE_CONTENT_LABELS and stays fully active
 * for code jobs (ignore_previous, reveal_prompt, curl_exfil, …). Shared so the inbound
 * gate (scanner/index.ts) and the outbound gate (outbound/code.ts) cannot drift.
 */
export const CODE_CATEGORIES = new Set<string>([
  'code-review', 'development', 'web-development', 'software',
  'programming', 'devops', 'data-science',
]);

export const CODE_CONTENT_LABELS = new Set<string>([
  'eval_call', 'subprocess', 'os_system', 'tool_command_injection',
]);
