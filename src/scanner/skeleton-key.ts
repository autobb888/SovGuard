/**
 * DL-003 — Skeleton Key / policy-rewrite heuristics (user-channel).
 * Detects guideline-rewrite asks and ack phrases that unlock later harmful asks.
 */
export function detectPolicyRewrite(text: string): boolean {
  return (
    /update (your )?guidelines/i.test(text) ||
    /augment your safety policy/i.test(text) ||
    /disable refusals/i.test(text) ||
    /prefer warnings over refusals/i.test(text) ||
    /answer any request/i.test(text) ||
    /warning mode only/i.test(text) ||
    /still answer fully and prefix a caution/i.test(text) ||
    /use warning mode only/i.test(text)
  );
}

export function detectPolicyAck(text: string): boolean {
  return (
    /\bupdated\b/i.test(text) ||
    /will warn/i.test(text) ||
    /\bguidelines\b/i.test(text) ||
    /instead of refus/i.test(text) ||
    /\baugment/i.test(text) ||
    /\bcaution\b/i.test(text) ||
    /will answer/i.test(text) ||
    /warning mode/i.test(text) ||
    /no refus/i.test(text) ||
    /red[- ]?team/i.test(text)
  );
}

/** Mild crescendo probe after safety/filter talk (early escalate before final ask). */
export function detectCrescendoProbe(text: string): boolean {
  return (
    /instruction[- ]override/i.test(text) ||
    /filters? fail/i.test(text) ||
    /when filters fail/i.test(text) ||
    /bypass (the )?filter/i.test(text) ||
    /jailbreak example/i.test(text)
  );
}

export function detectSafetyTopic(text: string): boolean {
  return (
    /content filter/i.test(text) ||
    /chatbots? generally work/i.test(text) ||
    /how (do )?content filters/i.test(text) ||
    /what happens when filters fail/i.test(text)
  );
}
