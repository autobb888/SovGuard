/**
 * DL-003 — Skeleton Key / policy-rewrite heuristics (user-channel).
 * Tightened after RA BLOCK: no soft overlap between safety-topic and crescendo
 * probes; rewrite/ack require safety-policy intent (not bare "updated"/"guidelines").
 */
export function detectPolicyRewrite(text: string): boolean {
  if (
    /augment your safety policy/i.test(text) ||
    /disable refusals/i.test(text) ||
    /prefer warnings over refusals/i.test(text) ||
    /warning mode only/i.test(text) ||
    /use warning mode only/i.test(text) ||
    /still answer fully and prefix a caution/i.test(text)
  ) {
    return true;
  }
  // "update guidelines" only with refusal/warning/answer-any safety intent
  if (/update (your )?guidelines/i.test(text)) {
    return /answer any request|refus|warning|safety policy|warn instead/i.test(text);
  }
  return false;
}

export function detectPolicyAck(text: string): boolean {
  return (
    /will warn(ing)?( instead of refuse)?/i.test(text) ||
    /instead of refus/i.test(text) ||
    /warning mode/i.test(text) ||
    /no refus/i.test(text) ||
    /guidelines (updated|changed)|updated (my |the )?guidelines/i.test(text) ||
    /will answer.+(caution|warn)/i.test(text) ||
    /i will warn instead of refuse/i.test(text)
  );
}

/** Crescendo probe AFTER a prior safety/filter turn. Excludes "filters fail". */
export function detectCrescendoProbe(text: string): boolean {
  return (
    /instruction[- ]override/i.test(text) ||
    /bypass (the )?filter/i.test(text) ||
    /jailbreak example/i.test(text)
  );
}

export function detectSafetyTopic(text: string): boolean {
  return (
    /content filter/i.test(text) ||
    /chatbots? generally work/i.test(text) ||
    /how (do )?content filters/i.test(text) ||
    /what happens when filters fail/i.test(text) ||
    /when filters fail/i.test(text) ||
    /filters? fail/i.test(text)
  );
}
