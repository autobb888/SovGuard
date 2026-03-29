/**
 * Outbound Toxicity Scanner
 * Detects hate speech, threats, self-harm, sexual content, and harassment
 * in agent responses before delivery to buyers.
 */

import type { OutputFlag } from '../types.js';

// ─── Hate Speech / Slurs ─────────────────────────────────────────────────────
// Word boundary matching to avoid false positives (e.g. "grape", "class", "assassin")
const HATE_SPEECH_PATTERNS: RegExp[] = [
  // Racial / ethnic slurs — pattern list kept clinical; words intentionally abbreviated
  /\bn[i!1][gq][gq][ae3][rh]s?\b/i,
  /\bsp[i!1]c[ks]?\b(?!\s+and\s+span)/i,
  /\bch[i!1]nk[s]?\b/i,
  /\bgook[s]?\b/i,
  /\bw[e3]tb[a@]ck[s]?\b/i,
  /\bk[i!1]k[e3][s]?\b/i,
  /\bcr[a@][ck]k[e3]r[s]?\b(?!\s+(?:jack|barrel|and\s+cheese))/i,
  /\bz[i!1][p!1][e3]rh[e3][a@]d[s]?\b/i,
  /\bs[l1][a@]nt[- ]?[e3]y[e3][ds]?\b/i,
  /\bj[a@]p[s]?\b(?!an)/i,          // "jap" but not "japan"
  /\bboon[e3][rs]?\b(?! dock)/i,     // slur but not "booner dock"
  // Homophobic slurs
  /\bf[a@][gq][gq][o0]?[ts]?\b/i,
  /\bd[y!1]k[e3][s]?\b(?! road| street| lane| avenue)/i,
  /\bp[o0][o0]ft[e3]r[s]?\b/i,
  // Gendered slurs
  /\bc[u!1]nt[s]?\b/i,
  /\bsl[u!1]t[s]?\b/i,
  /\bwh[o0]r[e3][s]?\b/i,
  // Disability slurs
  /\br[e3]t[a@]rd[e3]d?\b/i,
];

// ─── Threats / Violence ───────────────────────────────────────────────────────
const THREAT_PATTERNS: RegExp[] = [
  /\bi(?:'?ll| will| am going to| plan to| intend to)\s+(?:kill|murder|shoot|stab|beat|strangle|behead|execute|slaughter|dismember)\s+(?:you|him|her|them|u|your family|your kids|everyone)\b/i,
  /\bi(?:'?ll| will| am going to)\s+(?:hurt|harm|attack|destroy|end)\s+(?:you|him|her|them|u|your family)\b/i,
  /\b(?:you(?:'re| are)|ur)\s+(?:dead|going to die|a dead man|a dead woman|gonna die)\b/i,
  /\b(?:watch your back|dead meat|you won'?t survive|i'?ll find you|i know where you live)\b/i,
  /\bdeath\s+threat[s]?\b/i,
  /\b(?:gonna|going to)\s+(?:kill|murder|shoot)\s+(?:you|him|her|them|u)\b/i,
  /\b(?:i(?:'ll)?|we(?:'ll)?)\s+(?:blow up|bomb|torch|burn down)\s+(?:your|the|a)\b/i,
  /\bslit\s+(?:your|his|her|their)\s+(?:throat|wrists)\b/i,
];

// ─── Self-Harm ────────────────────────────────────────────────────────────────
// These patterns target *instructional / encouragement* language, not clinical mentions.
const SELF_HARM_PATTERNS: RegExp[] = [
  // Instructional / how-to framing for suicide methods
  /\b(?:how\s+to|steps?\s+to|ways?\s+to|instructions?\s+(?:for|to))\s+(?:kill\s+yourself|commit\s+suicide|end\s+your\s+life|hang\s+yourself|overdose)\b/i,
  // Direct encouragement
  /\b(?:you\s+should|just|go\s+and)\s+(?:kill\s+yourself|kys|end\s+it|end\s+your\s+life|commit\s+suicide|hang\s+yourself|slit\s+your\s+wrists|overdose)\b/i,
  /\b(?:just|go)\s+kys\b/i,
  /\b(?:cut\s+yourself|self[- ]?harm\s+(?:guide|tutorial|instructions?|steps?|method))\b/i,
  /\bencourag(?:e|ing)\s+(?:self[- ]?harm|suicide|cutting)\b/i,
  /\bmethod[s]?\s+(?:for|to)\s+(?:suicide|self[- ]?harm|hanging|overdos)\b/i,
  /\b(?:best|easiest|quickest|most\s+effective)\s+(?:way|method|approach)\s+to\s+(?:kill\s+yourself|commit\s+suicide|die)\b/i,
];

// ─── Sexual Content ───────────────────────────────────────────────────────────
const SEXUAL_CONTENT_PATTERNS: RegExp[] = [
  /\b(?:suck(?:ing)?|blow(?:ing)?)\s+(?:my|his|her|their|your)\s+(?:cock|dick|penis)\b/i,
  /\b(?:fuck(?:ing)?|shag(?:ging)?|screw(?:ing)?|bang(?:ing)?)\s+(?:you|him|her|them|me)\b/i,
  /\b(?:explicit\s+sexual|graphic\s+sex(?:ual)?|hardcore\s+porn(?:ography)?)\b/i,
  /\b(?:cum\s+shot|creampie|gangbang|bukk?ake)\b/i,
  /\bsend\s+(?:me\s+)?(?:your\s+)?(?:nudes?|naked\s+pics?|explicit\s+photos?)\b/i,
  /\bsex(?:ual)?\s+(?:solicitation|proposition|for\s+hire|in\s+exchange\s+for)\b/i,
  /\b(?:i\s+want\s+to|let(?:'s)?\s+|let\s+me)\s+(?:fuck|shag|bang|screw|penetrate)\s+(?:you|him|her|u)\b/i,
  /\bp[o0]rn(?:ography)?\s+(?:video|clip|content|material)\b/i,
];

// ─── Harassment / Bullying ────────────────────────────────────────────────────
const HARASSMENT_PATTERNS: RegExp[] = [
  // Doxxing language
  /\b(?:i'?(?:ve|ll)|we'?(?:ve|ll))\s+(?:found|posted?|published?|leaked?|shared?)\s+(?:your|his|her|their)\s+(?:address|home address|phone number|personal info|real name|location|IP address)\b/i,
  /\b(?:dox(?:x)?(?:ing|ed)?|posting\s+(?:their|your|his|her)\s+(?:address|info|details))\b/i,
  // Stalking language
  /\b(?:i(?:'m|\s+am)\s+(?:watching|following|tracking|monitoring)\s+(?:you|your))\b/i,
  /\b(?:i\s+know\s+where\s+you\s+(?:live|work|go|are|sleep))\b/i,
  /\b(?:i(?:'ll|\s+will)\s+(?:find|track|follow)\s+(?:you|him|her|them))\b/i,
  // Targeted insults
  /\b(?:you(?:'re|\s+are)\s+(?:a\s+)?(?:worthless|pathetic|disgusting|subhuman|garbage|vermin|piece\s+of\s+shit|waste\s+of\s+(?:space|oxygen|life)))\b/i,
  /\b(?:nobody\s+(?:loves|likes|cares\s+about)\s+you|everyone\s+hates\s+you|go\s+(?:kill\s+yourself|die|away\s+forever))\b/i,
  /\b(?:i(?:'ll|\s+will)\s+(?:ruin|destroy|end)\s+(?:your|his|her|their)\s+(?:life|career|reputation))\b/i,
];

interface ToxicityCategory {
  name: string;
  patterns: RegExp[];
  severity: 'high' | 'medium';
  action: 'block' | 'flag';
}

const CATEGORIES: ToxicityCategory[] = [
  {
    name: 'hate_speech',
    patterns: HATE_SPEECH_PATTERNS,
    severity: 'high',
    action: 'block',
  },
  {
    name: 'threats_violence',
    patterns: THREAT_PATTERNS,
    severity: 'high',
    action: 'block',
  },
  {
    name: 'self_harm',
    patterns: SELF_HARM_PATTERNS,
    severity: 'high',
    action: 'block',
  },
  {
    name: 'sexual_content',
    patterns: SEXUAL_CONTENT_PATTERNS,
    severity: 'medium',
    action: 'flag',
  },
  {
    name: 'harassment_bullying',
    patterns: HARASSMENT_PATTERNS,
    severity: 'medium',
    action: 'flag',
  },
];

export function scanToxicity(text: string): OutputFlag[] {
  const flags: OutputFlag[] = [];

  for (const category of CATEGORIES) {
    for (const pattern of category.patterns) {
      // Create a fresh regex each iteration to reset lastIndex
      const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        flags.push({
          type: 'toxicity',
          severity: category.severity,
          detail: category.name,
          evidence: m[0],
          action: category.action,
        });
        // Only flag the first match per pattern to avoid flooding
        break;
      }
    }
  }

  return flags;
}
