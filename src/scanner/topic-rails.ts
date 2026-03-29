/**
 * SovGuard Topic/Policy Rails Scanner
 * Scans text against configurable denied topic definitions.
 * Works on both inbound and outbound text.
 */

export interface TopicRailsConfig {
  /** List of denied topic definitions */
  deniedTopics: DeniedTopic[];
}

export interface DeniedTopic {
  /** Topic name (e.g. "competitors", "legal-advice") */
  name: string;
  /** Keywords/phrases that indicate this topic. Case-insensitive matching. */
  keywords: string[];
  /** Optional: regex patterns for more complex matching */
  patterns?: RegExp[];
  /** Action to take: 'block' or 'flag' (default: 'flag') */
  action?: 'block' | 'flag';
}

export interface TopicMatch {
  topic: string;
  keyword: string;
  action: 'block' | 'flag';
}

// Module-level cache: maps a keyword string to its compiled word-boundary regex
const keywordRegexCache = new Map<string, RegExp>();

function getKeywordRegex(keyword: string): RegExp {
  const cached = keywordRegexCache.get(keyword);
  if (cached) return cached;
  // Escape special regex characters in the keyword, then wrap with \b word boundaries
  const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`\\b${escaped}\\b`, 'i');
  keywordRegexCache.set(keyword, re);
  return re;
}

/**
 * Scan text against denied topic rails.
 * Returns array of topic matches found.
 */
export function scanTopics(text: string, config: TopicRailsConfig): TopicMatch[] {
  const matches: TopicMatch[] = [];

  for (const topic of config.deniedTopics) {
    const action = topic.action ?? 'flag';

    // Check keywords with word-boundary matching
    for (const keyword of topic.keywords) {
      const re = getKeywordRegex(keyword);
      if (re.test(text)) {
        matches.push({ topic: topic.name, keyword, action });
        break; // one keyword match per topic is enough to register the topic
      }
    }

    // If keyword already matched this topic, skip pattern check to avoid duplicate
    const alreadyMatched = matches.some(m => m.topic === topic.name);
    if (alreadyMatched) continue;

    // Check regex patterns if provided
    if (topic.patterns) {
      for (const pattern of topic.patterns) {
        if (pattern.test(text)) {
          matches.push({ topic: topic.name, keyword: pattern.toString(), action });
          break;
        }
      }
    }
  }

  return matches;
}
