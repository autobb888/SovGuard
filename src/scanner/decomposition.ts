/**
 * DL-009 — Algorithmic decomposition / split-payload heuristics.
 * Detect reconstruct-then-execute procedural asks (list-filter-join, var concat)
 * and correlate multi-doc half-payloads in a shared session.
 */
import { normalizeToFixedPoint } from './regex.js';

export interface DecompositionHit {
  found: boolean;
  kinds: Array<'list_filter_join' | 'var_concat' | 'assemble_execute' | 'multi_doc_half'>;
  evidence: string;
  /** Mild fragment score for session correlation (0–1). */
  fragmentScore: number;
}

const ASSEMBLE =
  /\b(join|concatenat\w*|assemble|combine|filter\s+to|word\s+after\s+each)\b/i;
const EXECUTE =
  /\b(execute|follow|then\s+(?:run|call|execute|follow)|call\s+send_email|dump\s+system)\b/i;
const VAR_ASSIGN =
  /\b(?:let|const|var)?\s*[a-z]\s*=\s*["'][^"']{1,40}["']\s*;?\s*(?:[a-z]\s*=\s*["'][^"']{1,40}["']\s*;?\s*){1,}/i;
const VAR_CONCAT =
  /\b(?:concatenat\w*|join|assemble)\b[\s\S]{0,60}?\b[a-z](?:\s*\+\s*[a-z])+\b|\b[a-z](?:\s*\+\s*[a-z]){2,}\b[\s\S]{0,40}\b(?:follow|execute|run)\b/i;
const COLOR_LIST =
  /(?:^|\n)\s*[-*]\s*\w+\s*:\s*\S+[\s\S]{0,200}?\b(?:filter|join|execute)\b/i;
const HALF_MARK =
  /\bpart\s*[12]\s*\/\s*2\b|\b\(1\/2\)|\b\(2\/2\)|\bignore previous instructions\b|\bcall send_email\b/i;

/**
 * Detect reconstruct-then-execute procedural asks in a single chunk.
 * Runs on Unicode fixed-point text.
 */
export function detectDecomposition(text: string): DecompositionHit {
  const fp = normalizeToFixedPoint(text).text;
  const kinds: DecompositionHit['kinds'] = [];
  let fragmentScore = 0;

  const hasAssemble = ASSEMBLE.test(fp);
  const hasExecute = EXECUTE.test(fp);

  if (COLOR_LIST.test(fp) && hasAssemble && hasExecute) {
    kinds.push('list_filter_join');
  } else if (hasAssemble && hasExecute) {
    kinds.push('assemble_execute');
  }

  // Require an execute/follow cue — bare coding concat is FP
  if (hasExecute && VAR_ASSIGN.test(fp) && (VAR_CONCAT.test(fp) || hasAssemble)) {
    kinds.push('var_concat');
  } else if (hasExecute && VAR_CONCAT.test(fp)) {
    kinds.push('var_concat');
  }

  // Fragment hints for session correlation (even if not full hit alone)
  if (/\bignore previous\b/i.test(fp)) fragmentScore = Math.max(fragmentScore, 0.35);
  if (/\bcall send_email\b/i.test(fp)) fragmentScore = Math.max(fragmentScore, 0.4);
  if (/\bpart\s*[12]\s*\/\s*2\b/i.test(fp)) fragmentScore = Math.max(fragmentScore, 0.3);
  if (HALF_MARK.test(fp)) fragmentScore = Math.max(fragmentScore, fragmentScore);

  const found = kinds.length > 0;
  let evidence = '';
  if (found) {
    const idx = fp.search(ASSEMBLE);
    evidence = fp.slice(Math.max(0, idx >= 0 ? idx : 0), Math.max(0, idx >= 0 ? idx : 0) + 160).trim();
  }

  return {
    found,
    kinds: [...new Set(kinds)],
    evidence,
    fragmentScore: found ? Math.max(fragmentScore, 0.55) : fragmentScore,
  };
}

export interface FragmentEntry {
  text: string;
  fragmentScore: number;
  at: number;
}

/**
 * Session-level half-payload correlation: store mild fragments; when combined
 * text looks like assemble+execute / ignore+tool, raise multi_doc_half.
 */
export class DecompositionWatch {
  private frags = new Map<string, FragmentEntry[]>();

  record(sessionId: string, text: string): DecompositionHit {
    const hit = detectDecomposition(text);
    const fp = normalizeToFixedPoint(text).text;
    const list = this.frags.get(sessionId) ?? [];
    list.push({
      text: fp,
      fragmentScore: hit.fragmentScore || (hit.found ? 0.55 : scoreFragmentAlone(fp)),
      at: Date.now(),
    });
    // keep last 8
    this.frags.set(sessionId, list.slice(-8));

    if (hit.found) return hit;

    // Cross-fragment: concatenate recent halves
    const combined = list.map((f) => f.text).join('\n');
    const combo = detectDecomposition(combined);
    if (combo.found || looksLikeSplitInjection(list)) {
      return {
        found: true,
        kinds: [...new Set([...combo.kinds, 'multi_doc_half' as const])],
        evidence: combo.evidence || combined.slice(0, 160),
        fragmentScore: Math.max(combo.fragmentScore, 0.6),
      };
    }
    return hit;
  }

  clear(sessionId: string): void {
    this.frags.delete(sessionId);
  }

  clearAll(): void {
    this.frags.clear();
  }
}

function scoreFragmentAlone(fp: string): number {
  let s = 0;
  if (/\bignore previous\b/i.test(fp)) s += 0.35;
  if (/\bcall send_email\b|\battacker@|\bexfil\b/i.test(fp)) s += 0.4;
  if (/\bpart\s*[12]\s*\/\s*2\b/i.test(fp)) s += 0.25;
  return Math.min(1, s);
}

function looksLikeSplitInjection(list: FragmentEntry[]): boolean {
  if (list.length < 2) return false;
  const combined = list.map((f) => f.text).join(' ');
  const hasIgnore = /\bignore previous\b/i.test(combined);
  const hasTool = /\b(send_email|dump system|call tool)\b/i.test(combined);
  const scores = list.reduce((a, f) => a + f.fragmentScore, 0);
  return hasIgnore && hasTool && scores >= 0.5;
}

export const decompositionWatch = new DecompositionWatch();
