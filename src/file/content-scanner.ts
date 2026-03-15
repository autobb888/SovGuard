/**
 * File Content Scanner (GAP-5)
 *
 * Extracts text from file content and runs it through the SovGuard scan pipeline.
 * Catches injections hidden in document body text that filename/metadata scanning misses.
 *
 * Supported formats:
 * - Plain text (.txt, .md, .csv, .json, .xml, .yaml, .css, .js) — direct scan
 * - HTML — extracts visible text + detects hidden text attacks (display:none, font-size:0, etc.)
 * - SVG — extracts text/desc/title elements, detects script/foreignObject injection
 * - PDF — basic text extraction (no OCR) + hidden text detection
 *
 * Convention: 0 = safe, 1 = dangerous.
 */

import type { LayerResult } from '../types.js';
import { regexScan } from '../scanner/regex.js';

export interface ContentScanResult {
  safe: boolean;
  score: number;
  flags: string[];
  /** Number of text chunks scanned */
  chunksScanned: number;
  /** Extracted text length (chars) */
  extractedLength: number;
  details: {
    /** Per-chunk scan results */
    chunkResults: Array<{ offset: number; score: number; flags: string[] }>;
  };
}

export interface ContentScanOptions {
  /** Max text to extract in bytes. Default: 100KB */
  maxExtractBytes?: number;
  /** Chunk size for scanning. Default: 4KB */
  chunkSize?: number;
  /** Score threshold to flag. Default: 0 (any match) */
  flagThreshold?: number;
}

const DEFAULT_MAX_EXTRACT = 100 * 1024; // 100KB
const DEFAULT_CHUNK_SIZE = 4 * 1024; // 4KB

/**
 * Extract text from a file buffer based on MIME type, then scan for injections.
 */
export function scanFileContent(
  buffer: Buffer,
  mimeType: string,
  options?: ContentScanOptions,
): ContentScanResult {
  // Input validation
  if (!Buffer.isBuffer(buffer)) {
    return { safe: true, score: 0, flags: [], chunksScanned: 0, extractedLength: 0, details: { chunkResults: [] } };
  }
  const maxExtract = Math.max(1, Math.min(options?.maxExtractBytes ?? DEFAULT_MAX_EXTRACT, 10 * 1024 * 1024));

  // Extract text based on type
  let text: string;
  try {
    text = extractText(buffer, mimeType, maxExtract);
  } catch {
    // Can't extract — not scannable, treat as safe
    return {
      safe: true,
      score: 0,
      flags: [],
      chunksScanned: 0,
      extractedLength: 0,
      details: { chunkResults: [] },
    };
  }

  if (!text || text.trim().length === 0) {
    return {
      safe: true,
      score: 0,
      flags: [],
      chunksScanned: 0,
      extractedLength: 0,
      details: { chunkResults: [] },
    };
  }

  // Scan the extracted text in chunks (large files)
  const result = scanText(text, options);

  // Add structural flags for hidden text and SVG dangers
  const structuralFlags: string[] = [];
  if (text.includes('[HIDDEN]')) {
    structuralFlags.push('content:hidden_text_detected');
  }
  if (text.includes('[SVG_SCRIPT]')) {
    structuralFlags.push('content:svg_script_element');
  }
  if (text.includes('[SVG_FOREIGN_OBJECT]')) {
    structuralFlags.push('content:svg_foreign_object');
  }
  if (text.includes('[SVG_EVENT_HANDLER]')) {
    structuralFlags.push('content:svg_event_handler');
  }

  if (structuralFlags.length > 0) {
    for (const f of structuralFlags) {
      if (!result.flags.includes(f)) result.flags.push(f);
    }
    result.safe = false;
    result.score = Math.max(result.score, 0.6);
  }

  return result;
}

/**
 * Scan raw text content for injection patterns.
 * Useful when you already have the text (e.g., from a text field).
 */
export function scanText(
  text: string,
  options?: ContentScanOptions,
): ContentScanResult {
  const chunkSize = options?.chunkSize ?? DEFAULT_CHUNK_SIZE;
  const maxExtract = options?.maxExtractBytes ?? DEFAULT_MAX_EXTRACT;

  // Truncate if needed
  const truncated = text.slice(0, maxExtract);

  const chunkResults: Array<{ offset: number; score: number; flags: string[] }> = [];
  let maxScore = 0;
  const allFlags: string[] = [];

  // Scan in chunks to localize injection position
  for (let offset = 0; offset < truncated.length; offset += chunkSize) {
    const chunk = truncated.slice(offset, offset + chunkSize);
    const result = regexScan(chunk);
    if (result.score > 0) {
      const chunkFlags = result.flags.map(f => `content:${f}`);
      chunkResults.push({ offset, score: result.score, flags: chunkFlags });
      allFlags.push(...chunkFlags);
      maxScore = Math.max(maxScore, result.score);
    }
  }

  // Also scan the full text (catches patterns spanning chunk boundaries)
  const fullResult = regexScan(truncated);
  if (fullResult.score > maxScore) {
    maxScore = fullResult.score;
    const fullFlags = fullResult.flags.map(f => `content:${f}`);
    for (const f of fullFlags) {
      if (!allFlags.includes(f)) allFlags.push(f);
    }
  }

  return {
    safe: allFlags.length === 0,
    score: maxScore,
    flags: [...new Set(allFlags)],
    chunksScanned: Math.ceil(truncated.length / chunkSize),
    extractedLength: truncated.length,
    details: { chunkResults },
  };
}

/**
 * Extract readable text from a file buffer.
 */
function extractText(buffer: Buffer, mimeType: string, maxBytes: number): string {
  switch (mimeType) {
    case 'text/plain':
    case 'text/markdown':
    case 'text/csv':
    case 'application/json':
    case 'application/xml':
    case 'text/xml':
    case 'text/yaml':
    case 'application/x-yaml':
    case 'text/css':
    case 'application/javascript':
    case 'text/javascript':
      return buffer.subarray(0, maxBytes).toString('utf-8');

    case 'text/html':
      return extractHtmlText(buffer.subarray(0, maxBytes).toString('utf-8'));

    case 'image/svg+xml':
      return extractSvgText(buffer.subarray(0, maxBytes).toString('utf-8'));

    case 'application/pdf':
      return extractPdfText(buffer, maxBytes);

    default:
      return '';
  }
}

/**
 * Basic PDF text extraction.
 * Extracts text from PDF stream objects without external dependencies.
 * Not comprehensive (no CMap, no font decoding) but catches injections in plain-text PDF content.
 */
function extractPdfText(buffer: Buffer, maxBytes: number): string {
  // Slice buffer before regex to prevent ReDoS on oversized PDFs
  const text = buffer.subarray(0, maxBytes * 4).toString('latin1');
  const chunks: string[] = [];
  let totalLen = 0;

  // Extract text between BT (begin text) and ET (end text) markers (bounded to 64KB per match)
  const btEtRegex = /BT\s([\s\S]{0,65536}?)ET/g;
  let match;
  while ((match = btEtRegex.exec(text)) !== null && totalLen < maxBytes) {
    const block = match[1];
    // Extract text from Tj, TJ, and ' operators (bounded quantifiers to prevent ReDoS)
    const tjRegex = /\(([^)]{0,4096})\)\s*Tj/g;
    let tj;
    while ((tj = tjRegex.exec(block)) !== null && totalLen < maxBytes) {
      chunks.push(tj[1]);
      totalLen += tj[1].length;
    }
    // TJ array: [(text) kern (text) kern ...] (bounded to 8KB per array)
    const tjArrayRegex = /\[([^\]]{0,8192})\]\s*TJ/g;
    let tja;
    while ((tja = tjArrayRegex.exec(block)) !== null && totalLen < maxBytes) {
      const innerRegex = /\(([^)]{0,4096})\)/g;
      let inner;
      while ((inner = innerRegex.exec(tja[1])) !== null) {
        chunks.push(inner[1]);
        totalLen += inner[1].length;
      }
    }
  }

  // Also scan for plain-text streams (bounded to 64KB per match to prevent ReDoS)
  const streamRegex = /stream\r?\n([\s\S]{0,65536}?)endstream/g;
  while ((match = streamRegex.exec(text)) !== null && totalLen < maxBytes) {
    const stream = match[1];
    // Only include if it looks like readable text (>50% printable ASCII)
    const printable = stream.replace(/[^\x20-\x7E]/g, '');
    if (printable.length > 20 && printable.length / stream.length > 0.5) {
      chunks.push(printable);
      totalLen += printable.length;
    }
  }

  return chunks.join(' ').slice(0, maxBytes);
}

/**
 * Extract text from HTML while detecting hidden text attacks.
 * Hidden text (display:none, font-size:0, opacity:0, visibility:hidden,
 * off-screen positioning, same-color text/bg) is extracted with a
 * [HIDDEN] marker so the regex scanner can flag it.
 */
function extractHtmlText(html: string): string {
  const chunks: string[] = [];

  // Extract text from hidden elements — these are high-signal injection vectors
  // display:none, visibility:hidden, opacity:0, font-size:0, off-screen position
  const hiddenPatterns = [
    /style\s*=\s*"[^"]*display\s*:\s*none[^"]*"[^>]*>([^<]{1,4096})/gi,
    /style\s*=\s*"[^"]*visibility\s*:\s*hidden[^"]*"[^>]*>([^<]{1,4096})/gi,
    /style\s*=\s*"[^"]*opacity\s*:\s*0[^"]*"[^>]*>([^<]{1,4096})/gi,
    /style\s*=\s*"[^"]*font-size\s*:\s*0[^"]*"[^>]*>([^<]{1,4096})/gi,
    /style\s*=\s*"[^"]*color\s*:\s*(?:white|#fff(?:fff)?|rgba?\(\s*255\s*,\s*255\s*,\s*255)[^"]*"[^>]*>([^<]{1,4096})/gi,
    /style\s*=\s*"[^"]*position\s*:\s*absolute[^"]*left\s*:\s*-\d{3,}[^"]*"[^>]*>([^<]{1,4096})/gi,
  ];

  for (const pat of hiddenPatterns) {
    let m;
    while ((m = pat.exec(html)) !== null) {
      const text = m[1].trim();
      if (text.length > 0) {
        chunks.push(`[HIDDEN] ${text}`);
      }
    }
  }

  // Extract script content for scanning (injections can be hidden in script tags)
  const scriptRegex = /<script[^>]{0,1024}>([\s\S]{0,65536}?)<\/script>/gi;
  let sm;
  while ((sm = scriptRegex.exec(html)) !== null) {
    const text = sm[1].trim();
    if (text.length > 0) chunks.push(text);
  }

  // Strip all HTML tags and extract visible text
  const visibleText = html
    .replace(/<script[^>]*>[\s\S]{0,65536}?<\/script>/gi, '')
    .replace(/<style[^>]*>[\s\S]{0,65536}?<\/style>/gi, '')
    .replace(/<[^>]{0,1024}>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();

  if (visibleText.length > 0) {
    chunks.push(visibleText);
  }

  return chunks.join('\n');
}

/**
 * Extract text from SVG elements that LLMs/VLMs process.
 * Flags dangerous elements (script, foreignObject) as injection vectors.
 */
function extractSvgText(svg: string): string {
  const chunks: string[] = [];

  // Extract <text> element content (bounded)
  const textRegex = /<text[^>]{0,1024}>([^<]{0,4096})<\/text>/gi;
  let m;
  while ((m = textRegex.exec(svg)) !== null) {
    if (m[1].trim()) chunks.push(m[1].trim());
  }

  // Extract <title> content — VLMs use this for context
  const titleRegex = /<title[^>]{0,256}>([^<]{0,4096})<\/title>/gi;
  while ((m = titleRegex.exec(svg)) !== null) {
    if (m[1].trim()) chunks.push(m[1].trim());
  }

  // Extract <desc> content — VLMs use this for context
  const descRegex = /<desc[^>]{0,256}>([^<]{0,4096})<\/desc>/gi;
  while ((m = descRegex.exec(svg)) !== null) {
    if (m[1].trim()) chunks.push(m[1].trim());
  }

  // Extract aria-label attributes — VLMs pay attention to accessibility
  const ariaRegex = /aria-label\s*=\s*"([^"]{1,4096})"/gi;
  while ((m = ariaRegex.exec(svg)) !== null) {
    if (m[1].trim()) chunks.push(m[1].trim());
  }

  // Extract CDATA sections — hidden text vector
  const cdataRegex = /<!\[CDATA\[([\s\S]{0,65536}?)\]\]>/gi;
  while ((m = cdataRegex.exec(svg)) !== null) {
    if (m[1].trim()) chunks.push(m[1].trim());
  }

  // Flag dangerous SVG elements
  if (/<script[^>]{0,256}>/i.test(svg)) {
    chunks.push('[SVG_SCRIPT] script element detected in SVG');
  }
  if (/<foreignObject[^>]{0,256}>/i.test(svg)) {
    chunks.push('[SVG_FOREIGN_OBJECT] foreignObject element detected in SVG');
  }
  // Detect event handlers (onload, onclick, etc.)
  if (/\bon\w+\s*=\s*"/i.test(svg)) {
    chunks.push('[SVG_EVENT_HANDLER] inline event handler detected in SVG');
  }

  return chunks.join('\n');
}
