/**
 * File Scanner
 * Scans filenames and metadata for injection patterns, path traversal, and encoding attacks.
 */

import path from 'path';
import type { FileMetadata, FileScanResult } from '../types.js';
import { regexScan } from '../scanner/regex.js';

// Unicode control characters to strip
const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202F\uFEFF]/g;
const RLO_CHAR = /\u202E/;
const NULL_BYTE = /\x00/;
// Path traversal: .., encoded variants (%2e, %252e, overlong UTF-8 %c0%ae), encoded slashes (%2f, %5c)
const PATH_TRAVERSAL = /(?:^|[\\/])\.\.(?:[\\/]|$)|^~[\\/]|%2e%2e|%252e|%c0%ae|%2f\.\.|\.\.%2f|%5c\.\.|\.\.%5c/i;

// Dangerous executable extensions that should always be flagged
const DANGEROUS_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.msi', '.msp',
  '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
  '.dll', '.sys', '.cpl', '.inf', '.reg', '.hta', '.lnk', '.sct',
]);

// Double extension pattern: legitimate extension followed by dangerous one
const DOUBLE_EXT_RE = /\.\w{1,10}\.(exe|bat|cmd|com|scr|pif|msi|ps1|vbs|vbe|js|jse|wsf|wsh|dll|hta|lnk)$/i;

/**
 * Scan a filename and optional metadata for security issues.
 */
export function scanFile(filename: string, metadata?: FileMetadata): FileScanResult {
  const flags: string[] = [];
  const details = {
    pathTraversal: false,
    nullBytes: false,
    unicodeRLO: false,
    injectionInName: false,
    suspiciousMetadata: false,
    dangerousExtension: false,
    doubleExtension: false,
  };

  // ── Null bytes ──
  if (NULL_BYTE.test(filename)) {
    details.nullBytes = true;
    flags.push('null_byte_in_filename');
  }

  // ── Unicode RLO (right-to-left override) ──
  if (RLO_CHAR.test(filename)) {
    details.unicodeRLO = true;
    flags.push('unicode_rlo_in_filename');
  }

  // ── Path traversal ──
  if (PATH_TRAVERSAL.test(filename)) {
    details.pathTraversal = true;
    flags.push('path_traversal_attempt');
  }

  // ── Dangerous extension ──
  const ext = path.extname(filename).toLowerCase();
  if (DANGEROUS_EXTENSIONS.has(ext)) {
    details.dangerousExtension = true;
    flags.push('dangerous_extension');
  }

  // ── Double extension (e.g. report.pdf.exe) ──
  if (DOUBLE_EXT_RE.test(filename)) {
    details.doubleExtension = true;
    flags.push('double_extension');
  }

  // ── Injection patterns in filename ──
  const nameResult = regexScan(filename.replace(/[_\-./]/g, ' '));
  if (nameResult.score > 0) {
    details.injectionInName = true;
    flags.push(...nameResult.flags.map(f => `filename:${f}`));
  }

  // ── Metadata scanning ──
  if (metadata) {
    const metadataText = Object.values(metadata)
      .filter((v): v is string => typeof v === 'string')
      .join(' ');

    if (metadataText.length > 0) {
      const metaResult = regexScan(metadataText);
      if (metaResult.score > 0) {
        details.suspiciousMetadata = true;
        flags.push(...metaResult.flags.map(f => `metadata:${f}`));
      }
    }
  }

  // ── Sanitize filename ──
  const sanitizedFilename = sanitizeFilename(filename);

  const safe = flags.length === 0;

  return { safe, sanitizedFilename, flags, details };
}

/**
 * Sanitize a filename: strip path components, control chars, and restrict to safe characters.
 */
export function sanitizeFilename(filename: string): string {
  // Extract basename (remove directory components)
  let name = path.basename(filename);

  // Remove control characters
  name = name.replace(CONTROL_CHARS, '');

  // Remove null bytes
  name = name.replace(/\x00/g, '');

  // Replace unsafe characters with underscore
  name = name.replace(/[^a-zA-Z0-9._\-]/g, '_');

  // Collapse multiple underscores
  name = name.replace(/_+/g, '_');

  // Remove leading dots (hidden files)
  name = name.replace(/^\.+/, '');

  // Ensure non-empty
  if (!name || name === '_') {
    name = 'unnamed_file';
  }

  // Limit length
  if (name.length > 200) {
    const ext = path.extname(name);
    name = name.slice(0, 200 - ext.length) + ext;
  }

  return name;
}
