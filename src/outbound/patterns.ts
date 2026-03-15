/**
 * Shared regex patterns for outbound scanners.
 * Deduplicated from pii.ts and contamination.ts to ensure consistency.
 */

/**
 * Email regex — structural validation:
 * - Local part: starts/ends with alphanumeric, allows ._%+- in middle
 * - Domain: each label starts/ends with alphanumeric (prevents leading/trailing dots)
 * - Valid TLD of 2+ chars
 * - Bounded quantifiers to prevent ReDoS
 * NOTE: Consecutive dots in local part must be checked at call site (see scanPII).
 */
export const EMAIL_RE = /\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b/g;

/**
 * URL regex — matches http/https URLs.
 */
export const URL_RE = /https?:\/\/[^\s)<>"']+/gi;
