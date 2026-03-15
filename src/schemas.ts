/**
 * SovGuard — Shared Zod Schemas for Request Validation
 * Used by server.ts for request validation.
 */

import { z } from 'zod';

export const ScanBody = z.object({ text: z.string().min(1).max(50000) });

export const ScanFileBody = z.object({
  filename: z.string().min(1).max(1000),
  metadata: z.record(z.union([z.string().max(10000), z.number()]))
    .refine(obj => Object.keys(obj).length <= 50, { message: 'Maximum 50 metadata keys' })
    .optional(),
});

export const WrapBody = z.object({
  text: z.string().min(1).max(50000),
  role: z.string().min(1).max(256).optional(),
  jobId: z.string().min(1).max(256).optional(),
  sessionId: z.string().min(1).max(256).optional(),
});

export const CanaryCreateBody = z.object({ sessionId: z.string().min(1).max(256) });

export const CanaryCheckBody = z.object({
  text: z.string().min(1).max(50000),
  sessionId: z.string().max(256).optional(),
});

export const ScanFileContentBody = z.object({
  /** Base64-encoded file content (must fit within 128KB body limit) */
  content: z.string().min(1).max(131_072),
  /** MIME type of the file */
  mimeType: z.string().min(1).max(256),
  /** Optional scan options */
  maxExtractBytes: z.number().int().min(1).max(1_048_576).optional(),
  chunkSize: z.number().int().min(512).max(65_536).optional(),
});

export const ScanOutputBody = z.object({
  text: z.string().min(1).max(50000),
  jobId: z.string().min(1).max(256),
  jobCategory: z.string().min(1).max(256).optional(),
  whitelistedAddresses: z.array(z.string().max(256)).max(100).optional(),
});

