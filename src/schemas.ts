/**
 * SovGuard — Shared Zod Schemas for Request Validation
 * Used by server.ts (self-hosted) and integrations.
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

export const ScanReportBody = z.object({
  file_path: z.string().min(1).max(1024).optional(),
  content_hash: z.string().min(1).max(128),
  score: z.number().min(0).max(1),
  mime_type: z.string().min(1).max(256).optional(),
  workspace_uid: z.string().min(1).max(256).optional(),
  verdict: z.enum(['false_positive', 'false_negative', 'confirmed']),
  notes: z.string().max(1000).optional(),
});

