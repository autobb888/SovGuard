/**
 * Layer 3: ML Classifier
 * Uses Lakera Guard v2 API for prompt injection / jailbreak detection.
 * Graceful degradation: if no API key, returns score 0 (layers 1/2/4/5/6 still active).
 * Future: Self-hosted ONNX model (DeBERTa-v3).
 */

import type { LayerResult } from '../types.js';

interface ClassifierConfig {
  lakeraApiKey?: string;
  /** Override API URL (for testing) */
  apiUrl?: string;
  /** Timeout in ms. Default: 5000 */
  timeoutMs?: number;
}

/**
 * Lakera Guard v2 response.
 * The actual API returns a flat { flagged, metadata } shape.
 * We also support the documented { results: [...] } shape for forward-compat.
 */
interface LakeraV2Response {
  // Actual v2 response shape
  flagged?: boolean;
  metadata?: { request_uuid?: string };
  // Documented/future shape with detailed scores
  model?: string;
  results?: Array<{
    flagged: boolean;
    categories: {
      prompt_injection: boolean;
      jailbreak: boolean;
    };
    category_scores: {
      prompt_injection: number;
      jailbreak: number;
    };
  }>;
}

const DEFAULT_API_URL = 'https://api.lakera.ai/v2/guard';
const DEFAULT_TIMEOUT_MS = 5000;

/**
 * Run ML classifier on text.
 * If LAKERA_API_KEY is configured, calls Lakera Guard v2 API.
 * Otherwise returns a stub result (score 0, not flagged).
 */
export async function classifierScan(text: string, config?: ClassifierConfig): Promise<LayerResult> {
  const apiKey = config?.lakeraApiKey || process.env.LAKERA_API_KEY;

  if (!apiKey) {
    return {
      layer: 'classifier',
      score: 0,
      flags: ['classifier_unavailable'],
      details: {
        available: false,
        message: 'No LAKERA_API_KEY configured. ML classification skipped.',
      },
    };
  }

  const apiUrl = config?.apiUrl || DEFAULT_API_URL;
  const timeoutMs = config?.timeoutMs || DEFAULT_TIMEOUT_MS;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        messages: [{ role: 'user', content: text }],
      }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!response.ok) {
      return {
        layer: 'classifier',
        score: 0,
        flags: ['classifier_error'],
        details: { available: false, error: `Lakera API returned ${response.status}` },
      };
    }

    const data = (await response.json()) as LakeraV2Response;

    // Handle the detailed results format (documented/future)
    if (data.results && data.results.length > 0) {
      const result = data.results[0];
      const injectionScore = result.category_scores?.prompt_injection ?? 0;
      const jailbreakScore = result.category_scores?.jailbreak ?? 0;
      const score = Math.max(injectionScore, jailbreakScore);
      const flags: string[] = [];

      if (result.categories.prompt_injection) flags.push('ml:prompt_injection');
      if (result.categories.jailbreak) flags.push('ml:jailbreak');

      return {
        layer: 'classifier',
        score,
        flags,
        details: {
          available: true,
          provider: 'lakera',
          model: data.model,
          injectionScore,
          jailbreakScore,
          flagged: result.flagged,
        },
      };
    }

    // Handle the flat response format (actual v2 API)
    if (typeof data.flagged === 'boolean') {
      const flagged = data.flagged;
      const score = flagged ? 0.95 : 0.05;
      const flags: string[] = [];
      if (flagged) flags.push('ml:flagged');

      return {
        layer: 'classifier',
        score,
        flags,
        details: {
          available: true,
          provider: 'lakera',
          flagged,
          requestId: data.metadata?.request_uuid,
        },
      };
    }

    // Unknown response shape
    return {
      layer: 'classifier',
      score: 0,
      flags: ['classifier_error'],
      details: { available: false, error: 'Lakera API returned unexpected response format' },
    };
  } catch (err: unknown) {
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return {
      layer: 'classifier',
      score: 0,
      flags: ['classifier_error'],
      details: {
        available: false,
        error: isTimeout ? `Lakera API timeout (${timeoutMs}ms)` : (err instanceof Error ? err.message : 'Unknown classifier error'),
      },
    };
  }
}
