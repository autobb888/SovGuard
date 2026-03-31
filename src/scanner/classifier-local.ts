/**
 * Layer 3: Self-Hosted ML Classifier
 * Uses DeBERTa-v3-base-prompt-injection via ONNX Runtime.
 * Tokenization via HuggingFace tokenizers (Rust-based, accurate).
 * No external API calls — model runs entirely in-process.
 */

import type { LayerResult } from '../types.js';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

// Lazy-loaded modules and state
let ort: any = null;
let Tokenizer: any = null;
let session: any = null;
let tokenizer: any = null;
let modelLoaded = false;
let loadError: string | null = null;

const MODEL_DIR = process.env.SOVGUARD_MODEL_DIR || join(process.cwd(), 'models', 'deberta-v3-prompt-injection');
const MODEL_FILE = 'model.onnx';
const TOKENIZER_FILE = 'tokenizer.json';
const MAX_LENGTH = 512;

async function ensureModel(): Promise<boolean> {
  if (modelLoaded) return true;
  if (loadError) return false;

  const modelPath = join(MODEL_DIR, MODEL_FILE);
  const tokenizerPath = join(MODEL_DIR, TOKENIZER_FILE);

  if (!existsSync(modelPath)) {
    loadError = `Model not found at ${modelPath}. Run: scripts/download-model.sh`;
    return false;
  }
  if (!existsSync(tokenizerPath)) {
    loadError = `Tokenizer not found at ${tokenizerPath}. Run: scripts/download-model.sh`;
    return false;
  }

  try {
    // Dynamic imports (these packages may not be installed at build time)
    ort = await (Function('return import("onnxruntime-node")')() as Promise<any>);
    const tokenizersModule = await (Function('return import("tokenizers")')() as Promise<any>);
    Tokenizer = tokenizersModule.Tokenizer;

    // Load tokenizer from HuggingFace tokenizer.json (async in tokenizers >=0.13.4)
    tokenizer = await Tokenizer.fromFile(tokenizerPath);
    tokenizer.setTruncation(MAX_LENGTH);
    tokenizer.setPadding({ maxLength: MAX_LENGTH, padId: 0, padToken: '[PAD]' });

    // Create ONNX inference session
    session = await ort.InferenceSession.create(modelPath);

    modelLoaded = true;
    console.log(`[classifier-local] DeBERTa model loaded (${Math.round(require('fs').statSync(modelPath).size / 1024 / 1024)}MB)`);
    return true;
  } catch (err) {
    loadError = err instanceof Error ? err.message : 'Unknown error loading ONNX model';
    console.error('[classifier-local] Failed to load model:', loadError);
    return false;
  }
}

function softmax(logits: Float32Array): number[] {
  const maxLogit = Math.max(...logits);
  const exps = Array.from(logits).map(l => Math.exp(l - maxLogit));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map(e => e / sum);
}

/**
 * Run local DeBERTa classifier on text.
 * Returns a LayerResult compatible with the existing classifier interface.
 */
export async function localClassifierScan(text: string): Promise<LayerResult> {
  const ready = await ensureModel();

  if (!ready) {
    return {
      layer: 'classifier',
      score: 0,
      flags: ['classifier_unavailable'],
      details: {
        available: false,
        provider: 'local',
        message: loadError || 'Model not loaded',
      },
    };
  }

  try {
    // Tokenize using the HuggingFace tokenizer (handles SentencePiece/Unigram correctly)
    const encoded = await tokenizer.encode(text);
    const ids: number[] = encoded.getIds();
    const attMask: number[] = encoded.getAttentionMask();

    // Convert to BigInt64Array for ONNX Runtime
    const inputIds = new BigInt64Array(ids.map(id => BigInt(id)));
    const attentionMask = new BigInt64Array(attMask.map(m => BigInt(m)));

    // Build feeds
    const feeds: Record<string, any> = {
      input_ids: new ort.Tensor('int64', inputIds, [1, inputIds.length]),
      attention_mask: new ort.Tensor('int64', attentionMask, [1, attentionMask.length]),
    };

    // Add token_type_ids if the model expects them
    if (session.inputNames.includes('token_type_ids')) {
      const tokenTypeIds = new BigInt64Array(inputIds.length).fill(0n);
      feeds.token_type_ids = new ort.Tensor('int64', tokenTypeIds, [1, inputIds.length]);
    }

    const results = await session.run(feeds);

    // Output is logits: [1, 2] — index 0 = SAFE, index 1 = INJECTION
    const logits = results.logits?.data as Float32Array;
    if (!logits || logits.length < 2) {
      return {
        layer: 'classifier',
        score: 0,
        flags: ['classifier_error'],
        details: { available: true, provider: 'local', error: 'Unexpected model output shape' },
      };
    }

    const probs = softmax(logits);
    const injectionProb = probs[1]; // index 1 = INJECTION class
    const score = injectionProb;
    const flags: string[] = [];

    if (score > 0.5) flags.push('ml:prompt_injection');
    if (score > 0.8) flags.push('ml:high_confidence');

    return {
      layer: 'classifier',
      score,
      flags,
      details: {
        available: true,
        provider: 'local',
        model: 'deberta-v3-base-prompt-injection-v2',
        injectionScore: injectionProb,
        safeScore: probs[0],
        tokenCount: ids.length,
      },
    };
  } catch (err) {
    return {
      layer: 'classifier',
      score: 0,
      flags: ['classifier_error'],
      details: {
        available: true,
        provider: 'local',
        error: err instanceof Error ? err.message : 'Inference failed',
      },
    };
  }
}

/** Check if the local model is available without loading it. */
export function isLocalModelAvailable(): boolean {
  return existsSync(join(MODEL_DIR, MODEL_FILE));
}
