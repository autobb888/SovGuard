/**
 * Layer 3: Self-Hosted ML Classifier
 * Uses DeBERTa-v3-base-prompt-injection via ONNX Runtime.
 * No external API calls — model runs entirely in-process.
 */

import type { LayerResult } from '../types.js';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

// Lazy-loaded ONNX runtime and model session
let ort: any = null;
let session: any = null;
let tokenizer: any = null;
let modelLoaded = false;
let loadError: string | null = null;

const MODEL_DIR = process.env.SOVGUARD_MODEL_DIR || join(process.cwd(), 'models', 'deberta-v3-prompt-injection');
const MODEL_FILE = 'model.onnx';
const VOCAB_FILE = 'tokenizer.json';

/**
 * Simple tokenizer for DeBERTa.
 * Loads the HuggingFace tokenizer.json and performs WordPiece-style tokenization.
 * For production accuracy we use a simplified approach:
 * split on whitespace/punctuation, look up token IDs, pad/truncate to max_length.
 */
interface TokenizerData {
  model: { vocab: Record<string, number> };
  added_tokens?: Array<{ id: number; content: string }>;
}

const MAX_LENGTH = 512;
const PAD_TOKEN_ID = 0;
const CLS_TOKEN_ID = 1;
const SEP_TOKEN_ID = 2;
const UNK_TOKEN_ID = 3;

function loadTokenizer(path: string): TokenizerData {
  const raw = readFileSync(path, 'utf-8');
  return JSON.parse(raw);
}

function tokenize(text: string, vocab: Record<string, number>): number[] {
  // Simple whitespace + subword tokenization
  const tokens: number[] = [CLS_TOKEN_ID];
  const words = text.toLowerCase().split(/\s+/).filter(Boolean);

  for (const word of words) {
    if (tokens.length >= MAX_LENGTH - 1) break;
    const id = vocab[word];
    if (id !== undefined) {
      tokens.push(id);
    } else {
      // Try subword tokenization: split into characters as fallback
      // Check for ##subword pieces
      let remaining = word;
      let isFirst = true;
      while (remaining.length > 0 && tokens.length < MAX_LENGTH - 1) {
        let found = false;
        for (let end = remaining.length; end > 0; end--) {
          const piece = isFirst ? remaining.slice(0, end) : '##' + remaining.slice(0, end);
          const pieceId = vocab[piece];
          if (pieceId !== undefined) {
            tokens.push(pieceId);
            remaining = remaining.slice(end);
            isFirst = false;
            found = true;
            break;
          }
        }
        if (!found) {
          tokens.push(UNK_TOKEN_ID);
          break;
        }
      }
    }
  }

  tokens.push(SEP_TOKEN_ID);
  return tokens;
}

function padTokens(tokenIds: number[], maxLen: number): { inputIds: BigInt64Array; attentionMask: BigInt64Array } {
  const inputIds = new BigInt64Array(maxLen).fill(BigInt(PAD_TOKEN_ID));
  const attentionMask = new BigInt64Array(maxLen).fill(0n);

  for (let i = 0; i < Math.min(tokenIds.length, maxLen); i++) {
    inputIds[i] = BigInt(tokenIds[i]);
    attentionMask[i] = 1n;
  }

  return { inputIds, attentionMask };
}

async function ensureModel(): Promise<boolean> {
  if (modelLoaded) return true;
  if (loadError) return false;

  const modelPath = join(MODEL_DIR, MODEL_FILE);
  const vocabPath = join(MODEL_DIR, VOCAB_FILE);

  if (!existsSync(modelPath)) {
    loadError = `Model not found at ${modelPath}. Run: scripts/download-model.sh`;
    return false;
  }
  if (!existsSync(vocabPath)) {
    loadError = `Tokenizer not found at ${vocabPath}. Run: scripts/download-model.sh`;
    return false;
  }

  try {
    // Dynamic import of onnxruntime-node (not installed at build time)
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    ort = await (Function('return import("onnxruntime-node")')() as Promise<any>);

    // Configure session options for CPU inference
    const options = new ort.InferenceSession.SessionOptions();
    // Use 2 threads for inference (balance between speed and CPU usage)
    options.intraOpNumThreads = 2;
    options.interOpNumThreads = 1;

    session = await ort.InferenceSession.create(modelPath, {
      executionProviders: ['CPUExecutionProvider'],
      graphOptimizationLevel: 'all',
      intraOpNumThreads: 2,
      interOpNumThreads: 1,
    });

    tokenizer = loadTokenizer(vocabPath);
    modelLoaded = true;
    console.log('[classifier-local] DeBERTa model loaded successfully');
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
    const vocab = tokenizer.model.vocab;
    const tokenIds = tokenize(text, vocab);
    const { inputIds, attentionMask } = padTokens(tokenIds, MAX_LENGTH);

    // Create ONNX tensors
    const inputIdsTensor = new ort.Tensor('int64', inputIds, [1, MAX_LENGTH]);
    const attentionMaskTensor = new ort.Tensor('int64', attentionMask, [1, MAX_LENGTH]);

    // Run inference
    const feeds: Record<string, any> = {
      input_ids: inputIdsTensor,
      attention_mask: attentionMaskTensor,
    };

    // Some models also need token_type_ids
    const tokenTypeIds = new BigInt64Array(MAX_LENGTH).fill(0n);
    feeds.token_type_ids = new ort.Tensor('int64', tokenTypeIds, [1, MAX_LENGTH]);

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
        tokenCount: tokenIds.length,
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
