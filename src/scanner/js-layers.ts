/**
 * The pure-JS scan layers (regex / indirect / perplexity), assembled in one
 * place (H3). Single source of truth shared by scan()'s inline path, the worker,
 * and the pool's crash fallback — so all three paths produce identical results.
 */
import type { LayerResult } from '../types.js';
import { regexScan } from './regex.js';
import { indirectInjectionScan } from './indirect.js';
import { perplexityScan } from './perplexity.js';

export function runJsLayersSync(
  input: string,
  enablePerplexity: boolean,
  extraPatterns?: Parameters<typeof regexScan>[1],
): LayerResult[] {
  const layers: LayerResult[] = [];
  layers.push(regexScan(input, extraPatterns));
  layers.push(indirectInjectionScan(input));
  if (enablePerplexity) layers.push(perplexityScan(input));
  return layers;
}
