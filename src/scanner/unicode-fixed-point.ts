/** DL-002 re-exports from regex (implementation lives there to avoid import cycles). */
export {
  normalizeToFixedPoint,
  shouldEscalateUnicodeSignals,
  bidiCorroborated,
  stripBidiOverrides,
  decodeCodePointEscapes,
  materializeUnicodeTags,
  type FixedPointNorm,
} from './regex.js';
