#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# Download the sentence-embedding model used by the semantic layer
# (all-MiniLM-L6-v2). Pinned to an immutable commit + SHA-256 verified
# so a compromised/rotated upstream can't swap the model (audit H6).
# ──────────────────────────────────────────────────────────────
set -euo pipefail

REPO="sentence-transformers/all-MiniLM-L6-v2"
# Immutable revision (NOT 'main') — pinned 2026-05-30.
REVISION="c9745ed1d9f207416be6d2e6f8de32d1f16199bf"
DEST="$(cd "$(dirname "$0")/.." && pwd)/models/all-MiniLM-L6-v2"
BASE="https://huggingface.co/${REPO}/resolve/${REVISION}"

# file:relative-url:sha256
FILES=(
  "model.onnx:onnx/model.onnx:6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452"
  "tokenizer.json:tokenizer.json:be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037"
)

mkdir -p "$DEST"
for entry in "${FILES[@]}"; do
  name="${entry%%:*}"; rest="${entry#*:}"; rel="${rest%%:*}"; sum="${rest##*:}"
  out="$DEST/$name"
  if [ -f "$out" ] && echo "${sum}  ${out}" | sha256sum -c --status 2>/dev/null; then
    echo "✓ $name already present and verified"
    continue
  fi
  echo "Downloading $name ..."
  curl -fL "${BASE}/${rel}" -o "$out"
  echo "${sum}  ${out}" | sha256sum -c --status || {
    echo "ERROR: checksum mismatch for $name — refusing to use it." >&2
    rm -f "$out"
    exit 1
  }
  echo "✓ $name verified"
done
echo "Embedding model ready at $DEST"
