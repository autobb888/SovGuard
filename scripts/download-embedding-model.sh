#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# Download the sentence-embedding model used by the semantic layer
# (paraphrase-multilingual-MiniLM-L12-v2 — 50+ languages so the attack corpus
# matches foreign-language attacks too). Pinned to an immutable commit + SHA-256
# verified so a compromised/rotated upstream can't swap the model (audit H6).
# ──────────────────────────────────────────────────────────────
set -euo pipefail

REPO="Xenova/paraphrase-multilingual-MiniLM-L12-v2"
# Immutable revision (NOT 'main') — pinned 2026-06-01.
REVISION="2c4055b12046f11709e9df2c122e59ffbdc2f900"
DEST="$(cd "$(dirname "$0")/.." && pwd)/models/paraphrase-multilingual-MiniLM-L12-v2"
BASE="https://huggingface.co/${REPO}/resolve/${REVISION}"

# file:relative-url:sha256
FILES=(
  "model.onnx:onnx/model.onnx:185ae63f47e17a7e8d30d0e6a3cde6a6e4b79bc5b81666ecffc279a6856ca113"
  "tokenizer.json:tokenizer.json:b60b6b43406a48bf3638526314f3d232d97058bc93472ff2de930d43686fa441"
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
