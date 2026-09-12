#!/usr/bin/env bash
# Download PIGuard ONNX export for D0 disagreement harness (not a product model).
# Source: ahmedomuharram/piguard-onnx (export of leolee99/PIGuard, ACL 2025).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${SOVGUARD_PIGUARD_DIR:-$ROOT/models/piguard-onnx}"
mkdir -p "$DIR"
cd "$DIR"
if [[ ! -f model.onnx ]]; then
  curl -L --fail -o model.onnx "https://huggingface.co/ahmedomuharram/piguard-onnx/resolve/main/model.onnx"
fi
if [[ ! -f tokenizer.official.json ]]; then
  curl -L --fail -o tokenizer.official.json "https://huggingface.co/leolee99/PIGuard/resolve/main/tokenizer.json"
fi
# keep a copy as tokenizer.json for humans
cp -f tokenizer.official.json tokenizer.json
sha256sum model.onnx tokenizer.official.json
echo "PIGuard ONNX ready at $DIR"
