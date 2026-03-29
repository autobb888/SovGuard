#!/usr/bin/env bash
# Download the DeBERTa-v3 prompt injection detection model for local inference.
# Model: ProtectAI/deberta-v3-base-prompt-injection-v2 (Apache 2.0)
set -euo pipefail

MODEL_DIR="${SOVGUARD_MODEL_DIR:-$(cd "$(dirname "$0")/.." && pwd)/models/deberta-v3-prompt-injection}"
HF_REPO="ProtectAI/deberta-v3-base-prompt-injection-v2"
BASE_URL="https://huggingface.co/${HF_REPO}/resolve/main"

mkdir -p "$MODEL_DIR"
echo "Downloading model to: ${MODEL_DIR}"

# Download ONNX model
if [ ! -f "${MODEL_DIR}/model.onnx" ]; then
  echo "Downloading model.onnx..."
  curl -L "${BASE_URL}/onnx/model.onnx" -o "${MODEL_DIR}/model.onnx"
else
  echo "model.onnx already exists, skipping"
fi

# Download tokenizer
if [ ! -f "${MODEL_DIR}/tokenizer.json" ]; then
  echo "Downloading tokenizer.json..."
  curl -L "${BASE_URL}/tokenizer.json" -o "${MODEL_DIR}/tokenizer.json"
else
  echo "tokenizer.json already exists, skipping"
fi

echo "Done. Model ready at: ${MODEL_DIR}"
echo "Set SOVGUARD_MODEL_DIR=${MODEL_DIR} or place in models/deberta-v3-prompt-injection/ relative to project root."
ls -lh "${MODEL_DIR}/"
