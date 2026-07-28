#!/usr/bin/env bash
# Download the DeBERTa-v3 prompt injection detection model for local inference.
# Model: protectai/deberta-v3-base-prompt-injection-v2 (Apache 2.0)
#
# H6 (SECURITY_AUDIT_2026-05-30): this used to fetch from the mutable `main` ref
# with no integrity check, so whoever controls the upstream repo — or anything
# on the path — could swap the model and silently defeat detection. It also used
# a bare `curl -L` with no --fail, which writes an HTTP error body to disk as
# model.onnx and then reports success.
#
# Now: pinned to an immutable commit, every file SHA-256 verified, fail closed.
# Digests confirmed against the HuggingFace API on 2026-07-26.
#
# To move to a newer revision, update HF_REV and both digests together. Get them with:
#   curl -sL "https://huggingface.co/api/models/${HF_REPO}?blobs=true" | jq '.sha, .siblings[]|select(.rfilename=="onnx/model.onnx").lfs.oid'
# and sha256sum the non-LFS files after downloading from the pinned revision.
set -euo pipefail

MODEL_DIR="${SOVGUARD_MODEL_DIR:-$(cd "$(dirname "$0")/.." && pwd)/models/deberta-v3-prompt-injection}"
HF_REPO="protectai/deberta-v3-base-prompt-injection-v2"
HF_REV="90c9989b1a342275dd0d1a95aad283c04e075671"
BASE_URL="https://huggingface.co/${HF_REPO}/resolve/${HF_REV}"

SHA256_MODEL="f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c"
SHA256_TOKENIZER="f0a66ad0d735d8dca9ecac4ff50fcdef4bb6adbadd2941a926844844d2c2059b"

# fetch_verified <remote-path> <local-file> <expected-sha256>
#
# Verifies whatever is already on disk too — an existing file is not evidence of
# a good file, and skipping the check was half of H6. Downloads to a temp path so
# a failed or truncated fetch can never replace a known-good file.
fetch_verified() {
  local remote="$1" dest="$2" want="$3" name
  name="$(basename "$dest")"

  if [ -f "$dest" ]; then
    local have
    have="$(sha256sum "$dest" | cut -d' ' -f1)"
    if [ "$have" = "$want" ]; then
      echo "${name}: present and verified"
      return 0
    fi
    echo "${name}: on-disk copy FAILED verification — refetching" >&2
    echo "  expected ${want}" >&2
    echo "  found    ${have}" >&2
  fi

  echo "${name}: downloading from ${HF_REV:0:12}…"
  local tmp="${dest}.partial.$$"
  # --fail: do not write an HTTP error body to disk. --location-trusted is NOT
  # used; credentials must never follow a redirect.
  if ! curl -fL --retry 3 --retry-delay 2 --max-time 1800 "$remote" -o "$tmp"; then
    rm -f "$tmp"
    echo "ERROR: download failed for ${name}" >&2
    return 1
  fi

  local got
  got="$(sha256sum "$tmp" | cut -d' ' -f1)"
  if [ "$got" != "$want" ]; then
    rm -f "$tmp"
    echo "ERROR: SHA-256 MISMATCH for ${name} — refusing to install." >&2
    echo "  expected ${want}" >&2
    echo "  got      ${got}" >&2
    echo "  The upstream artifact changed, or the download was tampered with." >&2
    return 1
  fi

  mv -f "$tmp" "$dest"
  echo "${name}: verified OK"
}

mkdir -p "$MODEL_DIR"
echo "Model dir: ${MODEL_DIR}"
echo "Pinned revision: ${HF_REV}"

fetch_verified "${BASE_URL}/onnx/model.onnx"  "${MODEL_DIR}/model.onnx"     "$SHA256_MODEL"
fetch_verified "${BASE_URL}/tokenizer.json"   "${MODEL_DIR}/tokenizer.json" "$SHA256_TOKENIZER"

echo
echo "Done. All artifacts verified against pinned digests."
echo "Set SOVGUARD_MODEL_DIR=${MODEL_DIR} or place in models/deberta-v3-prompt-injection/ relative to project root."
ls -lh "${MODEL_DIR}/"
