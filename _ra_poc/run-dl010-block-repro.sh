#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --import tsx _ra_poc/dl010-block-repro.ts
