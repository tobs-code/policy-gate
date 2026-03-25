#!/usr/bin/env bash
set -euo pipefail

TARGET="${FUZZ_TARGET:-fuzz_normalise}"
MAX_TIME="${FUZZ_MAX_TIME:-60}"
CORPUS_DIR="/corpus/${TARGET}"
ARTIFACTS_DIR="/artifacts/${TARGET}"

mkdir -p "$CORPUS_DIR" "$ARTIFACTS_DIR"

echo "=== cargo-fuzz: target=${TARGET} max_time=${MAX_TIME}s ==="

# --sanitizer none: skips ASan/sancov instrumentation that causes lld symbol
# resolution failures on Linux with nightly. Coverage-guided fuzzing still works
# via libFuzzer's built-in SanitizerCoverage; only memory-error detection is reduced.
cargo +nightly fuzz run "$TARGET" \
  --fuzz-dir /app/crates/firewall-fuzz \
  --sanitizer none \
  "$CORPUS_DIR" \
  -- \
  -max_total_time="$MAX_TIME" \
  -artifact_prefix="$ARTIFACTS_DIR/" \
  -print_final_stats=1
