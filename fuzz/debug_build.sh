#!/usr/bin/env bash
set -euo pipefail

echo "=== clang version ==="
clang --version

echo "=== libclang_rt files ==="
find /usr/lib/llvm-*/lib/clang -name "libclang_rt*x86_64*" 2>/dev/null | sort

SANCOV_LIB=$(find /usr/lib/llvm-*/lib/clang -name "libclang_rt.fuzzer_no_main-x86_64.a" 2>/dev/null | head -1)
SANCOV_DIR=$(dirname "$SANCOV_LIB" 2>/dev/null || echo "NOT FOUND")
echo "=== SANCOV_DIR: ${SANCOV_DIR} ==="

echo "=== building with -fuse-ld=bfd ==="
ASAN_OPTIONS="detect_odr_violation=0" \
RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cllvm-args=-simplifycfg-branch-fold-threshold=0 -Zsanitizer=address -Cdebug-assertions -Ccodegen-units=1 -Clink-arg=-fuse-ld=bfd" \
cargo +nightly build \
  --manifest-path /app/crates/firewall-fuzz/Cargo.toml \
  --target x86_64-unknown-linux-gnu \
  --release \
  --bin fuzz_normalise 2>&1 | tail -5
