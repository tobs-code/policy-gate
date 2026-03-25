#!/usr/bin/env bash
set -e
mkdir -p /app/crates/firewall-fuzz/.cargo
printf '[target.x86_64-unknown-linux-gnu]\nlinker = "clang"\n' \
  > /app/crates/firewall-fuzz/.cargo/config.toml
echo "=== config.toml ==="
cat /app/crates/firewall-fuzz/.cargo/config.toml
echo "=== building fuzz_normalise ==="
cargo +nightly fuzz build fuzz_normalise --fuzz-dir /app/crates/firewall-fuzz 2>&1 | tail -5
