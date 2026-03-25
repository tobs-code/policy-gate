FROM rust:slim

# Minimal build deps — we use rustup's own LLVM tools, not system clang
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install nightly with llvm-tools (provides llvm-profdata, lld matching nightly's LLVM)
RUN rustup toolchain install nightly \
      --component rust-src,llvm-tools \
 && cargo +nightly install cargo-fuzz

WORKDIR /app

# Copy workspace
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY fuzz/ ./fuzz/

# Pre-fetch dependencies
RUN cargo +nightly fetch

ENTRYPOINT ["bash", "/app/fuzz/run_fuzz.sh"]
