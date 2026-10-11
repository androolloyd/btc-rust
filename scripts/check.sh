#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked
cargo check --locked --package btc-primitives --no-default-features
cargo check --locked --package btc-network --no-default-features
cargo check --locked --package btc-storage --no-default-features
cargo build --release --locked --package btc-node
