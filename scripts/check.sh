#!/usr/bin/env bash
set -euo pipefail

wallet_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$wallet_root"

if rg -n 'path\s*=\s*"\.\./' --glob Cargo.toml .; then
  echo "sibling path dependency is forbidden" >&2
  exit 1
fi

if rg -n 'name = "(electrum-client|esplora-client|bitcoincore-rpc)"' Cargo.lock; then
  echo "alternate Bitcoin production backend found" >&2
  exit 1
fi

cargo fmt --all --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

contract_dir="$wallet_root/crates/hns-wallet-ethereum/contracts"
npm --prefix "$contract_dir" ci --ignore-scripts
npm --prefix "$contract_dir" audit --audit-level=high
npm --prefix "$contract_dir" run check

git diff --check
