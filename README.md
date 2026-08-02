# hns-wallet-rs

`hns-wallet-rs` is the independent Rust wallet boundary for the Handshake DANE
browser products. It owns encrypted local wallet state, a Handshake-first
wallet, the Handshake Provider API core, fixed-price Shakedex orchestration,
chain-neutral market settlement, and deliberately narrow Bitcoin and Ethereum
modules.

The workspace does not combine the browser, node, or canonical protocol
repositories. It consumes released protocol crates and exposes a private,
length-prefixed wallet-service ABI for separately released browser adapters.

Current safety status: the production-hardening source boundary is implemented,
but executable HNS and Bitcoin value operations and all mainnet settlement
remain release-gated. The HNS runtime rejects configurations that enable send
or settlement, and the Bitcoin module cannot issue its value permit, until the
adapter-qualification and persistence gates recorded in
[`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) and
[`docs/QUALIFICATION.md`](docs/QUALIFICATION.md) are complete. Test success is
never a mainnet authorization signal.

## Crates

- `hns-wallet-types`: wallet-local identifiers and UI-safe summaries.
- `hns-wallet-store`: SQLite migrations and authenticated encryption.
- `hns-wallet-chain-api`: modular chain and settlement capability traits.
- `hns-wallet-hns`: Handshake account/name workflows and node backend.
- `hns-wallet-provider`: hostile-page request, permission, and approval core.
- `hns-wallet-shakedex`: persisted fixed-price seller/buyer state machines.
- `hns-wallet-market`: price-bound reservations and atomic-swap recovery.
- `hns-wallet-bitcoin-kyoto`: BDK/Kyoto wallet, separated swap keys, and Bitcoin HTLC adapter.
- `hns-wallet-ethereum`: Helios policy and native-ETH-only HTLC adapter.
- `hns-wallet-ffi`: ABI v2 framing, canonical service IDs, approval prompts, and events.
- `hns-wallet-service`: private session/authority registry and subprocess composition boundary.
- `hns-wallet-testkit`: deterministic, non-mainnet fixtures.

Run `scripts/check.sh` once for the complete local qualification gate.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Provider API](docs/PROVIDER_API.md)
- [Persistence and recovery](docs/PERSISTENCE_AND_RECOVERY.md)
- [Handshake node RPC adapter](docs/HNS_NODE_RPC.md)
- [Bitcoin Kyoto-only module](docs/BITCOIN_KYOTO.md)
- [Ethereum model and contract](docs/ETHEREUM.md)
- [Shakedex and market state](docs/SHAKEDEX_AND_MARKET.md)
- [Wallet service ABI v2](docs/ABI.md)
- [Qualification matrix](docs/QUALIFICATION.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)
- [Future work and excluded features](FUTURE_WORK.md)
