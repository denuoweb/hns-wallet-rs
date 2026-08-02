# Architecture

`hns-wallet-rs` is an independent release boundary. It does not absorb the
Handshake protocol library, full node, DANE trust engine, or browser products.

```text
hostile website
  -> browser authority: exact logical origin + namespace + generations
  -> browser provider bridge: bounded typed request only
  -> hns-wallet-ffi: version/session/request validation
  -> hns-wallet-provider: permission, replay, rate, approval policy
  -> wallet application: HNS / Shakedex / market workflow
  -> capability-specific chain module
  -> verified local chain evidence
  -> encrypted workflow journal before irreversible broadcast
```

Canonical Handshake transactions, covenants, scripts, Urkel proofs, Shakedex
proofs, and Denuo wire objects remain in released `hns-rs` crates. Node indexes
and Denuo relay stores remain in `hns-node-rs`. Provider-injection authority
remains in `hns-dane-engine`. Browser JavaScript and platform UI remain in the
browser repositories. This workspace owns keys, encrypted local state, wallet
semantics, approvals, and recoverable application workflows.

## Crate boundaries

| Crate | Owns | Must not own |
| --- | --- | --- |
| `hns-wallet-types` | IDs, integer amounts, capabilities, UI-safe summaries | consensus/wire types |
| `hns-wallet-store` | schema, migrations, secret AEAD, workflow CAS, replay rows | browser storage or remote truth |
| `hns-wallet-chain-api` | separate core, UTXO, account, and settlement capabilities | universal chain assumptions |
| `hns-wallet-hns` | HNS key roles, address/coin/name evidence and workflows | canonical encodings |
| `hns-wallet-provider` | hostile-input parsing, origin grants, approvals, events | JavaScript injection |
| `hns-wallet-shakedex` | fixed-price buyer/seller recovery state | proof codecs |
| `hns-wallet-market` | reservations and evidence-driven cross-chain sessions | chain networking |
| `hns-wallet-bitcoin-kyoto` | BDK descriptor wallet, Kyoto P2P, Bitcoin HTLC | alternate backends |
| `hns-wallet-ethereum` | native ETH, selected Helios policy, approved HTLC | general Ethereum provider |
| `hns-wallet-ffi` | versioned typed host frames | raw keys/native commands |
| `hns-wallet-testkit` | deterministic non-mainnet fixtures | production configuration |

Every maintained repository keeps its own lockfile, tests, and release. There
are no sibling-checkout dependencies. A newly added `hns-rs` protocol crate
must be released or referenced by an immutable commit before a wallet release
can consume it.

## Evidence authority

Peer statements, Denuo gossip, RPC status fields, and browser page messages are
hints. A safety-critical transition requires evidence from the corresponding
validated chain adapter. State machines accept explicit verified-evidence
variants and persist a compare-and-swap revision before the enclosing runtime
broadcasts an irreversible transaction.

The current implementation does not yet contain that complete enclosing
runtime for every chain. See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Future chains

A future UTXO module implements `ChainModule`, `UtxoChainModule`, and
`AtomicSettlement`. An account chain implements the applicable traits. The
market session is expressed only in module IDs, integer amounts, frozen terms,
hashlocks, timeout policies, and verified evidence. Adding a module does not
change provider method names or the market state machine. A pair is advertised
only after its complete success, restart, reorg, malicious-peer, and refund
qualification suite passes.
