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
| `hns-wallet-store` | schema, migrations, typed record AEAD, workflow/entity CAS and atomic batches, provider tombstones/approvals/replays | browser storage or remote truth |
| `hns-wallet-chain-api` | separate core, UTXO, account, and settlement capabilities | universal chain assumptions |
| `hns-wallet-hns` | HNS key roles, address/coin/name evidence and workflows | canonical encodings |
| `hns-wallet-provider` | hostile-input parsing, origin grants, approvals, events | JavaScript injection |
| `hns-wallet-shakedex` | fixed-price buyer/seller recovery state | proof codecs |
| `hns-wallet-market` | reservations and evidence-driven cross-chain sessions | chain networking |
| `hns-wallet-bitcoin-kyoto` | BDK descriptor wallet, bounded Kyoto P2P supervisor/recovery journal, Bitcoin HTLC | alternate backends or claims of unavailable Kyoto persistence |
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

The HNS adapter boundary requires a stable chain epoch/tip and a nonzero
node-instance nonce plus mempool generation across every bounded page of an
exact sorted wallet-address query. Each query carries canonical address version
and hash; the adapter must convert the exact version-0 `Address` to its node
`ScriptId`, never a bare hash. It also requires transaction/parent-output and
outpoint-spend evidence bound to that same snapshot. A stale cursor, restarted
mempool instance, or generation change restarts the bounded snapshot rather
than combining observations from different views.

HNS preparation authenticates the current account, workflow, and reservation
revisions before atomically committing change-index advancement, the prepared
workflow, and every input reservation. The cache changes only after commit.
Failures therefore cannot burn or reuse a change derivation and cannot leave a
partial losing workflow.

Name evidence deliberately preserves the interval-committed Urkel proof/state/
owner view separately from the node's current state/owner view. The proof root
and height must exactly equal the bound tip. A released canonical NameState
decoder is still required to bind owner, transfer, renewal and resource fields
to those bytes; until it and a dedicated bounded `HnsName` key-role scan exist,
known names are watch-only and raw resource/ownership claims are unavailable.

The concrete synchronous HNS adapter now speaks the authenticated loopback
`hns-node-rs` wallet RPC v1 boundary, pinned to node commit `74f7ae36`. It
derives canonical ScriptIds, enforces full chain/mempool bindings, and validates
HTTP, JSON, transaction, spender, and name evidence without giving the node
signing authority. The complete enclosing product runtime and qualification
evidence are still pending. `HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` therefore
remains false and HNS value capabilities are not advertised. See
[HNS_NODE_RPC.md](HNS_NODE_RPC.md) and
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Bitcoin supervisor boundary

The Kyoto module starts from an explicit validated birthday, persists a
sequence/phase transition before sync, commits each returned update to BDK
SQLite, reconciles encrypted transaction/output mirrors in bounded chunks, and
commits ready last. Crash recovery can resume a pending reconciliation from the
durable BDK tip. A bounded set of previous hashes is checked against Kyoto's
local most-work chain to identify reorg ancestry; an unbounded/deep mismatch
requires recovery.

A signed broadcast record is content-addressed by txid and binds the wallet
network, wtxid, BDK-calculated fee, approved fee maximum, and expiry. The raw
transaction and approval are durable before submission starts. The supervisor
requires ready state, a running node and peer quorum, then records
`submission_started` before its bounded P2P request. Timeouts are retryable from
that record.

The BDK database and encrypted journal are independent durable boundaries, so
ready-last sequencing supplies logical recovery rather than pretending they are
one SQLite transaction. Pinned Kyoto does not durably expose headers, filter
headers/filters, or its address book; those missing objects prevent production
qualification. `BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED` remains false.

## Future chains

A future UTXO module implements `ChainModule`, `UtxoChainModule`, and
`AtomicSettlement`. An account chain implements the applicable traits. The
market session is expressed only in module IDs, integer amounts, frozen terms,
hashlocks, timeout policies, and verified evidence. Adding a module does not
change provider method names or the market state machine. A pair is advertised
only after its complete success, restart, reorg, malicious-peer, and refund
qualification suite passes.
