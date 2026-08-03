# Architecture

`hns-wallet-rs` is an independent release boundary. It does not absorb the
Handshake protocol library, full node, DANE trust engine, or browser products.

```text
hostile website
  -> browser engine authority retained by native host
  -> private host registry: opaque random authority handle
  -> hns-wallet-ffi v2: length/session/restart/sequence validation
  -> hns-wallet-service: handle/revision/event/approval lifecycle
  -> hns-wallet-provider: origin permission, replay, rate, approval policy
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
| `hns-wallet-store` | schema, migrations, typed record AEAD, workflow/entity CAS and atomic batches, atomic approval-consume/workflow/reservation commits, provider permission tombstones, persisted workflow approvals/replays | browser storage, ABI v2 authority handles, or remote truth |
| `hns-wallet-chain-api` | separate core, UTXO, account, and settlement capabilities | universal chain assumptions |
| `hns-wallet-hns` | HNS key roles, address/coin/name evidence and workflows | canonical encodings |
| `hns-wallet-provider` | hostile-input parsing, bounded opaque-handle registry, origin grants, ephemeral approvals/replay/rate | engine policy or JavaScript injection |
| `hns-wallet-shakedex` | fixed-price buyer/seller recovery state | proof codecs |
| `hns-wallet-market` | reservations and evidence-driven cross-chain sessions | chain networking |
| `hns-wallet-bitcoin-kyoto` | BDK descriptor wallet, domain-separated swap keys, bounded Kyoto P2P supervisor/recovery journal, Bitcoin HTLC | alternate backends or claims of unavailable Kyoto persistence |
| `hns-wallet-ethereum` | native ETH, selected Helios policy, approved HTLC | general Ethereum provider |
| `hns-wallet-ffi` | strict ABI v2 framing, canonical service IDs, typed approvals/events | raw keys/native commands or engine authority objects |
| `hns-wallet-service` | random service/wallet sessions, exact sequences, private host control, permission-backed provider composition | browser engine policy or availability claims |
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

HNS value authorization is additionally bound to an exact final-signed
transaction fee quote. The approval is first read without mutation; signing and
quote validation complete before one store transaction consumes the unchanged
approval, saves the authorized exact bytes and quote, and activates the input
reservations. Broadcast re-quotes only those persisted bytes, saves the
refreshed quote with `RequiresRebroadcast` before submission, and allows at most
one full reconciliation and one retry for stale or unavailable quote evidence.
The released `hns-script` 0.1 API lacks the canonical sigop-adjusted fee algebra
needed to independently verify the quoted minimum, so
`HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` remains false and no local copy of the
node formula is used.

Name evidence deliberately preserves the interval-committed Urkel proof/state/
owner view separately from the node's current state/owner view. The proof root
and height must exactly equal the bound tip. A released canonical NameState
decoder is still required to bind owner, transfer, renewal and resource fields
to those bytes; until it and a dedicated bounded `HnsName` key-role scan exist,
known names are watch-only and raw resource/ownership claims are unavailable.

The concrete synchronous HNS adapter now speaks the authenticated loopback
`hns-node-rs` wallet RPC v1 boundary, pinned to node commit `5ed38d15`. It
derives canonical ScriptIds, enforces full chain/mempool bindings, and validates
HTTP, JSON, transaction, spender, and name evidence without giving the node
signing authority. The complete enclosing product runtime and qualification
evidence are still pending. `HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` therefore
remains false and HNS value capabilities are not advertised. See
[HNS_NODE_RPC.md](HNS_NODE_RPC.md) and
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Bitcoin supervisor boundary

Bitcoin ordinary receive/change keys remain exclusively in BDK's BIP84
descriptor trees. Atomic-swap keys use a wallet-private HKDF-SHA256 domain over
the recovery seed with separately encoded coin type, exact network, bounded
account/index, and receiver/refund role. The swap derivation therefore never
traverses or allocates an ordinary BIP84 child. Only the public half crosses
into HTLC construction, where its declared role selects the exact script
branch. The byte-level scheme and public recovery vectors are documented in
[BITCOIN_KYOTO.md](BITCOIN_KYOTO.md). Allocation persistence and signed-spend
supervision remain release blockers: every session must authenticate and
persist its exact scheme version and coordinates, and deterministic
regeneration is not a bounded discovery scan.

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
