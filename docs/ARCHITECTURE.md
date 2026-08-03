# Architecture

`hns-wallet-rs` is an independent release boundary. It does not absorb the
Handshake protocol library, full node, DANE trust engine, or browser products.

```text
hostile website
  -> browser engine authority retained by platform adapter
  -> hns-wallet-host: owned clock/entropy, opaque handle, request correlation
  -> hns-wallet-ffi v2: length/session/restart/sequence validation
  -> hns-wallet-service: handle/revision/event/approval lifecycle
  -> hns-wallet-provider: origin permission, replay, rate, approval policy
  -> wallet application: HNS / Shakedex / market workflow
  -> capability-specific chain module
  -> verified local chain evidence
  -> encrypted workflow journal before irreversible broadcast
```

Canonical Handshake transactions, covenants, scripts, Urkel proofs, Shakedex
proofs, signed fixed-price listings/cancellations, and Denuo name-market
envelopes remain in `hns-rs`. This workspace consumes the required protocol
crates from reviewed immutable revision `4b989aa`; its exact source and lock
coherence are checked before the workspace gate. The wallet owns only the
protocol-verification boundary and encrypted replay/tombstone board state. Node
indexes and Denuo relay stores remain in `hns-node-rs`. Provider-injection authority
remains in `hns-dane-engine`. Browser JavaScript and platform UI remain in the
browser repositories. This workspace owns keys, encrypted local state, wallet
semantics, approvals, and recoverable application workflows.

## Crate boundaries

| Crate | Owns | Must not own |
| --- | --- | --- |
| `hns-wallet-types` | IDs, integer amounts, capabilities, UI-safe summaries | consensus/wire types |
| `hns-wallet-store` | schema, migrations, typed record AEAD, workflow/entity CAS and atomic batches, complete bounded binary-prefix entity and opaque-workflow reads, atomic approval-consume/workflow/reservation commits, provider permission tombstones, persisted workflow approvals/replays | browser storage, ABI v2 authority handles, or remote truth |
| `hns-wallet-chain-api` | separate core, UTXO, account, and settlement capabilities | universal chain assumptions |
| `hns-wallet-hns` | HNS key roles, address/coin/name evidence and workflows | canonical encodings |
| `hns-wallet-provider` | hostile-input parsing, bounded opaque-handle registry, origin grants, ephemeral approvals/replay/rate | engine policy or JavaScript injection |
| `hns-wallet-shakedex` | fixed-price buyer/seller recovery state, exact listing/cancellation protocol verification, canonical Denuo adapter, encrypted sequence/tombstone board | proof/listing/Denuo codecs or caller-asserted chain truth |
| `hns-wallet-market` | reservations and evidence-driven cross-chain sessions | chain networking |
| `hns-wallet-bitcoin-kyoto` | BDK descriptor wallet, domain-separated swap keys, bounded Kyoto P2P supervisor/recovery journal, Bitcoin HTLC | alternate backends or claims of unavailable Kyoto persistence |
| `hns-wallet-ethereum` | offline native-ETH account derivation and release-gated Helios/HTLC policy | general Ethereum provider or caller-asserted proof authority |
| `hns-wallet-ffi` | strict ABI v2 framing, canonical service IDs, typed approvals/events | raw keys/native commands or engine authority objects |
| `hns-wallet-service` | random service/wallet sessions, exact sequences, private host control, permission-backed provider composition, runtime-selected atomic HNS account grant and minimized persisted account projection | concrete HNS runtime composition, browser engine policy, or availability claims |
| `hns-wallet-host` | host-owned negotiation, identifiers/nonces, bounded request correlation, authority revisions, approval ownership, private provider bindings, and event replay cursors | platform process launch, engine policy, page injection, artifact trust, or availability claims |
| `hns-wallet-testkit` | deterministic non-mainnet fixtures | production configuration |

Every maintained repository keeps its own lockfile, tests, and release. There
are no sibling-checkout dependencies. A newly added `hns-rs` protocol crate
must be released or referenced by an immutable commit before a wallet release
can consume it.

The machine-readable contract bundle under `abi/` describes strict private
ABI-v2 JSON payloads, the private capability snapshot, public approval/event
projections, and signed-artifact manifest structure. It is an interface source,
not an executable runtime, generated platform binding, trusted signing key, or
artifact verifier. The browser and mobile repositories still own their outer
transport wrappers and independently qualified platform integration.

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
Confirmed wallet coins retain exact inclusion height and canonical covenant
bytes through encrypted persistence. Final transactions are checked against
the ordered reconstructed consensus coins: immutable `hns-script` 0.2 computes
sigops, policy virtual size, minimum fee, and standard weight/sigop bounds,
while exact input/output sums independently reproduce actual fee. Legacy or
mismatched evidence fails closed. This source has not passed consolidated
wallet qualification, so `HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` remains
false; no local copy of the node formula is used.

Name evidence deliberately preserves the interval-committed Urkel proof/state/
owner view separately from the node's current state/owner view. The proof root
and height must exactly equal the bound tip. Ordinary HNS coin branches and the
domain-separated `HnsName` branch are scanned in separate bounded queries that
must share the exact chain epoch/tip and mempool instance/generation. Name-role
outputs may enter history but are excluded from ordinary balance, selection,
reservation, and spendability. The wallet independently decodes both raw
NameState views, compares every node projection, binds owner txid/index/value/
name covenant and typed TRANSFER/FINALIZE shape, and accepts current resource
bytes only from the decoded state. Current control is attributed only when the
owner address exactly matches a persisted `HnsName` program; incoming and
outgoing transfers are distinguished. Reconciliation replaces this encrypted
cache across restart/reorg, while legacy rows stay explicitly watch-only until
fresh evidence succeeds. Cache state cannot authorize an action: the runtime
must reacquire a non-serializable authority at the exact current snapshot.

Wallet-owned name actions additionally consume the node's versioned
`name_action_context` for the exact chain epoch, tip, mempool instance and
generation. The wallet independently binds chain identity, candidate height,
canonical state, owner transaction and active-chain inclusion, fixed ordered
ineligibility reasons, owner mempool spender, transfer lockup, FINALIZE
maturity, and the HSD-selected active-chain renewal block. TRANSFER preserves
the name value at canonical input/output zero. Direct FINALIZE derives its
destination from the authenticated TRANSFER covenant and is signed by the
outgoing owner's `HnsName` key; incoming-recipient classification is not
signing authority.

Name workflow IDs deterministically bind account, action, and request nonce.
Preparation atomically saves the encrypted workflow plus separately typed name
source and ordinary fee-input reservations. Authorization consumes one exact
approval, retains final signed bytes and fee evidence before broadcast, and
reconciliation reports broadcast, mempool, transfer lock, finalize eligibility,
finalization, transfer cancellation, conflict, rebroadcast, and reapproval
states. Reservations for a broadcast name action remain attached across
confirmed states so a later reorg cannot silently free returned inputs.
Authority reacquisition permits a newer chain or mempool snapshot only when the
owner source and every transaction-defining action term remain unchanged. The
wallet reacquires again against the final fee quote's exact snapshot before it
persists or submits signed bytes; changed source or FINALIZE renewal terms move
the workflow to `ReapprovalRequired` for explicit cancellation and replacement.

The concrete synchronous HNS adapter now speaks the authenticated loopback
`hns-node-rs` wallet RPC v1 boundary, pinned to node commit `e5f95c05`. It
derives canonical ScriptIds, enforces full chain/mempool bindings, and validates
HTTP, JSON, transaction, spender, and name evidence without giving the node
signing authority. The complete enclosing product runtime and qualification
evidence are still pending. `HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` therefore
remains false and HNS value capabilities are not advertised. See
[HNS_NODE_RPC.md](HNS_NODE_RPC.md) and
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Bitcoin supervisor boundary

Bitcoin ordinary receive/change keys remain exclusively in BDK's BIP84
descriptor trees. Durable atomic-swap allocations use a distinct wallet-private
HKDF-SHA256 domain over the recovery seed and bind the wallet profile, session,
opaque frozen-terms commitment, coin type, exact network, bounded account/index,
and receiver/refund role. The swap derivation therefore never traverses or
allocates an ordinary BIP84 child, and an independently restored counter cannot
reuse a key for a different logical swap. One encrypted CAS batch advances a
monotonic high-water record and writes an immutable wallet/session/role binding;
redundant namespace-anchor and binding-claim records detect isolated missing or
relocated records. Exact retries are idempotent, role rebinding and clock
rollback fail closed, and recovery recomputes the public key before exposing
the non-serializable, zeroizing secret handle. The role-aware HTLC constructor
accepts that handle rather than a deserializable public record.

This is an allocation primitive, not a value-path integration. The settlement
layer must construct the opaque commitment from its complete canonical terms
and must never recycle a session ID. A whole encrypted-database rollback cannot
be detected solely by records inside that database; session-bound derivation
prevents cross-session key reuse, but recovery of already active swaps still
requires a current encrypted database backup. The byte-level scheme and
persistence boundary are documented in [BITCOIN_KYOTO.md](BITCOIN_KYOTO.md).
Signed-spend supervision and complete restart/reorg qualification remain
release blockers.

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

## Ethereum containment boundary

Ethereum currently exposes only deterministic offline account/receive
derivation. Its synchronization, value-runtime, settlement-runtime, and
mainnet qualification constants are immutable and false; history shares the
synchronization gate. Capability discovery therefore advertises no online or
value path. Native-transfer and HTLC
construction/signing require opaque permits that the current source cannot
issue, and signing additionally binds the derived key role/address and an exact
approved maximum fee. The resulting bytes remain in a non-cloneable,
zeroizing, redacted controlled-broadcast artifact with no public raw accessor.
Chain ID 1 is rejected regardless of caller policy.

Serializable execution observations remain structural fixtures, not proof
authority. No release-flag-based public Helios provenance issuer exists; only a
future embedded verifier may construct the opaque evidence permit needed to
return an authoritative verified lock, and settlement permission is also
required. This prevents
ordinary JSON-RPC fields or caller-set booleans from advancing settlement while
Helios proof production, persistence, rollback recovery, deployment approval,
and qualification are absent.

## Future chains

A future UTXO module implements `ChainModule`, `UtxoChainModule`, and
`AtomicSettlement`. An account chain implements the applicable traits. The
market session is expressed only in module IDs, integer amounts, frozen terms,
hashlocks, timeout policies, and verified evidence. Adding a module does not
change provider method names or the market state machine. A pair is advertised
only after its complete success, restart, reorg, malicious-peer, and refund
qualification suite passes.
