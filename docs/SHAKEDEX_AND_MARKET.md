# Shakedex and cross-chain market

## Fixed-price Shakedex

The crate preserves the encrypted compare-and-swap seller, buyer, and recovery
schemas and their historical transition ordering for persisted-state
compatibility. It does not yet expose an executable value workflow. The wallet
dependency boundary consumes the canonical V2 `hns-swap` and
`hns-marketplace-protocol` source from the same immutable revision `4b989aa`.
It does not reproduce listing hashes, signatures, Shakedex scripts, presigns,
cancellations, or Denuo envelopes.

The canonical protocol-verification boundary decodes a bounded fixed-price
listing, requires its exact content hash, and calls
`FixedPriceListing::verify_for_network` with
the selected network, current time, and exact supplied locking coin. This
protocol authority has private fields and is neither cloneable nor
serializable, but it does not prove that the supplied coin is currently
unspent; the value runtime must obtain that evidence from the authenticated
HNS adapter. A cancellation is accepted only through
`ListingCancellation::verify_for_listing`. Its signed listing target can be
re-authenticated from persisted canonical bytes after restart or a lock spend,
without pretending those bytes prove current ownership. Denuo offer and
cancellation decoders return typed protocol results rather than
unauthenticated wire objects.

The encrypted `DenuoBoardObject` namespace now has a versioned, bounded board
reducer and CAS load/save boundary. It persists canonical listing and
cancellation bytes, content hashes, network/genesis, name hash, seller key,
expiry, and per-seller/name sequence watermarks. One current record is retained
per identity; a higher sequence replaces it without consuming another slot.
Exact repeats are idempotent; sequence rollback, replay after a tombstone,
registry substitution, corrupt restart state, and board overflow fail closed.
Inventory contains only active, unexpired content hashes. Watermarks remain
durable after expiry to preserve the protocol's monotonic sequence rule. The
board therefore refuses a 4,097th distinct seller/name identity; bounded
archival/admission policy is still required before live relay enablement.
Persisted board objects are re-decoded on load, but they remain cache data:
every purchase or value action must reacquire fresh locking-coin and chain
evidence.

Three compile-time gates are immutable and `false`:
`SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED`,
`SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED`, and
`SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED`. `SellerSession::new`,
`SellerSession::apply`, `BuyerSession::discover`, and `BuyerSession::apply`
check these gates before validation or mutation. Existing sessions restored
from legacy persisted records therefore cannot bypass the boundary.
The Denuo gate governs live transport, relay publication, and product
discovery. Offline canonical envelope parsing and encrypted cache reduction do
not enable those runtime paths or advertise the feature.

The wallet now has coherent canonical V2 source plus exact NameState/resource/
owner-output validation and ephemeral account ownership authority. Those are
prerequisites, not Shakedex authorization. Wallet-owned P2PKH TRANSFER/direct
FINALIZE is implemented behind HNS gates, but Shakedex cannot reuse that
authority. Locked-name/script-controlled transfer/finalize, wallet-owned typed
signing, funded fulfillment and recovery orchestration, authenticated
parent-MTP and unspent-coin evidence, live Denuo transport, trusted browser
approval, consolidated protocol qualification, and restart/reorg/regtest
evidence are still required before any gate can change. Reverse Dutch is
deferred.

## Market intents and sessions

Market intents freeze offered/received integer amounts and a verified price-
round hash. Reservations enforce expiration, partial-fill policy, available
quantity, monotonic sequences, and double-reservation prevention. Peers cannot
advance a swap by claiming funding/redeem/refund; only verified evidence can.

The session state includes terms frozen, refunds prepared, first/second funding,
both funded, first redemption, secret observation, second redemption,
completion, refund eligibility/broadcast/refunded, and terminal failure. Timeout
plans require the first refund to exceed the second by a safety margin. The
canonical funding order is the side with the longer refund window first; the
shorter side funds only after sufficient confirmation evidence, preserving time
for secret observation and the first-chain redemption.

HNS/BTC uses SHA-256 native HTLCs on both chains. HNS/ETH uses the HNS script
and the approved native-ETH contract. Neither pair is advertised because full
HNS adapters, Bitcoin signed settlement, Helios runtime evidence, integrated
success/refund/restart/reorg tests, and real-network qualification are absent.
Ethereum synchronization, history, send, authoritative evidence, and settlement
permits are unavailable, and chain ID 1 is rejected unconditionally.

## Price rounds and Denuo

Canonical reporter observations, quorum rounds, intents, fill grants, name
offers, cancellations, and swap messages live in the
`hns-marketplace-protocol` boundary in `hns-rs`. The wallet consumes it only at
the pinned immutable revision, never through a sibling path. The fixed-price
name board now consumes its canonical Denuo envelopes; price governance,
reporter enrollment, outlier/circuit-breaker qualification, peer
cooldown/scoring, and live node/browser relay integration remain unavailable.
