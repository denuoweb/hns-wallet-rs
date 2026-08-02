# Shakedex and cross-chain market

## Fixed-price Shakedex

The wallet consumes canonical `hns-swap` proof decoding. Seller state covers
ownership verification, transfer preparation/broadcast/lock, lock finalization,
fixed-price proof verification, Denuo publication/cancellation, fulfillment,
and recovery back to ownership. Buyer state covers listing/current-name proof,
fulfillment, transfer lock, finalization, conflicting fulfillment, and failure.

Every transition is journaled with a compare-and-swap revision. Recovery is
available from locked, offered, published, and cancelled seller states. Buyer
finalization cannot occur before verified transfer lock.

The orchestration source exists, but ownership transitions are unavailable.
Released protocol crates do not yet decode canonical NameState fields, and the
wallet has no separately persisted bounded `HnsName` key-role scan; imported
names are watch-only and node-supplied owner/resource hints cannot authorize a
seller action. Name transfer/finalize transaction construction, the concrete
node evidence adapter, live Denuo V2 publication, restart-at-every-state/reorg
qualification, and an installed browser approval UI are also unavailable.
Fixed-price Shakedex is therefore release-gated. Reverse Dutch is deferred.

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

## Price rounds and Denuo

Canonical reporter observations, quorum rounds, intents, fill grants, and swap
messages live in the new `hns-marketplace-protocol` release boundary in
`hns-rs`. The wallet cannot consume that unreleased crate by sibling path.
Price governance, reporter enrollment, outlier/circuit-breaker qualification,
peer cooldown/scoring, and bounded board integration remain blocked on a
released immutable protocol dependency and node/browser integration.
