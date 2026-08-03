# Shakedex and cross-chain market

## Fixed-price Shakedex

The crate preserves the encrypted compare-and-swap seller, buyer, and recovery
schemas and their historical transition ordering for persisted-state
compatibility. It does not expose an executable Shakedex workflow. The released
`hns-swap` v0.1 proof envelope is decoded only as a structural legacy format;
that decode does not verify signatures, network, current ownership, locking
coins, or canonical V2 listing identity and cannot authorize a transition.

Three compile-time gates are immutable and `false`:
`SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED`,
`SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED`, and
`SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED`. `SellerSession::new`,
`SellerSession::apply`, `BuyerSession::discover`, and `BuyerSession::apply`
check these gates before validation or mutation. Existing sessions restored
from legacy persisted records therefore cannot bypass the boundary.

A published coherent canonical V2 protocol dependency, canonical NameState and
resource decoding, a separately persisted bounded `HnsName` key-role scan,
signed name transfer/finalize and fulfillment/recovery construction, concrete
node evidence, live Denuo V2 publication and discovery, trusted browser
approval, and restart/reorg/regtest qualification are required before any gate
can change. Imported names remain watch-only, and node-supplied owner/resource
hints cannot authorize seller actions. Reverse Dutch is deferred.

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
