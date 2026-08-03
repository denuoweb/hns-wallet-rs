# Shakedex and cross-chain market

## Fixed-price Shakedex

The crate preserves the encrypted compare-and-swap seller, buyer, and recovery
schemas and their historical transition ordering for persisted-state
compatibility. It does not expose an executable Shakedex workflow. The wallet
dependency boundary now consumes the canonical V2 `hns-swap` source from
immutable revision `4b989aa`; the complete signed fixed-price listing envelope
is decoded only for bounded structural inspection. Decoding verifies the
envelope signature, its embedded claimed hash, and the caller-supplied listing
identity. It does not verify the current network/time window, current ownership,
or locking coin and cannot authorize a transition.

Three compile-time gates are immutable and `false`:
`SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED`,
`SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED`, and
`SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED`. `SellerSession::new`,
`SellerSession::apply`, `BuyerSession::discover`, and `BuyerSession::apply`
check these gates before validation or mutation. Existing sessions restored
from legacy persisted records therefore cannot bypass the boundary.

The wallet now has coherent canonical V2 source plus exact NameState/resource/
owner-output validation and ephemeral account ownership authority. Those are
prerequisites, not Shakedex authorization. Wallet-owned P2PKH TRANSFER/direct
FINALIZE is implemented behind HNS gates, but Shakedex cannot reuse that
authority. Locked-name/script-controlled transfer/finalize, fulfillment and
recovery construction, live Denuo V2 publication/discovery, trusted browser
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

Canonical reporter observations, quorum rounds, intents, fill grants, and swap
messages live in the new `hns-marketplace-protocol` release boundary in
`hns-rs`. The wallet cannot consume that unreleased crate by sibling path.
Price governance, reporter enrollment, outlier/circuit-breaker qualification,
peer cooldown/scoring, and bounded board integration remain blocked on a
released immutable protocol dependency and node/browser integration.
