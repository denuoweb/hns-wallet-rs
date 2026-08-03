# Implementation status

Snapshot: 2026-08-02. The production-hardening source boundary is implemented;
the executable wallet product is not yet release-qualified. HNS send and
settlement, Bitcoin send/settlement, and Ethereum synchronization/history/send/
settlement are hard-disabled on every network, and mainnet settlement remains
disabled independently.

| Deliverable | Implemented source | Required before availability |
| --- | --- | --- |
| Standalone workspace | 13 crates, resolver 3, Rust 1.89, independent lockfile, no sibling paths | release CI and published artifacts |
| Wallet types | persisted IDs unchanged; dedicated nonzero base64url service/session/handle/request/approval IDs with redacted diagnostics; decimal integer amounts, roles and capabilities | API stabilization review |
| Store | schema v3; Argon2id and XChaCha20-Poly1305; encrypted typed entities/workflows/provider records; metadata-bound AEAD; bounded heterogeneous CAS batches; non-consuming authenticated approval reads; atomic unchanged-approval consume plus workflow/reservation CAS; bounded passphrase input, approvals and replays; monotonic permission tombstones; migration checkpoint; Linux file-boundary enforcement | platform key wrapping, supported secure-open policy on non-Linux targets, migration/import tooling for populated schema-v1 entity tables, DB benchmarks and audit |
| HNS | create/restore, separated keys, BLAKE2b-160 version-0 addresses, authenticated loopback `hns-node-rs` wallet RPC v1 adapter, separate bounded coin and `HnsName` queries under one exact chain/mempool snapshot, encrypted monotonic name scan state, restore/history/reorg reconciliation, ordered spender evidence, optional exact time/transaction positions, exact current/proof NameState bytes, send construction/signing, exact final-signed fee-quote schema and persistence, pre-submission re-quote with durable `RequiresRebroadcast`, atomic account/workflow/input reservation preparation, watch-only split name evidence, canonical HTLC construction/spends, settlement evidence and restart supervision | consolidated adapter CI plus regtest/restart/reorg/adversarial/name-scan qualification, released `hns-script` canonical sigop-adjusted fee algebra, released canonical NameState/resource decoder before ownership actions, published canonical settlement profile |
| Provider | exact 43-name vocabulary, secure origin, opaque authority registry, authority-validated permission/tombstone snapshots, typed capability snapshot, ephemeral approvals/replay/rates, forbidden methods | published engine authority adapter, browser-native dispatch, atomic real `hns_requestAccounts` join, and complete trusted approval UI |
| Shakedex | encrypted/CAS seller, buyer, and recovery schemas; structural legacy v0.1 proof decoding; all creation, discovery, and transition entrypoints hard-disabled | published coherent canonical V2 protocol dependency, signed transaction construction, live node/Denuo V2 integration, trusted approval UI, restart/reorg/regtest qualification |
| Denuo market | chain-neutral reservations/sessions; canonical V2 protocol implemented in `hns-rs` | released protocol dependency, reporter governance, live relay/board integration |
| Bitcoin | BDK BIP84 create/load/receive/send primitives; deterministic domain/network/role-separated atomic-swap keys with public recovery vectors; bounded Kyoto tip discovery and supervisor; encrypted birthday/phase/checkpoint journal; BDK-first restart reconciliation; bounded transaction/output mirrors; exact fee-bound pre-broadcast journal; HTLC funding/spend/evidence units | pinned Kyoto durable header/filter/peer API, record archival, durable swap-key allocation, signed-spend/settlement integration, consolidated CI, regtest/restart/reorg/adversarial qualification and benchmarks; value gate remains false |
| Ethereum | separated offline accounts, typed dormant EIP-1559/HTLC and structural evidence primitives, deterministic contract, immutable false synchronization/value/settlement/mainnet gates, opaque runtime permits plus role/address/exact-fee-bound signing types, zeroizing preimages/intermediates, redacted controlled-broadcast artifact | embedded Helios proof source and privately minted evidence authority, persistence/balance/history/nonce/fee/broadcast runtime, redeem/refund verification, local-chain/restart/reorg qualification, approved address and audit |
| FFI/service/host | ABI v2; canonical framing; random host/service/wallet sessions; one typed provider binding; authority-scoped private capability snapshot distinct from the public website capability result; bounded typed frames; fail-closed subprocess; caller-side owned clock/entropy, hello/restart and dual-direction sequence state, bounded response correlation, authority/approval/binding/event replay state; Draft 2020-12 private/public/manifest schema bundle and bounded vectors | signed released service artifact and verifier trust store, private Chromium launcher and exact capability projection, generated JNI/Swift bindings, published engine join and compatibility E2E; provider/value/browser capability gates remain false |
| Testkit | deterministic non-mainnet, hostile-input, reorg, and qualification fixtures | full multi-process network harnesses |
| Browser products | authority and adapter work lives in separate repositories | installed-extension/native-host and signed-device qualification |

## HNS value release gate

`HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` is `false`. Runtime configuration rejects
`value_operations_enabled` or `settlement_enabled`, and capability discovery
does not advertise those paths.

Send and settlement-lock preparation now authenticate every current revision,
then atomically commit account change-index advancement, the prepared workflow,
and all input reservations in one bounded SQLite transaction. Duplicate
`(entity kind, record ID)` operations and stale revisions abort the whole batch.
The runtime cache changes only after commit, so failures neither burn addresses
nor reuse a change key nor leave an invisible losing workflow.

Ordinary send and the exposed settlement lock, HTLC redeem, and HTLC refund
paths are wired to quote the exact final signed bytes. Approval remains pending
until signing and quote validation succeed; one atomic store transaction then
consumes the unchanged approval, persists the authorized bytes and quote, and
activates reservations. Submission re-quotes only those persisted bytes and
durably records the refreshed quote plus `RequiresRebroadcast` first. A stale
or unavailable quote input gets one full reconciliation and one retry, never a
polling loop. Name transfer and FINALIZE transaction construction are not
exposed by this wallet source and are not claimed complete.

Other exact blockers are:

- the concrete authenticated loopback adapter is integrated in source, but its
  consolidated CI, multi-process regtest, restart/reorg, malformed-transport,
  stale-cursor, and resource qualification evidence is not yet recorded;
- coinbase identity is preserved but coinbase outputs remain unselectable until
  released canonical maturity evidence is integrated and qualified;
- the builder's weight-based fee remains provisional and the exact node quote
  is the final source boundary, but released `hns-script` 0.1 does not expose
  canonical sigop-adjusted policy-size/fee algebra for the wallet's independent
  minimum-fee check; `HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` remains false
  and the wallet does not copy the node formula;
- the separately persisted, bounded `HnsName` derivation scan is source-only
  and unqualified, and a released canonical NameState/resource decoder does not
  exist; imported names are therefore explicitly watch-only and owner/resource
  assertions are unavailable;
- the canonical `hns-swap` 0.2 / commit `b664` settlement profile is not a
  published dependency under this repository's released-dependency policy;
- platform key wrapping, secure approval UI, browser/native-host integration,
  and non-Linux secure persistent database opening are unavailable; and
- regtest, restart/reorg, installed-product, resource, and independent security
  qualification have not been recorded for this source tranche.

## Shakedex release gates

`SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED`,
`SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED`, and
`SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED` are `false`. Seller creation and
transition and buyer discovery and transition return an explicit unavailable
error before validation, decoding, persistence, or mutation. This also blocks
sessions restored from legacy persisted records. Released `hns-swap` v0.1
proof decoding is structural migration compatibility only and is not protocol,
ownership, listing, or value authorization.

## Bitcoin value release gate

`BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED` is `false`. Bitcoin receive address
derivation and source-level history remain discoverable, but capability output
does not advertise send or atomic settlement and the private value permit
cannot be constructed.

The dormant broadcast boundary requires a durable ready scan, a running Kyoto
node, configured peer quorum, owned unspent inputs, BDK-calculated exact fee,
and a canonical approval commitment over network, txid, wtxid, exact fee, fee
maximum, and exclusive expiry. Native-send signing and broadcast both require
the unavailable permit. It journals `submission_started` before the bounded
Kyoto request and applies the rebroadcast interval before retrying an ambiguous
submission.

The pinned `bip157` 0.6.3 source ignores `data_dir`; exact headers, compact-
filter headers/filters, and address-book state are not durably exposed. A
reviewed persistence-capable Kyoto boundary, safe archival at the 4,096-record
lifetime caps, durable per-session swap-key allocation, signed HTLC spend
supervision, regtest/restart/reorg/adversarial evidence, trusted-time policy,
resource measurements, and independent review remain blockers. The new
domain-separated swap-key source and its unexecuted conformance tests do not
change the false value-release gate.

## Ethereum containment gates

`ETHEREUM_SYNC_RUNTIME_RELEASE_QUALIFIED`,
`ETHEREUM_VALUE_RUNTIME_RELEASE_QUALIFIED`,
`ETHEREUM_SETTLEMENT_RUNTIME_RELEASE_QUALIFIED`, and
`ETHEREUM_MAINNET_RUNTIME_RELEASE_QUALIFIED` are `false`. Capability output
advertises offline receive derivation only. Public acquisition cannot issue the
opaque permits required for native-transfer or HTLC construction, exact-fee-
bound signing, or authoritative Helios lock evidence. Helios provenance has no
public release-flag acquisition path, and verification also requires the
settlement permit. Signed bytes remain in a zeroizing, redacted opaque artifact
without a public raw accessor. Chain ID 1 is rejected regardless of the legacy
serialized policy flag.

The checked-in evidence structs and contract remain dormant structural source.
They do not implement synchronization, balance/history/nonce/fee discovery,
broadcast, persistence/recovery, redeem/refund proof verification, or rollback.
Caller-provided verification booleans cannot become a verified settlement lock.

## Evidence statement

The earlier 2026-08-02 baseline passed 34 Rust tests and its complete local
gate. This production-hardening tranche was intentionally not rebuilt or tested
locally while being authored; that baseline must not be presented as evidence
for this commit. Run `scripts/check.sh` once in CI (or once as the consolidated
local gate) and record the resulting commit ID and artifacts in
[`QUALIFICATION.md`](QUALIFICATION.md).
The new provider/ABI/service/host contract tests and machine-readable vectors
are source-only and remain unrun.

## Deferred by design

Reverse-Dutch offers, arbitrary Bitcoin applications, generic Ethereum dapps,
tokens/NFTs/DeFi/staking, `window.ethereum`, WalletConnect, user-added chains or
contracts, browser contract deployment, hosted Bitcoin backends, crawler/
bootstrap expansion, and enabling any future chain pair without full
qualification are out of scope.
