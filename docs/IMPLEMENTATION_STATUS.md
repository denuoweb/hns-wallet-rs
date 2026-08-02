# Implementation status

Snapshot: 2026-08-02. The production-hardening source boundary is implemented;
the executable wallet product is not yet release-qualified. HNS send and
settlement and Bitcoin send/settlement are hard-disabled on every network, and
mainnet settlement remains disabled independently.

| Deliverable | Implemented source | Required before availability |
| --- | --- | --- |
| Standalone workspace | 11 crates, resolver 3, Rust 1.89, independent lockfile, no sibling paths | release CI and published artifacts |
| Wallet types | IDs, decimal integer amounts, roles, capabilities, UI-safe status | API stabilization review |
| Store | schema v3; Argon2id and XChaCha20-Poly1305; encrypted typed entities/workflows/provider records; metadata-bound AEAD; bounded heterogeneous CAS batches; bounded passphrase input, approvals and replays; monotonic permission tombstones; migration checkpoint; Linux file-boundary enforcement | platform key wrapping, supported secure-open policy on non-Linux targets, migration/import tooling for populated schema-v1 entity tables, DB benchmarks and audit |
| HNS | create/restore, separated keys, BLAKE2b-160 version-0 addresses, authenticated loopback `hns-node-rs` wallet RPC v1 adapter, bounded paginated atomic snapshots, durable chain epoch and restart-safe mempool instance/generation binding, restore/history/reorg reconciliation, ordered spender evidence, optional exact time/transaction positions, exact current/proof NameState bytes, send construction/signing, atomic account/workflow/input reservation preparation, watch-only split name evidence, canonical HTLC construction/spends, settlement evidence and restart supervision | consolidated adapter CI plus regtest/restart/reorg/adversarial qualification, released canonical NameState/resource decoder plus dedicated HNS-name key scan before ownership actions, published canonical settlement profile |
| Provider | exact secure origin, authority/session generations, monotonic permission generations and revocation tombstones, bounded encrypted approvals/replays, rate limits, forbidden methods | browser/native runtime dispatch and complete trusted approval UI |
| Shakedex | persisted seller/buyer/recovery state machines and canonical proof decoding | complete signed transaction construction, live node/Denuo integration, restart/reorg/regtest qualification |
| Denuo market | chain-neutral reservations/sessions; canonical V2 protocol implemented in `hns-rs` | released protocol dependency, reporter governance, live relay/board integration |
| Bitcoin | BDK BIP84 create/load/receive/send primitives; deterministic domain/network/role-separated atomic-swap keys with public recovery vectors; bounded Kyoto tip discovery and supervisor; encrypted birthday/phase/checkpoint journal; BDK-first restart reconciliation; bounded transaction/output mirrors; exact fee-bound pre-broadcast journal; HTLC funding/spend/evidence units | pinned Kyoto durable header/filter/peer API, record archival, durable swap-key allocation, signed-spend/settlement integration, consolidated CI, regtest/restart/reorg/adversarial qualification and benchmarks; value gate remains false |
| Ethereum | separated accounts, typed EIP-1559 native/HTLC signing, Helios policy, exact code/state/receipt/event checks, deterministic contract | embedded Helios proof source, persistence/history, local-chain qualification, approved address and audit |
| FFI | versioned bounded typed frames; Chromium phrase denial | generated JNI/Swift/Chromium bindings and compatibility E2E |
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

Other exact blockers are:

- the concrete authenticated loopback adapter is integrated in source, but its
  consolidated CI, multi-process regtest, restart/reorg, malformed-transport,
  stale-cursor, and resource qualification evidence is not yet recorded;
- coinbase identity is preserved but coinbase outputs remain unselectable until
  released canonical maturity evidence is integrated and qualified;
- the node fee estimate is denominated per 1,000 HSD policy virtual bytes,
  while the dormant wallet builder still sizes by transaction weight;
  canonical sigop-adjusted sizing must replace that mismatch before value
  enablement;
- a released canonical NameState/resource decoder and a separately persisted,
  bounded `HnsName` derivation scan do not exist; imported names are therefore
  explicitly watch-only and owner/resource assertions are unavailable;
- the canonical `hns-swap` 0.2 / commit `b664` settlement profile is not a
  published dependency under this repository's released-dependency policy;
- platform key wrapping, secure approval UI, browser/native-host integration,
  and non-Linux secure persistent database opening are unavailable; and
- regtest, restart/reorg, installed-product, resource, and independent security
  qualification have not been recorded for this source tranche.

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

## Evidence statement

The earlier 2026-08-02 baseline passed 34 Rust tests and its complete local
gate. This production-hardening tranche was intentionally not rebuilt or tested
locally while being authored; that baseline must not be presented as evidence
for this commit. Run `scripts/check.sh` once in CI (or once as the consolidated
local gate) and record the resulting commit ID and artifacts in
[`QUALIFICATION.md`](QUALIFICATION.md).

## Deferred by design

Reverse-Dutch offers, arbitrary Bitcoin applications, generic Ethereum dapps,
tokens/NFTs/DeFi/staking, `window.ethereum`, WalletConnect, user-added chains or
contracts, browser contract deployment, hosted Bitcoin backends, crawler/
bootstrap expansion, and enabling any future chain pair without full
qualification are out of scope.
