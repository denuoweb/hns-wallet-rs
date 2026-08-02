# Implementation status

Snapshot: 2026-08-02. The production-hardening source boundary is implemented;
the executable wallet product is not yet release-qualified. HNS send and
settlement are hard-disabled on every network, and mainnet settlement remains
disabled independently.

| Deliverable | Implemented source | Required before availability |
| --- | --- | --- |
| Standalone workspace | 11 crates, resolver 3, Rust 1.89, independent lockfile, no sibling paths | release CI and published artifacts |
| Wallet types | IDs, decimal integer amounts, roles, capabilities, UI-safe status | API stabilization review |
| Store | schema v3; Argon2id and XChaCha20-Poly1305; encrypted typed entities/workflows/provider records; metadata-bound AEAD; bounded heterogeneous CAS batches; bounded passphrase input, approvals and replays; monotonic permission tombstones; migration checkpoint; Linux file-boundary enforcement | platform key wrapping, supported secure-open policy on non-Linux targets, migration/import tooling for populated schema-v1 entity tables, DB benchmarks and audit |
| HNS | create/restore, separated keys, BLAKE2b-160 version-0 addresses, bounded paginated atomic snapshots, restart-safe mempool instance/generation binding, restore/history/reorg reconciliation, send construction/signing, atomic account/workflow/input reservation preparation, watch-only split current/proof name evidence, canonical HTLC construction/spends, settlement evidence and restart supervision | concrete `hns-node-rs` adapter, released canonical NameState/resource decoder plus dedicated HNS-name key scan before ownership actions, published canonical settlement profile, regtest/restart/reorg qualification |
| Provider | exact secure origin, authority/session generations, monotonic permission generations and revocation tombstones, bounded encrypted approvals/replays, rate limits, forbidden methods | browser/native runtime dispatch and complete trusted approval UI |
| Shakedex | persisted seller/buyer/recovery state machines and canonical proof decoding | complete signed transaction construction, live node/Denuo integration, restart/reorg/regtest qualification |
| Denuo market | chain-neutral reservations/sessions; canonical V2 protocol implemented in `hns-rs` | released protocol dependency, reporter governance, live relay/board integration |
| Bitcoin | BDK BIP84 create/load/receive/send, Kyoto client boundary, HTLC funding/spend/evidence units | supervisor integration, broadcast/reorg/regtest/benchmarks |
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

- a concrete adapter implementing the bounded, paginated chain-epoch/tip and
  restart-safe mempool-instance/generation evidence boundary and exact version-0
  Address-to-ScriptId conversion is not integrated or published;
- a released canonical NameState/resource decoder and a separately persisted,
  bounded `HnsName` derivation scan do not exist; imported names are therefore
  explicitly watch-only and owner/resource assertions are unavailable;
- the canonical `hns-swap` 0.2 / commit `b664` settlement profile is not a
  published dependency under this repository's released-dependency policy;
- platform key wrapping, secure approval UI, browser/native-host integration,
  and non-Linux secure persistent database opening are unavailable; and
- regtest, restart/reorg, installed-product, resource, and independent security
  qualification have not been recorded for this source tranche.

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
