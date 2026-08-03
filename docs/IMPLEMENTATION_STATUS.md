# Implementation status

Snapshot: 2026-08-03. The production-hardening source boundary is implemented;
the executable wallet product is not yet release-qualified. HNS send and
settlement, Bitcoin send/settlement, and Ethereum synchronization/history/send/
settlement are hard-disabled on every network, and mainnet settlement remains
disabled independently.

| Deliverable | Implemented source | Required before availability |
| --- | --- | --- |
| Standalone workspace | 13 crates, resolver 3, Rust 1.89, independent lockfile, no sibling paths | release CI and published artifacts |
| Wallet types | persisted IDs unchanged; dedicated nonzero base64url service/session/handle/request/approval IDs with redacted diagnostics; decimal integer amounts, roles and capabilities | API stabilization review |
| Store | schema v3; Argon2id and XChaCha20-Poly1305; encrypted typed entities/workflows/provider records; metadata-bound AEAD; bounded heterogeneous CAS batches; complete bounded binary-prefix entity and opaque-workflow reads; non-consuming authenticated approval reads; atomic unchanged-approval consume plus workflow/reservation CAS; bounded passphrase input, approvals and replays; monotonic permission tombstones; migration checkpoint; Linux file-boundary enforcement; cloneable non-debuggable shared lock/key authority with poison-time key clearing | platform key wrapping, supported secure-open policy on non-Linux targets, migration/import tooling for populated schema-v1 entity tables, DB benchmarks and audit |
| HNS | create/restore, separated keys, BLAKE2b-160 version-0 addresses, authenticated loopback `hns-node-rs` wallet RPC v1 adapter, separate bounded coin, `HnsName`, and 32-byte `HnsShakedex` queries under one exact chain/mempool snapshot, complete wallet/account-scoped persisted entity reads and fail-closed opaque-workflow recovery, encrypted monotonic name/Shakedex scan state with a cross-process durable allocation fence, protected workflow/economic-terms-bound Shakedex key allocation atomically coupled to WalletAccount and authenticated seed rederivation, restore/history/reorg reconciliation, ordered spender evidence, exact snapshot-bound HSD median time past and optional transaction positions, immutable canonical 0.2 NameState/resource source, exact raw/projected current/proof validation, owner txid/index/value/covenant/inclusion binding, `HnsName` ownership/incoming/outgoing classification, legacy-row revalidation, ephemeral exact-snapshot ownership authority, versioned chain/mempool/owner/lockup/renewal action-context validation, non-serializable current/unspent Shakedex lock and seller-script-bound TRANSFER authorities, canonical index-zero value-preserving TRANSFER and outgoing-owner direct FINALIZE construction, deterministic encrypted name workflows, typed name/funding and protected Shakedex source/funding reservations, runtime-bound Shakedex funding-coin recovery, single-use trusted approval, ordered `HnsName`/`HnsCoin` and funding-suffix signing, purpose-bound Shakedex proof/listing/cancellation/recovery signing, runtime-owned Shakedex time and same-snapshot transaction/all-input-spender observations, canonical policy-size/minimum-fee construction and independent node-quote comparison, exact signed-byte quote/requote, durable broadcast/mempool/lock/eligibility/finalization/cancellation/conflict/reapproval reconciliation, canonical HTLC construction/spends, settlement evidence and restart supervision | dedicated Shakedex-funding gate plus consolidated node/wallet action-context, MTP, key-allocation, Shakedex funding/reconciliation, and fee-policy CI; multi-process regtest, restart/reorg, mempool-conflict, adversarial, three-branch scan, and resource qualification; trusted provider/UI integration; protocol publication and independent review; published canonical settlement profile |
| Provider | exact 43-name vocabulary, secure origin, opaque authority registry, authority-validated permission/tombstone snapshots, bounded persisted account bindings, generation-CAS-bound single-approval `hns_requestAccounts` join, runtime-downgrade-safe minimized `hns_accounts`, typed capability snapshot, ephemeral approvals/replay/rates, forbidden methods; checked-in existing-database control dispatcher exposes only capabilities/status/permission read-or-revoke/lock after unlock and cannot create dormant generic grants | concrete `HnsWalletRuntime` account selector/read dispatch, published engine authority adapter, browser-native transport, complete trusted approval UI, executed restart/product qualification |
| Shakedex | encrypted/CAS seller, buyer, recovery, and typed transaction-plan schemas; opaque canonical fixed-price protocol authority bound to exact hash/network/time/locking coin; typed canonical cancellation; protected monotonic HNS seller-key allocation with purpose-bound signing; canonical fulfillment, explicit-recipient recovery, and script-witness FINALIZE planning; HNS-runtime adapters consume non-serializable current/unspent lock or TRANSFER, active NameState, parent-MTP, maturity, and renewal evidence; durable aggregate buyer-fulfillment/seller-recovery child with exact structural/coin/reservation/approval/final-byte-fee/signed-byte/pre-submit-fence evidence and runtime-owned restart/reorg/conflict/rebroadcast observations; all value authorization/submission entrypoints hard-disabled | product coin selection, durable script-FINALIZE child, evidence-backed signed-workflow reservation release, complete seller/buyer product orchestration, live node/Denuo/provider/trusted-UI integration, consolidated CI and restart/reorg/regtest qualification |
| Denuo market | pinned canonical name-market envelopes; bounded replay/tombstone-safe encrypted fixed-price board with sequence watermarks and CAS restart validation; chain-neutral reservations/sessions | live relay/outbox supervision, peer policy, reporter governance, product integration and qualification |
| Bitcoin | BDK BIP84 create/load/receive/send primitives; context-bound atomic-swap allocation keys with crate-local regression vectors; encrypted CAS-backed monotonic session/role allocation and authenticated re-derivation; bounded Kyoto tip discovery and supervisor; encrypted birthday/phase/checkpoint journal; BDK-first restart reconciliation; bounded transaction/output mirrors; exact fee-bound pre-broadcast journal; HTLC funding/spend/evidence units | canonical complete-terms caller and settlement-supervisor integration, pinned Kyoto durable header/filter/peer API, record archival, signed-spend integration, consolidated CI, regtest/restart/reorg/adversarial qualification and benchmarks; value gate remains false |
| Ethereum | separated offline accounts, typed dormant EIP-1559/HTLC and structural evidence primitives, deterministic contract, immutable false synchronization/value/settlement/mainnet gates, opaque runtime permits plus role/address/exact-fee-bound signing types, zeroizing preimages/intermediates, redacted controlled-broadcast artifact | embedded Helios proof source and privately minted evidence authority, persistence/balance/history/nonce/fee/broadcast runtime, redeem/refund verification, local-chain/restart/reorg qualification, approved address and audit |
| FFI/service/host | ABI v2; canonical framing; random host/service/wallet sessions; one typed provider binding; authority-scoped private capability snapshot distinct from the public website capability result; bounded typed frames; explicit existing-database locked subprocess with one shared provider/runtime key authority, zeroizing ABI unlock, post-unlock entropy-failure relock, and narrow non-value control dispatch; caller-side owned clock/entropy, hello/restart and dual-direction sequence state, bounded response correlation, authority/approval/binding/event replay state; Draft 2020-12 private/public/manifest schema bundle and bounded vectors | wallet create/restore and concrete account/chain runtime composition; signed released service artifact and verifier trust store, private Chromium launcher and exact capability projection, generated JNI/Swift bindings, published engine join and compatibility E2E; value/browser capability gates remain false |
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
polling loop. Wallet-owned P2PKH TRANSFER and direct FINALIZE use the same
boundary and remain unreachable while both HNS release gates are false.

Other exact blockers are:

- the concrete authenticated loopback adapter is integrated in source, but its
  consolidated CI, multi-process regtest, restart/reorg, malformed-transport,
  stale-cursor, and resource qualification evidence is not yet recorded;
- coinbase identity is preserved but coinbase outputs remain unselectable until
  released canonical maturity evidence is integrated and qualified;
- exact confirmed input height/address/covenant evidence now drives canonical
  `hns-script` sigops, policy-size, minimum-fee construction, standardness
  bounds, and independent node-quote comparison, but consolidated fee-policy
  and adapter qualification is not recorded, so
  `HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` remains false;
- name TRANSFER/FINALIZE source workflows consume fresh ephemeral authority and
  exact node action context, but their node/wallet restart/reorg/mempool/product
  qualification and provider/trusted-UI dispatch are not recorded;
- canonical `hns-swap` 0.2 source is pinned to immutable revision `4b989aa`, but
  that protocol revision is unpublished and lacks consolidated qualification;
- platform key wrapping, secure approval UI, browser/native-host integration,
  and non-Linux secure persistent database opening are unavailable; and
- regtest, restart/reorg, installed-product, resource, and independent security
  qualification have not been recorded for this source tranche.

## Shakedex release gates

`SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED`,
`SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED`, and
`SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED` are `false`. Seller creation and
transition and buyer discovery and transition return an explicit unavailable
error before mutation. This also blocks sessions restored from legacy
persisted records. Independently usable read/discovery boundaries now require
the exact listing hash, network, active time window, and supplied canonical
locking coin; cancellations bind to that exact listing; Denuo registry and
message family are checked before protocol authority is returned. The boundary
does not authenticate that coin as current or unspent. The persisted board
revalidates canonical bytes and monotonic seller/name watermarks after restart.
Typed adapters can also reconstruct canonical fulfillment, recovery, and
script-controlled FINALIZE plans. Encrypted workflow CAS retains signed
fulfillment and recovery parent plans; script-controlled FINALIZE is not yet
durable. Their supplied Coin, parent MTP, NameState, renewal block, and funding
suffix remain structural on the low-level compatibility functions. The current-
authority adapters replace the first four with one exact HNS chain/mempool
snapshot.

A distinct aggregate child now covers buyer fulfillment and seller recovery.
It durably binds the complete parent plan and commitment, exact source and
ordered funding coins, recipient, value, fee/maximum, finality/expiry,
prepared/signed bytes, exact approval and final-byte quote, bounded submission
fence, and chain observations. Initial persistence atomically installs a
globally keyed protected lock-source reservation plus exact account funding
reservations. Runtime time caps prepared rows at five minutes. Prepared
cancellation/expiry releases the whole set; signed
states retain it through rebroadcast, mempool, confirmation, rollback, and
conflict. Generic HNS cleanup cannot release these rows.

The runtime owns time and chain evidence, recovers funding derivations only by
exact current-cache matches, preserves the script-authorized first input,
signs only the ordinary suffix, and consumes approval only with the CAS that
persists verified signed bytes and their exact quote. Submission re-quotes the
persisted bytes and records `RequiresRebroadcast` plus active reservation
revisions before the node call. Same-snapshot transaction and all-input spender
evidence drives reconciliation, including rollback from a disappeared
confirmation to same-byte rebroadcast. Persisted fee evidence is revalidated
after restart without treating its old snapshot as current authority.

This source still does not select product funding coins, make script-controlled
FINALIZE durable, release signed-workflow reservations from terminal evidence,
contact live Denuo peers, dispatch through a provider/trusted approval UI, or
constitute restart/reorg/regtest qualification. Purpose-bound seller proof/
listing/cancellation/recovery signing remains separately constrained by
canonical terms and current-lock authority. No Shakedex or dependent HNS
Shakedex-funding/value/fee gate is enabled.

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
lifetime caps, signed HTLC spend supervision, complete allocation concurrency/
restart/corruption qualification, regtest/restart/reorg/adversarial evidence,
trusted-time policy, resource measurements, and independent review remain
blockers. The domain-separated keys and encrypted monotonic allocation source
passed only its 10-test targeted NVMe filter; that evidence does not change the
false value-release gate.

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
gate. On 2026-08-03 the focused NVMe `canonical_hns_v2` invocation passed 6 HNS
name/adapter tests and 3 Shakedex listing/gate tests; the subsequent exact
account-scoped persistence regression passed 1 test. The final focused
`canonical_hns_v3_name_action` invocation passed 4 HNS tests with 0 failures
and 19 filtered. The exact-lock/Denuo/board invocation then passed 1 Shakedex
test with 0 failures and 3 filtered, including encrypted CAS reopen recovery.
The provider/ABI/service/host account-join invocation passed 5 tests with 0
failures and 31 filtered. The final filtered `hns_shakedex` invocation passed 3
HNS tests with 0 failures and 22 filtered; the Shakedex unit and restart targets
compiled but had no matching selected test.
No standalone build, check, broad workspace test, RocksDB compilation, network
run, or benchmark was performed. These focused results do not replace the
consolidated gate and do not enable a value constant. Run
`scripts/check.sh` once in CI and record the resulting commit ID and artifacts
in [`QUALIFICATION.md`](QUALIFICATION.md). The new provider/ABI/service/host
contract has focused source evidence only; installed-product and restart
qualification remain unrun.

The durable Shakedex value-aggregate source described above was added after
the recorded `hns_shakedex` run. It has no recorded test result yet and does
not inherit qualification from the earlier structural-plan compilation.

## Deferred by design

Reverse-Dutch offers, arbitrary Bitcoin applications, generic Ethereum dapps,
tokens/NFTs/DeFi/staking, `window.ethereum`, WalletConnect, user-added chains or
contracts, browser contract deployment, hosted Bitcoin backends, crawler/
bootstrap expansion, and enabling any future chain pair without full
qualification are out of scope.
