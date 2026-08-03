# Qualification matrix

This file records evidence, not intent. Unit coverage never authorizes mainnet
value. “Implemented source” means the code boundary exists; “pending” means the
current commit has no recorded result for that gate.

| Area | Compile/unit evidence for current tranche | Persistence/restart | Reorg | Real network/product | Bench/audit | Release status |
| --- | --- | --- | --- | --- | --- | --- |
| Types/chain traits | pending consolidated gate | n/a | n/a | n/a | no external audit | qualification pending |
| Encrypted store/schema v3 | pending consolidated gate | source includes migration checkpoint, encrypted typed CRUD/CAS/batches and restart-safe workflow rows | n/a | no device secure-store test | no DB benchmark/audit | qualification pending |
| HNS wallet/names | focused `canonical_hns_v3_name_action` PASS on NVMe: 4 passed, 0 failed, 19 filtered; prior `canonical_hns_v2`: 6 passed, 0 failed, 9 filtered; prior account-scoped persistence regression: 1 passed, 0 failed, 15 filtered; consolidated gate pending | source includes authenticated loopback RPC configuration, strict HTTP/JSON parsing, atomic coin/name-role snapshot restoration, complete bounded account-prefix entity reloads, encrypted monotonic scan state, canonical current/proof summaries and exact owner inclusion, legacy-row revalidation, ephemeral ownership/finalize authority, versioned action context, exact persisted input evidence, canonical TRANSFER/FINALIZE construction, typed reservations, single-use approval, ordered coin/name signing, canonical local policy/minimum-fee checks, exact signed-byte fee-quote persistence, and durable rebroadcast/name-action state | source includes epoch-bound checkpoint rewind, ordered spender evidence, split current/proof revalidation, exact cross-scan binding rejection, authority reacquisition, persistent reservations across reversible confirmations, reapproval state, and one-reconciliation fee-quote recovery; no multi-process restart/reorg execution | concrete adapter source pinned to node RPC v1 commit `e5f95c05`; canonical protocol crates pinned coherently to immutable `hns-rs` `4b989aa`; no multi-process regtest or product name-action run | no resource measurement/audit | wallet-owned P2PKH TRANSFER/direct-FINALIZE source implemented; HNS value-runtime and fee-policy qualification gates remain false; provider/product and real-network qualification pending |
| Provider core | pending consolidated gate | encrypted grants/tombstones/approvals/replays implemented | n/a | no installed-browser E2E | no audit | product integration pending |
| Fixed-price Shakedex | focused immutable-V2 listing/gate filter PASS on NVMe: 3 passed, 0 failed | CAS journal source | evidence incomplete | no regtest/Denuo E2E | no audit | all workflow/value gates remain unavailable |
| Market sessions | prior unit baseline only | CAS journal source | evidence incomplete | no pair E2E | no audit | unavailable |
| Bitcoin Kyoto | targeted allocation filter PASS on NVMe: 10 passed, 0 failed, 8 filtered; consolidated gate pending | source includes encrypted CAS-backed monotonic session/role swap-key allocation, protected seed/allocation records, authenticated re-derivation, BDK-first sync journal, bounded reconciliation chunks, restart resume, and pre-broadcast intent; allocation database reopen covered by the targeted filter; pinned Kyoto header/filter/peer persistence unavailable | source queries exact canonical hash membership within a bounded retained window; no allocation reorg or snapshot-rollback evidence | no regtest/P2P/broadcast run | not measured/no audit | send and settlement hard-disabled |
| Ethereum | containment tranche pending consolidated gate | offline derivation and dormant typed primitives only; no synchronization/history persistence | no restart/reorg evidence | deterministic contract compiled only in prior baseline; no embedded Helios/local-chain run; permits unavailable; mainnet denied | no contract audit | synchronization/history/send/signing/settlement unavailable |
| ABI/host | host/contract tranche pending consolidated gate | source includes exact hello/restart and directional sequencing, bounded response correlation, authority/approval/private-binding/event replay state, and machine-readable private/public/manifest contracts plus bounded vectors | restart reset is implemented in source; no process-restart execution evidence | no platform ABI E2E, signed artifact verifier, launcher, or generated mobile binding | no resource measurement/audit | product integration pending; all browser/provider/value gates remain false |
| Browser products | separate repositories | platform integration pending | n/a | no installed/signed E2E | no review | unavailable |

## Single qualification command

The workspace gate is `scripts/check.sh`. It performs formatting, a locked
all-target check, warning-denied Clippy, tests, warning-denied docs,
sibling/forbidden-backend dependency checks, deterministic Solidity artifact
comparison, and an npm high-severity audit.

The Bitcoin allocation subtarget was tested once on 2026-08-03 from a
disposable NVMe checkout with an NVMe target and temporary directory:
`cargo test --locked -p hns-wallet-bitcoin-kyoto swap_key_store::tests --
--test-threads=1`. It passed 10 tests with 0 failures and 8 filtered out. No
standalone build/check, full workspace gate, optimized RocksDB compilation,
network test, or benchmark was run.

The final canonical-name source was tested on 2026-08-03 from an isolated NVMe
clone with NVMe target and temporary directories:
`cargo test --locked --lib -p hns-wallet-hns -p hns-wallet-shakedex
canonical_hns_v2 -- --test-threads=1`. The HNS crate passed 6 tests with 0
failures and 9 filtered; Shakedex passed 3 listing/gate tests with 0 failures.
The later exact regression
`cargo test --locked --lib -p hns-wallet-hns
canonical_hns_v2_persisted_queries_are_complete_and_account_scoped --
--test-threads=1` passed 1 test with 0 failures and 15 filtered.
No standalone build/check, full workspace gate, RocksDB compilation, network
test, or benchmark was run. The next broad evidence event is one consolidated
CI invocation of `scripts/check.sh`; do not run
separate build, check, test, and pre-push copies of the same gate. Record its
commit ID, runner/platform, full result, test count, and artifact hashes here.

The later exact-UTXO/fee-policy/signing substrate added focused unit cases but,
by explicit efficiency constraint, did not execute another local build or test
session. Those cases and the consolidated gate remain pending evidence; the
prior results above do not qualify the new source.

The wallet-owned name-action tranche ran one narrowly filtered NVMe command:
`cargo test --locked --lib -p hns-wallet-hns canonical_hns_v3_name_action -- --test-threads=1`.
The final invocation passed 4 tests with 0 failures and 19 filtered. It covered
canonical TRANSFER and FINALIZE construction/signing, candidate maturity and
renewal binding, and closed node wire vocabulary. It is focused implementation
evidence only and cannot change either false HNS release gate.

## Prior baseline evidence

The earlier 2026-08-02 baseline result was PASS: 34 Rust unit/negative tests,
formatting, locked all-target check, warning-denied Clippy and docs,
dependency-boundary checks, deterministic Solidity artifact comparison, and an
npm audit with zero vulnerabilities. It predates this tranche and is not
qualification evidence for the current commit.

Baseline contract evidence SHA-256:

- source: `537c0a4dd05f8128a6fe11046edc825f5a0a6577fc0fe0b61c7b31d5ec00caa7`;
- generated artifact: `ba3bfde0443c13bcdbe287ef292072d1a2a8645fd4efd9bdee2b9dd566f52cec`;
- npm lockfile: `43c5070e3475eb76ea9218bbafbe743307f4e9c7052153f2f53d5c4da3fde8e8`.

## External gates still required

- the current commit's single `scripts/check.sh` CI result;
- `hns-rs` conformance vectors and fuzz smoke/full campaigns;
- HNS and Bitcoin regtest success/refund/restart/reorg demonstrations;
- Kyoto invalid-PoW/filter/peer-consistency fixtures and birthday scans;
- Ethereum local-chain lock/redeem/refund/replay/receiver/refund-address,
  reentrancy/event/rollback tests;
- embedded proof-producing Helios runtime plus persistence/restart/reorg tests;
- Chromium installed-extension/native-host and signed Android/iOS tests;
- Kyoto disk/bandwidth/startup/mobile-memory benchmarks; and
- independent review of key management, provider authority, HTLC scripts,
  Solidity source/bytecode, and cross-chain timeout policy.

No automated test moves live mainnet funds.
