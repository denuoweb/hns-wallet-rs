# Qualification matrix

This file records evidence, not intent. Unit coverage never authorizes mainnet
value. “Implemented source” means the code boundary exists; “pending” means the
current commit has no recorded result for that gate.

| Area | Compile/unit evidence for current tranche | Persistence/restart | Reorg | Real network/product | Bench/audit | Release status |
| --- | --- | --- | --- | --- | --- | --- |
| Types/chain traits | pending consolidated gate | n/a | n/a | n/a | no external audit | qualification pending |
| Encrypted store/schema v3 | pending consolidated gate | source includes migration checkpoint, encrypted typed CRUD/CAS/batches and restart-safe workflow rows | n/a | no device secure-store test | no DB benchmark/audit | qualification pending |
| HNS wallet/names | name-role/adapter tranche pending consolidated gate | source includes authenticated loopback RPC configuration, strict HTTP/JSON parsing, atomic coin/name-role snapshot restoration, encrypted monotonic scan state, mempool-bound point reads, non-consuming approval authentication, atomic approval/workflow/reservation commit, exact signed-byte fee-quote persistence, and durable pre-submission `RequiresRebroadcast` recovery | source includes epoch-bound checkpoint rewind, ordered spender evidence, split current/proof evidence revalidation, exact cross-scan binding rejection, and one-reconciliation fee-quote recovery | concrete adapter source pinned to node RPC v1 commit `5ed38d15`; no multi-process regtest run, released canonical fee algebra, canonical NameState decoder, or executed name-role qualification | no resource measurement/audit | value runtime and fee-algebra gates unavailable; names watch-only |
| Provider core | pending consolidated gate | encrypted grants/tombstones/approvals/replays implemented | n/a | no installed-browser E2E | no audit | product integration pending |
| Fixed-price Shakedex | prior unit baseline only | CAS journal source | evidence incomplete | no regtest/Denuo E2E | no audit | unavailable |
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
network test, or benchmark was run. The remainder of this production-hardening
and host-contract tranche has no new local evidence. Its next broad evidence
event is one consolidated CI invocation of `scripts/check.sh`; do not run
separate build, check, test, and pre-push copies of the same gate. Record its
commit ID, runner/platform, full result, test count, and artifact hashes here.

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
