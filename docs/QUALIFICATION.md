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
| Bitcoin Kyoto | current supervisor tranche pending consolidated gate | source includes BDK-first sync journal, bounded reconciliation chunks, restart resume, and pre-broadcast intent; pinned Kyoto header/filter/peer persistence unavailable | source queries exact canonical hash membership within a bounded retained window; no current execution evidence | no regtest/P2P/broadcast run | not measured/no audit | send and settlement hard-disabled |
| Ethereum | containment tranche pending consolidated gate | offline derivation and dormant typed primitives only; no synchronization/history persistence | no restart/reorg evidence | deterministic contract compiled only in prior baseline; no embedded Helios/local-chain run; permits unavailable; mainnet denied | no contract audit | synchronization/history/send/signing/settlement unavailable |
| ABI | prior unit baseline only | session field only | n/a | no platform ABI E2E | no audit | product integration pending |
| Browser products | separate repositories | platform integration pending | n/a | no installed/signed E2E | no review | unavailable |

## Single qualification command

The workspace gate is `scripts/check.sh`. It performs formatting, a locked
all-target check, warning-denied Clippy, tests, warning-denied docs,
sibling/forbidden-backend dependency checks, deterministic Solidity artifact
comparison, and an npm high-severity audit.

This production-hardening tranche was not built or tested locally, by explicit
instruction to avoid redundant build/test sessions. Its next evidence event is
one consolidated CI invocation of `scripts/check.sh`; do not run separate
build, check, test, and pre-push copies of the same gate. Record its commit ID,
runner/platform, full result, test count, and artifact hashes here.

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
