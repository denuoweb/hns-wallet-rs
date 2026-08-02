# Qualification matrix

This file records evidence, not intent. “Unit” never means “mainnet ready.”

| Area | Compile | Unit/negative | Persistence/restart | Reorg | Real network/local chain | Bench/audit | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Types/chain traits | yes | yes | n/a | n/a | n/a | no external audit | experimental |
| Secret store/schema v1 | yes | encryption/lock/migration/CAS/replay | workflow reopen unit only | n/a | no device secure-store test | no DB benchmark/audit | partial |
| HNS wallet/names | yes | key roles/address/selection/proof units | workflow rows | incomplete | no regtest | no audit | partial |
| Provider core | yes | origin/permission/stale/rate/replay/forbidden | grants/replays in SQLite | n/a | no installed-browser E2E | no audit | partial |
| Fixed-price Shakedex | yes | seller recovery/buyer ordering | CAS journal | incomplete | no regtest/Denuo E2E | no audit | partial |
| Market sessions | yes | reservations/timeouts/evidence/refunds | CAS journal | incomplete | no pair E2E | no audit | partial |
| Bitcoin Kyoto | yes | descriptor/HTLC/evidence/reorg units | BDK/Kyoto stores designed | unit rewind only | no regtest/P2P run | not measured | partial |
| Ethereum | yes | roles/signing/policy/code/evidence | schema only | rollback negative unit | contract compiles; no local chain/Helios run | no contract audit | partial |
| ABI | yes | bounds/high-risk transport negatives | session field only | n/a | no platform ABI E2E | no audit | partial |
| Browser products | separate repos | targeted tests pending | platform integration pending | n/a | no installed/signed E2E | no review | incomplete |

## Local commands

The single workspace gate is `scripts/check.sh`. It performs formatting,
locked all-target check, warning-denied Clippy, tests, warning-denied docs,
sibling/forbidden-backend dependency checks, deterministic Solidity artifact
comparison, and npm high-severity audit.

Local result on 2026-08-02: PASS. All 34 Rust unit/negative tests passed;
formatting, locked all-target check, warning-denied Clippy, warning-denied docs,
dependency-boundary checks, deterministic Solidity artifact comparison, and
npm audit (zero vulnerabilities) passed. This result does not upgrade any
external-network, browser-installation, signed-device, benchmark, or audit row.

Contract evidence SHA-256:

- source: `537c0a4dd05f8128a6fe11046edc825f5a0a6577fc0fe0b61c7b31d5ec00caa7`;
- generated artifact: `ba3bfde0443c13bcdbe287ef292072d1a2a8645fd4efd9bdee2b9dd566f52cec`;
- npm lockfile: `43c5070e3475eb76ea9218bbafbe743307f4e9c7052153f2f53d5c4da3fde8e8`.

External gates still required:

- each modified repository's own `scripts/check.sh`;
- `hns-rs` conformance vectors and fuzz smoke/full campaigns;
- HNS and Bitcoin regtest success/refund/restart/reorg demonstrations;
- Kyoto invalid-PoW/filter/peer-consistency fixtures and birthday scans;
- Ethereum local-chain lock/redeem/refund/replay/receiver/refund-address/
  reentrancy/event/rollback tests;
- embedded Helios proof and persistence tests;
- Chromium installed-extension/native-host and signed Android/iOS tests;
- Kyoto disk/bandwidth/startup/mobile-memory benchmarks; and
- independent review of key management, provider authority, HTLC scripts,
  Solidity source/bytecode, and cross-chain timeout policy.

No automated test moves live mainnet funds.
