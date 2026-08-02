# Bitcoin: Kyoto only

Production synchronization has one implementation:

- `bip157` 0.6.3 for direct Bitcoin P2P, validated headers, compact-filter
  headers/filters, matching block retrieval, peer state, and broadcast;
- `bdk_kyoto` 0.17.0 for BDK wallet updates;
- `bdk_wallet` 3.1.0 for BIP84 descriptors, addresses, coin selection, PSBT
  construction/signing, balances, history, and SQLite persistence.

There is no Esplora, Electrum, hosted indexer, or Bitcoin Core RPC production
mode. Bitcoin Core regtest is allowed only as a deterministic qualification
fixture.

New wallets start at the current validated birthday height, never genesis.
Restores accept a conservative checkpoint/full scan plan. Kyoto owns its
validated header/filter and peer databases; BDK owns descriptor wallet chain
state; wallet metadata records birthday, progress, relevant objects, and the
last consistent checkpoint. Reorg handling rewinds to a verified common
ancestor before replaying filters/blocks.

The native settlement template is P2WSH:

```text
IF SHA256 <hashlock> EQUALVERIFY <receiver-key> CHECKSIG
ELSE <refund-height> CLTV DROP <refund-key> CHECKSIG ENDIF
```

Funding verification reconstructs the exact script, checks value, unique
matching output, transaction bounds, and confirmation minimum. Redeem/refund
templates enforce the branch, hashlock, dust, fee, and refund height. Preimage
observation requires the expected outpoint and exact witness script.

## Current qualification

The actual Kyoto client factory, BDK create/load/receive/send boundaries,
canonical HTLC construction, funding checks, unsigned spend templates,
preimage extraction, and unit reorg state are implemented. A continuously
running/persisting client supervisor, peer inconsistency fixtures, invalid-PoW
and filter-header tests, signed HTLC spends, transaction broadcast/rebroadcast,
regtest end-to-end swaps, and mobile resource testing remain incomplete.

## Benchmark report

No measurements were run in this environment. Values are deliberately not
estimated.

| Scenario | Disk | Bandwidth | Usable balance | Full scan | Peak mobile memory |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fresh install | not measured | not measured | not measured | not measured | not measured |
| New wallet | not measured | not measured | not measured | not measured | not measured |
| One-year restore | not measured | not measured | not measured | not measured | not measured |
| Five-year restore | not measured | not measured | not measured | not measured | not measured |
| Genesis restore | not measured | not measured | not measured | not measured | not measured |

There is no universal fixed light-client size. Mainnet Bitcoin and HNS/BTC
settlement remain disabled until these measurements and the complete
qualification suite are recorded on supported desktop/mobile targets.
