# Bitcoin: Kyoto only

Bitcoin has one synchronization implementation: direct P2P with `bip157`
0.6.3 and `bdk_kyoto` 0.17.0, feeding a BIP84 `bdk_wallet` 3.1.0 wallet.
There is no Esplora, Electrum, hosted indexer, or Bitcoin Core RPC production
mode. Bitcoin Core regtest is only a deterministic qualification fixture.

## Implemented source boundary

The bounded supervisor now owns these transitions:

- a header/filter discovery client starts from an explicit trusted checkpoint
  and waits under a configured deadline for Kyoto's `FiltersSynced` event;
- a new wallet accepts only that validated current tip as its birthday and
  separately retains the non-genesis trusted discovery anchor plus bounded
  validated history as its recovery checkpoint set, so recovery neither reuses
  an orphaned tip nor silently falls back to genesis;
- restores accept a known checkpoint or genesis. A date-based restore requires
  a checkpoint which the already-synced Kyoto chain proves canonical and whose
  header timestamp precedes the source date by a bounded safety window; the
  wallet does not guess a height from wall-clock time;
- the encrypted scan record uses CAS revisions and explicit starting,
  synchronizing, reconciling, ready, and recovery-required phases;
- each Kyoto update is applied and committed to BDK SQLite before bounded
  transaction/output mirrors are reconciled in encrypted 512-record chunks;
  the ready checkpoint is committed last. A crash in a chunk leaves the state
  reconciling, so restart replays reconciliation from the already-durable BDK
  view without another network scan;
- exact block-hash membership queries locate a retained common ancestor. A
  reorg deeper than the bounded 32-checkpoint recovery window fails closed and
  requires a recovery-anchor scan;
- sync, requester, discovery, fee, peer, and broadcast waits have configured
  deadlines. Timing out Kyoto's non-cancel-safe update poisons that supervisor,
  shuts its node down, records recovery-required state, and requires a fresh
  instance; and
- relevant transaction and wallet-output records have 4,096-record lifetime
  caps. Canonically absent records are retained for reorg evidence. Safe
  archival/pruning is not implemented, so reaching either cap fails closed.

The supervisor returns Kyoto log receivers to the application; a product must
drain them and must not treat informational progress or peer messages as chain
authority.

Initial tip discovery is bounded too. If its sync deadline expires, discovery
shuts down its Kyoto node and poisons itself; callers must create a new
discovery instance rather than continue using a possibly active timed-out
operation.

## Persistence ownership and pinned limitation

BDK SQLite durably owns descriptors, revealed derivations, local-chain
checkpoints, relevant transactions, and wallet outputs. The encrypted wallet
store owns birthday, supervisor sequence/phase, last consistent checkpoint,
the distinct recovery checkpoint, bounded recent checkpoints,
transaction/output reconciliation records, and broadcast intents.

`bip157` 0.6.3 accepts `data_dir`, but this pinned release discards the field in
`Node::new`; it does not persist headers, compact-filter headers/filters, or its
address book. `bdk_kyoto` also exposes a completed wallet update, not the exact
filter-header chain or durable peer database. The source therefore does not
claim those objects are persisted. A reviewed Kyoto release/API which exposes
and durably restores that validated state is a release blocker. BDK's wallet
checkpoint permits bounded restart recovery in the meantime, but is not a
substitute for the missing Kyoto database.

## Broadcast boundary and release gate

A signed transaction is accepted for journaling only when the BDK wallet can
resolve every input as owned and unspent, calculate its exact fee, and prove the
fee does not exceed the approved maximum. The approval commitment is
domain-separated and binds network magic, txid, wtxid, exact fee, fee maximum,
and expiry. The complete raw transaction and approval are persisted before the
state advances to `submission_started`.

Only a durable ready checkpoint, a running Kyoto node, and the configured peer
quorum can reach `submit_package`. Expiry is exclusive: a request at the expiry
second is rejected. Submission has a bounded timeout. A timeout leaves
`submission_started` durable for an idempotent retry after the same bounded
rebroadcast interval used by a known submission; successful return must contain
the expected wtxid before `submitted` is committed.

The broadcast journal rejects time earlier than its durable preparation or
latest-attempt timestamp. This prevents a backward wall-clock jump from
silently extending approval or retry windows, but a qualified product still
needs a reviewed trusted-time/monotonic-clock policy.

`BITCOIN_VALUE_RUNTIME_RELEASE_QUALIFIED` remains `false`. No
`BitcoinValueRuntimePermit` can be obtained, capability discovery does not
advertise send or atomic settlement, and both native-send signing and broadcast
require that unavailable permit in this source revision.

## Atomic-swap key derivation

Ordinary receive/change keys remain in BDK's BIP84 descriptor trees. Atomic-
swap keys never enter those trees and do not claim a standardized BIP-32 path.
They use HKDF-SHA256 over the wallet profile's 64-byte BIP-39 recovery seed
(the same empty BIP-39 passphrase policy used by this wallet's BIP84 setup),
with the exact ASCII salt:

```text
hns-wallet-rs/bitcoin-atomic-swap-key/v1
```

The 25-byte HKDF info is `HSWP || coin_type || network_code || account || role
|| index || counter`. Each numeric field except the final counter is a big-
endian `u32`; the counter is one byte and advances from 0 through 255 only if
the candidate is not a valid secp256k1 scalar. The first valid candidate wins.
Role 0 is the receiver/redeem branch and role 1 is the refund-owner branch.
Both account and key index are accepted only in the inclusive range
0..=100,000.

| Bitcoin network | coin type | network code |
| --- | ---: | ---: |
| mainnet | 0 | 0 |
| testnet3 | 1 | 1 |
| testnet4 | 1 | 2 |
| signet | 1 | 3 |
| regtest | 1 | 4 |

The coin-type field mirrors the ordinary wallet's main/test split, while the
separate network code prevents testnet, testnet4, signet, and regtest from
sharing swap keys. This application-private HKDF scheme is disjoint from BIP84
at the KDF boundary rather than relying on an unregistered BIP purpose number.

Public recovery vectors below were calculated from the BIP-39 English
`abandon` eleven times followed by `about` mnemonic, its empty-passphrase
64-byte seed, and the exact salt/info encoding above. They are embedded as
source conformance assertions; no private material is recorded:

| Reference | compressed public key |
| --- | --- |
| mainnet, receiver, account 0, index 0 | `025e70317534f24fafdbcbd0f8524967de9a5c6f6dc9655872ddb6adba94174bff` |
| mainnet, refund owner, account 0, index 0 | `03a5f831491d756b0429dbe97b54280091883d16b0a9f79b74e220dfafe823f7af` |
| regtest, receiver, account 0, index 0 | `02de93cfd4281366f4308cc0ed7df6753c2bb3bd3e9ef32cc2e22c28f9745277b3` |

The in-memory handle exposes only its role-bound public half, redacts its secret
in `Debug`, cannot be serialized or cloned, and zeroizes its 32-byte secret on
drop. A serializable public reference carries the exact recovery coordinates.
The HTLC constructor can place that public key only in its declared receiver or
refund position. The serialized reference also binds scheme version 1 and
rejects other versions. Each swap session must authenticate and durably persist
the exact scheme version, network, account, role, and key index before an
irreversible action; deterministic regeneration from known coordinates is not
a bounded discovery scan. That session allocation/persistence and signed-spend
integration are still missing, no signing or value permit is exposed, and this
source does not advertise atomic settlement.

## HTLC profile

The native settlement template is P2WSH:

```text
IF SHA256 <hashlock> EQUALVERIFY <receiver-key> CHECKSIG
ELSE <refund-height> CLTV DROP <refund-key> CHECKSIG ENDIF
```

Funding verification reconstructs the exact script, checks value, a unique
matching output, transaction bounds, and confirmation minimum. Redeem/refund
templates enforce the branch, hashlock, dust, fee, and refund height. Preimage
observation requires the expected outpoint and exact witness script. The
domain-separated local public key can now be bound to its HTLC script position;
signed spend integration and the cross-chain settlement supervisor remain
unavailable.

## Qualification and benchmarks

This tranche was source-only and was not built or tested locally. The prior
baseline is not evidence for these changes. No benchmark values are estimated.

| Scenario | Disk | Bandwidth | Usable balance | Full scan | Peak mobile memory |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fresh install | not measured | not measured | not measured | not measured | not measured |
| New wallet | not measured | not measured | not measured | not measured | not measured |
| One-year restore | not measured | not measured | not measured | not measured | not measured |
| Five-year restore | not measured | not measured | not measured | not measured | not measured |
| Genesis restore | not measured | not measured | not measured | not measured | not measured |

Bitcoin send and settlement remain unavailable until the pinned persistence
gap is resolved and the consolidated CI, invalid-PoW/filter/peer tests, regtest
restart/reorg/broadcast/HTLC suite, mobile resource benchmarks, and independent
review are recorded.
