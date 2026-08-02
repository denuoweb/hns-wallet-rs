# Persistence and restart recovery

Schema version 1 creates explicit tables for wallet accounts/addresses, HNS
UTXOs and transactions, names and transfers, Shakedex, Denuo cache, Kyoto
headers/filter headers/peers/scan progress, Bitcoin UTXOs and transactions,
Ethereum accounts and transactions, price rounds, intents, fill grants, swap
sessions, HTLC secrets, refunds, permissions, approvals, replays, and generic
versioned workflows.

Sensitive record values use XChaCha20-Poly1305. Workflow rows use an immediate
SQLite transaction and compare-and-swap revision. A caller records a prepared
irreversible action before broadcasting it. Duplicate/stale writers fail.

## Required startup sequence

The product runtime must:

1. open and migrate the database, remain locked, and request platform-backed
   unlock;
2. load persisted workflows and the last consistent chain checkpoints;
3. resume HNS, Kyoto, and the selected Ethereum synchronization adapter;
4. reconcile mempools, confirmations, replacements, and reorgs;
5. revalidate name ownership/proofs and Shakedex listings;
6. expire price rounds, intents, fill grants, approvals, and replay rows;
7. restore swap sessions and independently verify every recorded funding,
   redemption, and refund;
8. extract an on-chain preimage only from a verified spend/event;
9. determine refund eligibility from validated local chain time; and
10. surface user actions without automatically moving value.

The library implements schema/migration, encrypted secret records, workflow
CAS, and state-machine journals. A complete multi-chain startup supervisor,
transaction rebroadcast policy, all entity-specific CRUD, and every reorg
reconciliation path are not yet implemented.

## Migrations and backups

Opening a database with a newer schema fails. Migration 1 is transactional.
Future migrations must be forward-only, idempotently tested from every
supported prior version, and retain an offline backup/restore test. Copying a
live SQLite file without its WAL is not a supported backup procedure.

The passphrase is not a substitute for platform device security. A production
backup design must document whether encrypted seeds are included, how KDF
parameters are retained, and how rollback to stale workflow state is detected.
