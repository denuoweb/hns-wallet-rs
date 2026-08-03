# Persistence and restart recovery

Schema version 3 retains the schema-v1 table layout for forward migration and
adds encrypted, typed entity storage plus private provider tables. Wallet
accounts, derived addresses, HNS/Bitcoin/Ethereum state, known names, input
reservations, settlement verification records, market state, workflows,
permissions, approval requests, and replay records have bounded typed accessors.

Provider-service permissions use the encrypted permission records and monotonic
revocation tombstones. Provider authority handles, service/wallet sessions,
pending website approvals, handle replay/rate state, request-ID windows, and
event cursors are intentionally not restored. The generic pending-approval and
replay tables remain available to persisted wallet/HNS workflows, but ABI v2
does not write provider approvals or provider nonces there. This prevents stale
provider rows from becoming actionable or consuming provider capacity after a
restart.

Sensitive values use XChaCha20-Poly1305 with random nonces. Associated data
binds the database ID, record domain and identifier, plus plaintext columns that
can affect a decision: entity/workflow revision and update time, workflow kind
and broadcast state, permission generation/revocation state, approval origin
token and expiry, and replay origin token/nonce/expiry. Changing one of those
columns without the key makes the record fail authentication.

Entity and workflow writes use immediate SQLite transactions and
compare-and-swap revisions. Bounded heterogeneous preparation batches
authenticate every current ciphertext and revision before writing, then commit
the wallet account, workflow, and all input-reservation saves/deletes together.
Duplicate `(entity kind, record ID)` operations and stale writers fail before a
partial batch becomes visible. Secret record kinds are immutable.

HNS authorization can authenticate and return a pending approval without
consuming it. After exact signed-byte fee quoting succeeds, a bounded immediate
transaction re-authenticates that unchanged approval together with the current
workflow and reservation revisions, activates the reservations, saves the
authorized workflow/raw bytes/quote, and only then deletes the approval. Any
stale revision, changed approval, signing error, or quote error leaves the
approval and workflow state unconsumed.

## HNS change derivations

Send preparation and settlement-lock preparation commit account change-index
advancement, the prepared workflow, and input reservations in one SQLite
transaction. The in-memory account is updated only after commit. Concurrent
losers and any precommit fee/build/sign failure leave all three records
unchanged; a committed workflow cannot reuse its change key or become invisible
behind a failed account CAS.

The send request nonce and settlement session/action derive deterministic
workflow IDs. A same-terms, nonexpired retry loads the encrypted prepared
workflow first, verifies the exact account/request/fee terms, signed artifact,
and complete reservation set, refreshes the committed account cache, and returns
the persisted artifact without deriving or reserving another change address.
Mismatched, expired, or advanced-stage retries fail closed.

## HNS name-role derivations

The `HnsName` branch has independent encrypted next-index, scan-end, and
last-used state. Legacy account records deserialize with deterministic defaults,
while legacy HNS coin address identifiers remain unchanged. Name-role address
identifiers include the role so the same branch/index cannot collide with an
ordinary receive address. A complete reconciliation persists the combined
account/address state only after the separate coin and name queries prove the
same chain epoch/tip and mempool instance/generation.
Reconciliation reloads the full authoritative account and its CAS revision
after taking the store mutex, rejects any derivation high-water rollback, and
holds that ordering through cache installation; a concurrently prepared send or
settlement cannot be overwritten by a stale scan clone.

Name-role scan advancement is monotonic and bounded across restart and reorg.
Outputs to discovered name keys remain visible to history/reconciliation but
are excluded from ordinary balance, input selection, reservations, and
spendable UTXOs. This persistence establishes key discovery only: it neither
populates authoritative name-owner outpoints nor converts current/proof owner
hints into ownership before canonical NameState decoding is integrated.

Before HNS submission, the runtime loads the exact persisted signed bytes and
prior quote, re-quotes only those bytes, and atomically saves the refreshed
quote with `RequiresRebroadcast` before invoking the node. That durable state
means submission may have started even if the caller sees an error or the
process exits; recovery rebroadcasts the same persisted bytes, never caller
replacement bytes. Stale snapshot or unavailable quote input triggers at most
one complete reconciliation and one quote retry, with no polling loop.

## Required startup sequence

The product runtime must:

1. securely open and migrate the database, remain locked, and request
   platform-backed unlock;
2. create fresh random wallet-service and wallet-session IDs with empty
   authority, approval, replay, rate, request-ID, and event registries;
3. negotiate a random host session plus exact restart generation over the
   private host/service transport; old handles and frames remain invalid;
4. finish any plaintext-migration checkpoint before exposing wallet state;
5. load persisted workflows, permission generations/tombstones, and the last
   consistent chain checkpoints;
6. resume HNS and Kyoto; keep Ethereum synchronization unavailable until its
   selected embedded adapter is implemented and qualified;
7. reconcile mempools, confirmations, replacements, and reorgs from atomic,
   validated evidence;
8. restore the bounded name-role scan, revalidate split committed-proof/current
   name views and Shakedex listings, and leave ownership watch-only until
   canonical state decoding;
9. expire price rounds, intents, fill grants, persisted workflow approvals, and replay rows only
   after their authenticated metadata verifies;
10. restore swap sessions and independently verify every recorded funding,
   redemption, and refund;
11. extract an on-chain preimage only from the exact verified spend/event;
12. determine refund eligibility from validated local chain time; and
13. surface user actions without automatically moving value.

The HNS source implements the concrete synchronous authenticated node adapter,
bounded coin/name-role chain/mempool snapshot reconciliation, and prepared-
transaction recovery. The learned durable chain epoch and process-instance/
generation pair remain exact across both scans, gap expansion, and all point
reads in one reconciliation;
they are intentionally reacquired after process restart rather than persisted
as timeless authority. Exact final-signed fee quotes are wired and persisted,
but released `hns-script` 0.1 lacks the canonical policy-size fee algebra needed
for independent validation; its explicit qualification gate remains false. The
complete multi-chain product supervisor and current qualification evidence are
not integrated, so HNS value operations remain release-gated.

No Ethereum synchronization, history, or recovery checkpoint exists to resume
in this revision. Ethereum account and receive-target derivation is offline;
online evidence and value paths remain behind unavailable opaque permits.

## Bitcoin Kyoto recovery journal

The Bitcoin module persists two coordinated stores. BDK SQLite is the durable
descriptor/local-chain/transaction/output authority. The encrypted wallet store
records an authenticated birthday, a distinct non-genesis new-wallet recovery
anchor, bounded recent checkpoints, supervisor sequence and phase,
transaction/output reconciliation mirrors, and signed broadcast intents.

A sync records `synchronizing`, applies the Kyoto update, persists BDK, records
`reconciling`, applies encrypted mirror changes in bounded chunks, and commits
`ready` last. Consumers must ignore an incomplete mirror unless the scan record
is ready at its completed sequence. Restart from `reconciling` compares the BDK
tip to the pending checkpoint and resumes the chunks without another network
update. A sync timeout discards the non-cancel-safe subscriber, shuts down the
node, and persists `recovery_required`; the poisoned supervisor cannot be
reused.

Broadcast preparation resolves every input through the same BDK wallet,
calculates the exact fee, verifies the approved maximum, and persists raw bytes
plus a network/txid/wtxid/fee/maximum/expiry commitment before Kyoto receives
them. A timeout after `submission_started` is restart-safe and retryable. This
retry observes the same rebroadcast interval as a known submission; approval
expiry is exclusive. Native-send signing and broadcast are dormant because the
Bitcoin value permit is release-gated.

Execution rejects a clock value behind the durable preparation or latest
attempt timestamp. A production release still requires a reviewed source of
trusted or monotonic time across process and device restart.

The pinned `bip157` 0.6.3 implementation ignores its configured `data_dir` and
does not expose durable headers, filter headers/filters, or peer address-book
state. Those databases cannot be truthfully restored by this source and remain
a release blocker. Canonically absent transaction/output records are retained;
safe archival is also pending, so the fixed lifetime caps fail closed.

## Migrations and backups

Opening a database with a newer schema fails. Schema upgrades are transactional.
After plaintext rows are encrypted and deleted, unlock records a checkpoint,
truncates the WAL, clears the marker, and truncates again; an interrupted
checkpoint is retried on the next unlock before state is returned.

Legacy schema-v1 provider grants and replay records have deterministic migration
paths. Legacy pending approvals are discarded because their creation time and
authority binding were not authenticated. Populated legacy funds-bearing entity
tables fail closed with `LegacyEntityMigrationRequired`; a dedicated import tool
must map them without ambiguity before unlock.

On Linux, persistent database opening requires an owner-only regular file in an
owner-only directory and uses SQLite's no-follow flag. Non-Linux persistent
opening intentionally fails until an equivalent native secure-open and
ownership policy exists. In-memory stores remain available for bounded tests.

Copying a live SQLite file without its WAL is not a supported backup procedure.
The passphrase is not a substitute for platform device security. Product backup
design must document wrapped key handling, seed inclusion, retained KDF
parameters, and stale-state rollback detection.
