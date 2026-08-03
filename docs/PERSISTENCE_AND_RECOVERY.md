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

An HNS Accounts permission generation persists the exact bounded account-ID
set selected for that origin and namespace. The service validates and encodes
the minimized `hns_requestAccounts` result before the scoped permission write;
after restart, `hns_accounts` projects only that authenticated set. Legacy or
generic records that claim Accounts without an account binding are rejected,
not migrated into broader authority. The write must compare equal to the
generation authenticated by the approval, so a concurrent grant or revocation
makes that approval stale instead of rebinding it to newer authority. Runtime
selection and website approvals remain process-local and must be reacquired
after restart.

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
partial batch becomes visible. Secret record IDs cannot change kinds; recovery
seed bytes are additionally immutable once inserted.

The fixed-price Denuo board is one versioned encrypted `DenuoBoardObject` with
an explicit 4,096-offer/watermark bound and a store-owned CAS revision. It
retains one canonical latest listing/cancellation record plus network/genesis,
name hash, seller key, expiry, status, and the exact highest observed sequence
for each seller/name identity. A higher valid listing replaces that identity's
older record without consuming another slot. Load re-decodes every object and
rejects unsorted, duplicate, mismatched, rolled-back, or malformed state. A
cancellation tombstone advances the watermark, so restart cannot make the
cancelled listing active or admit the same sequence under another content hash.
The signed listing target can be re-authenticated from these bytes to process a
still-active cancellation after restart without recreating locking-coin
authority. After the listing or cancellation's signed horizon expires, bounded
inventory filtering hides the object but retains its authenticated watermark,
so a later listing cannot reset or reuse the seller/name sequence. Relisting
the same identity replaces its stored object without growing the board. The
4,096-distinct-identity ceiling fails closed; durable archival and peer
admission policy remain required for a live relay. The cache does not persist
an action capability; current locking-coin/network/time authority must be
reacquired before a listing can drive value behavior.

Dormant Shakedex transaction plans use the encrypted seller or buyer workflow
journal and its exact expected revision. Fulfillment plans retain the canonical
seller-controlled prefix and caller-supplied buyer suffix; recovery plans bind
the exact lock descriptor and explicit recovery recipient. Script-controlled
FINALIZE construction is typed but remains memory-only until a durable plan is
added. Exact retries may revalidate the same persisted plan, while a stale
revision or changed canonical plan fails instead of replacing previously
prepared bytes. This CAS state is crash-recovery and audit data only. On every
resume, the product must reacquire current/unspent lock evidence, active-chain
NameState and renewal evidence, authoritative parent MTP, wallet funding and
reservations, signing approval, fee evidence, and broadcast/reorg state. A
persisted or newly supplied Coin, MTP, or NameState never restores those
authorities.

HNS authorization can authenticate and return a pending approval without
consuming it. After exact signed-byte fee quoting succeeds, a bounded immediate
transaction re-authenticates that unchanged approval together with the current
workflow and reservation revisions, activates the reservations, saves the
authorized workflow/raw bytes/quote, and only then deletes the approval. Any
stale revision, changed approval, signing error, or quote error leaves the
approval and workflow state unconsumed.

Wallet-owned name preparation uses the same atomic boundary. The canonical
name source has a `Name` reservation carrying its exact name hash, while fee
inputs have `Ordinary` reservations; both sets must exactly match the encrypted
plan. Authorization activates the complete set before broadcast. Broadcast
name workflows retain those reservations through `TransferLocked`,
`FinalizeEligible`, `Finalized`, and confirmed transfer-cancellation tracking,
because any of those confirmations can disappear on reorg. Expiry, explicit
cancellation, or conflict releases them atomically. A formerly confirmed action
that disappears becomes `ReapprovalRequired`; replacing an explicitly
abandoned record requires a fresh request nonce and approval.

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
authorizes an action nor treats a node hint as ownership. Fresh reconciliation
independently decodes the split current/proof NameState bytes, binds exact owner
transactions and resource bytes, and persists canonical summaries plus
account-bound `HnsName` ownership or transfer direction. Legacy rows keep their
watch-only variant until replaced. Context-free imports authenticate canonical
state but mark wallet ownership explicitly unevaluated. Runtime imports recheck
the exact cache binding while holding the store lock immediately before their
CAS write, so a concurrent reconciliation cannot be overwritten with stale
evidence. Account, address, name, coin, transaction, and reservation reloads
query the complete bounded binary ID prefix for the selected wallet/account
(and the dedicated name role where applicable); a global list limit is never
applied before account filtering. Workflow IDs remain opaque, so recovery and
transaction lookup read the complete bounded kind or fail closed on overflow
before filtering decrypted account ownership. An action must reacquire
ephemeral ownership authority from the exact current snapshot; the encrypted
cache is UI/recovery state only.

Before HNS submission, the runtime loads the exact persisted signed bytes and
prior quote, re-quotes only those bytes, and atomically saves the refreshed
quote with `RequiresRebroadcast` before invoking the node. That durable state
means submission may have started even if the caller sees an error or the
process exits; recovery rebroadcasts the same persisted bytes, never caller
replacement bytes. Stale snapshot or unavailable quote input triggers at most
one complete reconciliation and one quote retry, with no polling loop.
Snapshot-only advancement does not invalidate an otherwise unchanged name
plan: the wallet revalidates the stable owner source and transaction-defining
terms, then reacquires against the final quote's chain/mempool binding. A
changed source or FINALIZE renewal commitment persists
`ReapprovalRequired`; cancellation releases its reservations, and replacement
uses a fresh nonce and approval.

TRANSFER/FINALIZE reconciliation follows the same persist-before-broadcast
rule and reconciles the exact persisted signed transaction by txid and
available raw-byte equality, together with confirmation arithmetic, competing
spenders, the transfer output's subsequent covenant, current candidate
maturity, renewal evidence, and owner mempool spender. It never restores an
ephemeral ownership or finalize authority from disk.

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
   name views, replace legacy watch-only rows with exact canonical summaries,
   and reacquire rather than restore any ephemeral ownership authority;
9. expire price rounds, intents, fill grants, persisted workflow approvals, and replay rows only
   after their authenticated metadata verifies;
10. restore swap sessions and independently verify every recorded funding,
   redemption, refund, and Shakedex plan against newly acquired chain
   authority;
11. extract an on-chain preimage only from the exact verified spend/event;
12. determine refund eligibility from validated local chain time; and
13. surface user actions without automatically moving value.

The HNS source implements the concrete synchronous authenticated node adapter,
bounded coin/name-role chain/mempool snapshot reconciliation, and prepared-
transaction recovery. The learned durable chain epoch and process-instance/
generation pair remain exact across both scans, gap expansion, and all point
reads in one reconciliation;
they are intentionally reacquired after process restart rather than persisted
as timeless authority. Exact final-signed fee quotes are wired and persisted;
canonical fee-policy integration is implemented in source, but its explicit
qualification gate remains false. The complete multi-chain product supervisor
and current qualification evidence are not integrated, so HNS value operations
remain release-gated.

No Ethereum synchronization, history, or recovery checkpoint exists to resume
in this revision. Ethereum account and receive-target derivation is offline;
online evidence and value paths remain behind unavailable opaque permits.

## Bitcoin Kyoto recovery journal

The Bitcoin module persists two coordinated stores. BDK SQLite is the durable
descriptor/local-chain/transaction/output authority. The encrypted wallet store
records an authenticated birthday, a distinct non-genesis new-wallet recovery
anchor, bounded recent checkpoints, supervisor sequence and phase,
transaction/output reconciliation mirrors, and signed broadcast intents.

Bitcoin swap keys add an encrypted entity namespace without a plaintext schema
table or seed copy. Each role allocation atomically writes an immutable
wallet/session/role binding and redundant binding claim while advancing its
network/account/role high-water record alongside a fixed namespace anchor. The
binding authenticates the scheme version, exact reference, compressed public
key, recovery-seed commitment, opaque frozen-terms commitment, and allocation
time. Existing exact bindings are idempotent; the store rejects generic single
or batch deletion of allocation rows. Recovery seeds are insert-once and may be
reinserted only with identical bytes; replacement or generic deletion is
rejected. Recovery re-derives from that encrypted seed and requires exact seed-
commitment and public-key matches before returning the zeroizing in-memory
secret handle. Counter, reference, record-kind, revision, time, or terms
mismatch fails closed.

The allocation-specific KDF additionally binds wallet ID, session ID, and terms
commitment, so a stale or copied counter cannot reuse a key for a different
logical swap. A full database snapshot rollback cannot be detected solely from
inside the rolled-back database and can still lose an active binding or choose
a different numeric reference. Session IDs must never be recycled, and a
current encrypted database backup is required to recover already active swaps;
the mnemonic alone is not an allocation journal.

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
