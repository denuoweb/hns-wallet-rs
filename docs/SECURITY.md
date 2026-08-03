# Security model

Status: production-hardening source implemented; executable value paths remain
release-gated. HNS send/settlement and Ethereum synchronization/history/send/
settlement are disabled on every network. Chain ID 1 and all other mainnet
marketplace settlement are independently disabled.

## Trust boundaries

- The website is hostile. It cannot supply an authenticated origin, select a
  browser namespace, reuse another navigation, or send native-host commands.
- The browser product retains the engine-issued, nonserializable authority. Its
  native host registers only engine-derived origin/namespace/runtime/policy/
  navigation facts over a private child pipe and issues a random opaque handle.
  The page cannot supply the handle or any authority fact as authentication.
- Service, wallet, and host sessions are random identities. Restart and
  authority revisions plus directional channel/event sequences are checked
  exactly. Wallet lock state and permission generation are service-owned.
- The reusable host state machine owns its authorization clock and operating-
  system entropy, mints all private host/request/authority identifiers and
  provider nonces, correlates a bounded pending set, and treats responses and
  events as one exact service-direction sequence. UI callers cannot choose
  authority revisions, approval ownership, provider bindings, or expiry time.
  Mandatory approval response classes, non-reusable approval IDs, negotiated
  method capabilities, and exact permission/session transitions are enforced
  again at this caller-side boundary.
- The wallet database and keys live in a native/mobile wallet process. Website
  JavaScript, extension local storage, and native-messaging frames never carry
  seed or raw private-key bytes.
- Denuo/Brontide authenticates a connection, not a listing, price, fill, chain
  state, or peer claim. Canonical signatures and local chain evidence decide.
- Bitcoin production synchronization has one backend: Kyoto direct P2P with
  BIP157/158. There is no trusted indexer fallback.
- Handshake node evidence crosses one authenticated loopback HTTP/1.1 boundary.
  Loopback is not authorization: the wallet requires an exact, bounded,
  visible-ASCII Authorization value and rejects redirects, remote endpoints,
  ambiguous HTTP framing, and noncanonical RPC envelopes.
- The source models Helios-shaped evidence but has no embedded verifier that can
  produce its opaque authorization permit. Caller-serializable verification
  booleans are structural consistency inputs only. A future selected Helios
  runtime and its consensus/execution providers may still censor, omit, delay,
  correlate, or make the wallet unavailable.

## Secrets

Recovery seeds, imported private keys, HTLC preimages, wallet/workflow state,
provider permissions, and persisted workflow approvals/replay origins use
per-record XChaCha20-Poly1305 with random nonces. ABI v2 provider approvals and
handle replay windows are memory-only and disappear on service restart.
Associated data binds the database ID,
record kind and ID, and every plaintext metadata column used for authorization,
expiry, revision, revocation, or broadcast decisions. The database key is
derived with Argon2id. Secret buffers use zeroizing containers where practical.
The store rejects empty passphrases and inputs larger than 1,024 bytes at its
own API boundary; this is a resource/safety bound, not a substitute for device
key wrapping or a password-strength policy.

This is authenticated record encryption, not whole-file encryption. Table
names, row counts, indexes, selected authenticated metadata, filenames, SQLite
journals, and access patterns may be visible. On Linux, persistent opening
requires an owner-only regular file in an owner-only directory and rejects
symlink traversal. Other persistent platforms fail closed until an equivalent
native policy is implemented. A product integration must wrap the database key
with Android Keystore/iOS Keychain/OS secure storage and protect backups; that
wrapping is not implemented in this repo.

Recovery-phrase display remains a dedicated high-risk native/mobile concern and
is absent from the private service/provider ABI. Logs and ordinary `Debug`
implementations redact signing transactions, phrases, keys, and preimages.
Inbound passphrases and restore phrases use non-cloneable, redacted ABI secret
values whose owned allocations are zeroized on drop. Host-frame encoding, its
temporary JSON payload, and the checked-in service's inbound frame allocation
are also zeroized on drop; platform transports must not copy those
secret-bearing bytes into ordinary persistent buffers.
New host/service/wallet session IDs, authority handles, fingerprints, request
IDs, and approval IDs also redact `Debug` and `Display`; only their canonical
wire serializers reveal the value to the private transport.
Bitcoin swap-key handles additionally keep their secret half private,
non-serializable and non-cloneable, redact it from `Debug`, and zeroize the
32-byte scalar on drop. Their public recovery coordinates contain no secret.

## Money and transaction approval

Amounts are integer base units serialized to JavaScript as decimal strings.
Arithmetic is checked; prices and fees never use floating point. Value-moving
methods require a typed approval of at most 90 seconds bound to the service
session and exact authority handle/revision. Production UI must display asset,
exact amount, recipient, fee maximum, chain, finality policy, price-round
commitment, and refund timeout. Free-form approval display lines are rejected.

The library supplies the policy and state boundary; the current browser UI does
not yet provide every approval screen. No mainnet enablement may infer approval
from a unit test.

For ordinary HNS sends, the persisted workflow approval is authenticated
without consumption before signing. Only after the exact final signed bytes
receive a bound fee quote does one immediate transaction re-authenticate and
consume the unchanged approval, persist those bytes and quote, and activate the
matching reservations. Submission re-quotes the persisted bytes and records
`RequiresRebroadcast` before the node call. The released canonical
sigop-adjusted fee algebra is still unavailable, so its explicit false gate
prevents this source wiring from authorizing value and the wallet does not copy
the node's policy formula.

## Provider defenses

The provider core enforces secure exact origins (with loopback HTTP allowed for
development), origin-scoped persisted permissions, bounded methods/params,
ephemeral handle-bound request nonces, per-method windows, 90-second approval
expiry, and exact authority revisions. Replacement cannot change origin,
namespace, or runtime session and cannot regress runtime, policy, or navigation
generation. The service owns wallet session/lock state and reads permission
generation from the encrypted store. Permission creation begins at generation
one; every later grant or revocation advances the stored generation exactly
once. Revocation stores an authenticated tombstone so delete/regrant cannot
reset the generation. Service restart intentionally drops authorities,
approvals, replay/rate state, request IDs, and event cursors while permissions
survive.
Host restart/reset independently drops every service-derived handle revision,
pending request and approval, private binding, and event cursor. A response
kind mismatch, stale session, sequence gap/replay, unknown request ID, or stale
binding fails closed instead of advancing partial host state. Trusted-clock
rollback likewise poisons the private session and requires explicit restart.
Detached, stale, or expired host facts may be discarded, but their random
handles remain reserved for the lifetime of the host process.
Permission-change events clear every same-origin and same-namespace derived
binding and reset the global event-cursor domain exactly as the service does;
wallet-lock events clear provider state globally before further use.
It explicitly rejects seed/key extraction, raw signing, PSBT signing, generic
Ethereum transactions/calls, chain switching, and arbitrary native-host access.

The signed-artifact manifest schema is structural only. It contains no trusted
public key and cannot authorize itself. A product verifier must own its trust
roots, verify the artifact and canonical signed payload, persist a per-release-
line rollback high-water mark, and bind that evidence to process launch. No such
verifier is wired here, so a schema-valid manifest does not make the wallet
available.

## Atomic-swap limits

HTLCs can prevent unilateral theft when scripts, transactions, confirmation
depth, contract code/state/events, timeouts, and preimages are verified. They
do not prevent non-cooperation, fee spikes, chain congestion, censorship,
privacy leakage, delayed refunds, adverse price movement, or liquidity griefing.
Timeouts must be asymmetric and refunds must be constructed and validated
before funding.

HNS evidence requests bind a chain epoch, tip and mempool generation across
bounded sorted exact version-0 address pages. A nonzero node-instance nonce
prevents a generation reset after restart from reusing an old cursor. Transaction,
parent-output and outpoint-spend evidence must match that same snapshot.
The separate ordinary-coin and `HnsName` scans must share that exact chain and
mempool binding. Name-role outputs are tracked for history but excluded from
ordinary balance, selection, reservation, and spendability.
The scan reloads the authoritative encrypted account revision while holding the
store mutex and rejects derivation high-water rollback before replacing cache
state, so concurrent workflow preparation cannot be lost to stale reconciliation.
Settlement lock verification binds the exact funding outpoint, output index,
script, terms and confirmation policy, and preimage observation accepts only the
exact verified redeem witness.

Name proof evidence is bound to the exact chain epoch, tip height and tip tree
root, and the verified Urkel bytes must equal the separately returned proof
state. The interval-committed proof view is not collapsed with the current node
view. Because released protocol crates do not yet decode canonical NameState
owner/resource/transfer/renewal fields, imported names remain watch-only;
current/proof owner hints and raw resource bytes are not authorization evidence.

Ethereum has no embedded Helios proof producer in this revision. Its exact
synchronization, value-runtime, settlement-runtime, and mainnet gates are
immutable and false; history shares the synchronization gate. Opaque permits
for transaction construction and verified locks cannot be issued. Helios
provenance has no public release-flag issuer and verified locks
also require settlement permission. Redeem preimages, signing intermediates,
and final signed bytes remain contained: preimages are non-Clone and zeroize on
drop, transient signing buffers use zeroizing owners, and the final signed
artifact is non-Clone, zeroizing, and redacted with no public raw-byte accessor.
Serializable observation fields are structural data only and cannot authorize
settlement.

Current cross-chain code is not qualified for live value. The concrete HNS node
adapter source is present, but its consolidated qualification, released
canonical HNS name-state/resource decoding, a published canonical HNS
settlement profile, released canonical HSD sigop-adjusted fee algebra, Bitcoin
supervisor qualification, embedded Helios proof construction/persistence,
name-role scan qualification, restart/reorg
demonstrations, real-chain tests, resource benchmarks, and independent review
remain blockers.

Bitcoin swap keys now have a deterministic application-private HKDF domain
which is disjoint from ordinary BIP84 receive/change derivation and binds the
coin type, exact network, bounded account/index, and receiver/refund script
role. The HTLC constructor enforces that local role. This separation does not
enable settlement: the scheme version and exact key coordinates are not yet
authenticated and durably allocated with each session, deterministic
regeneration is not discovery, and signed-spend supervision and the complete
qualification boundary are still absent. No Bitcoin signing or value permit is
exposed by this key slice.

Bitcoin's supervisor does not authorize from a peer status field. A completed
Kyoto wallet update is committed to BDK SQLite before encrypted transaction and
output mirrors advance; the authenticated scan record becomes ready only after
all bounded reconciliation chunks commit. Exact local-chain hash-membership
queries identify a retained reorg ancestor. Missing ancestry, capacity
exhaustion, timeout of the non-cancel-safe update, or BDK/encrypted-state
rollback mismatch fails closed and requires a new supervisor/recovery scan.

The dormant broadcast path resolves every input as an unspent wallet output,
uses BDK's exact fee calculation, and verifies a domain-separated approval over
network, txid, wtxid, exact fee, approved maximum, and expiry. It persists
`submission_started` before a timeout-bounded P2P send and also requires ready
state, a live node, and peer quorum. Approval expiry is exclusive and an
ambiguous `submission_started` attempt must wait the rebroadcast interval
before retry. Native-send signing and broadcast require the value permit, which
remains unobtainable in this revision.

The journal rejects wall-clock rollback behind durable preparation or attempt
timestamps. This fail-closed check does not replace a reviewed trusted-time or
monotonic-clock source, which remains a Bitcoin value-release requirement.

Pinned `bip157` 0.6.3 discards `data_dir` and does not expose persistent header,
filter-header/filter, or address-book state. BDK checkpoints and wallet records
are durable, but they do not fill that light-client persistence gap. Bitcoin
send/settlement therefore remain disabled pending a reviewed Kyoto boundary,
adversarial/restart/reorg qualification, resource measurements, and audit.

## Reporting

Do not include live seeds, keys, database files, preimages, capability tokens,
or production origin receipts in a report. Provide a minimal non-secret
reproducer and exact repository revision.
