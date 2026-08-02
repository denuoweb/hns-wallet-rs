# Security model

Status: production-hardening source implemented; executable value paths remain
release-gated. HNS send/settlement are disabled on every network and mainnet
marketplace settlement is independently disabled.

## Trust boundaries

- The website is hostile. It cannot supply an authenticated origin, select a
  browser namespace, reuse another navigation, or send native-host commands.
- Browser authority context is stamped by the browser product and binds exact
  logical origin, namespace, authority session/generation, policy generation,
  wallet session, permission generation, and navigation generation.
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
- Ethereum availability still depends on configured consensus and execution
  data providers. The selected Helios model is intended to verify consensus
  and execution evidence, but providers may censor, omit, delay, correlate, or
  make the wallet unavailable.

## Secrets

Recovery seeds, imported private keys, HTLC preimages, wallet/workflow state,
provider capabilities, pending approvals, and replay origins use per-record
XChaCha20-Poly1305 with random nonces. Associated data binds the database ID,
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

Recovery-phrase display is a dedicated high-risk mobile operation. The stable
ABI rejects it over Chromium native messaging. Logs and ordinary `Debug`
implementations redact signing transactions, phrases, keys, and preimages.
Bitcoin swap-key handles additionally keep their secret half private,
non-serializable and non-cloneable, redact it from `Debug`, and zeroize the
32-byte scalar on drop. Their public recovery coordinates contain no secret.

## Money and transaction approval

Amounts are integer base units serialized to JavaScript as decimal strings.
Arithmetic is checked; prices and fees never use floating point. Value-moving
methods require an expiring approval bound to origin and every browser/wallet
generation. Production UI must display asset, exact amount, recipient, fee
maximum, chain, finality policy, price-round commitment, and refund timeout.

The library supplies the policy and state boundary; the current browser UI does
not yet provide every approval screen. No mainnet enablement may infer approval
from a unit test.

## Provider defenses

The provider core enforces secure exact origins (with loopback HTTP allowed for
development), origin-scoped permissions, bounded frames/methods/params, request
nonces, replay persistence, per-method windows, approval expiry, and
stale-navigation rejection. Authority generations cannot regress within one
authority/wallet session; random session identifiers are treated as identities,
not counters. Permission creation may bootstrap from a trusted nonzero
generation, then every grant or revocation must advance exactly once. Revocation
stores an authenticated tombstone so delete/regrant cannot reset the generation.
It explicitly rejects seed/key extraction, raw signing, PSBT signing, generic
Ethereum transactions/calls, chain switching, and arbitrary native-host access.

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
Settlement lock verification binds the exact funding outpoint, output index,
script, terms and confirmation policy, and preimage observation accepts only the
exact verified redeem witness.

Name proof evidence is bound to the exact chain epoch, tip height and tip tree
root, and the verified Urkel bytes must equal the separately returned proof
state. The interval-committed proof view is not collapsed with the current node
view. Because released protocol crates do not yet decode canonical NameState
owner/resource/transfer/renewal fields, imported names remain watch-only;
current/proof owner hints and raw resource bytes are not authorization evidence.

Current cross-chain code is not qualified for live value. The concrete HNS node
adapter source is present, but its consolidated qualification, released
canonical HNS name-state/resource decoding, a published canonical HNS
settlement profile, canonical HSD sigop-adjusted fee sizing, Bitcoin supervisor
qualification, Helios proof construction, restart/reorg demonstrations,
real-chain tests, resource benchmarks, and independent review remain blockers.

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
