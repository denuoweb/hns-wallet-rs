# Security model

Status: experimental. Mainnet marketplace settlement is disabled.

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
- Ethereum availability still depends on configured consensus and execution
  data providers. The selected Helios model is intended to verify consensus
  and execution evidence, but providers may censor, omit, delay, correlate, or
  make the wallet unavailable.

## Secrets

Recovery seeds, imported private keys, HTLC preimages, metadata keys, provider
capabilities, and session authorizations use per-record XChaCha20-Poly1305 with
random nonces and associated data binding database ID, record kind, and record
ID. The database key is derived with Argon2id. Secret buffers use zeroizing
containers where practical.

This is authenticated record encryption, not whole-file encryption. Table
names, row counts, indexes, timestamps, non-sensitive workflow JSON, filenames,
SQLite journals, and access patterns may be visible. A platform integration
must wrap the database key with Android Keystore/iOS Keychain/OS secure storage
and protect backups. That platform wrapping is not implemented in this repo.

Recovery-phrase display is a dedicated high-risk mobile operation. The stable
ABI rejects it over Chromium native messaging. Logs and ordinary `Debug`
implementations redact signing transactions, phrases, keys, and preimages.

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
nonces, replay persistence, per-method windows, approval expiry, permission
generation, and stale-navigation rejection. It explicitly rejects seed/key
extraction, raw signing, PSBT signing, generic Ethereum transactions/calls,
chain switching, and arbitrary native-host access.

## Atomic-swap limits

HTLCs can prevent unilateral theft when scripts, transactions, confirmation
depth, contract code/state/events, timeouts, and preimages are verified. They
do not prevent non-cooperation, fee spikes, chain congestion, censorship,
privacy leakage, delayed refunds, adverse price movement, or liquidity griefing.
Timeouts must be asymmetric and refunds must be constructed and validated
before funding.

Current cross-chain code is not qualified for live value. Bitcoin signed HTLC
spend/broadcast integration, Helios proof construction, complete HNS adapters,
restart/reorg demonstrations, real-chain tests, resource benchmarks, and an
independent contract review remain blockers.

## Reporting

Do not include live seeds, keys, database files, preimages, capability tokens,
or production origin receipts in a report. Provide a minimal non-secret
reproducer and exact repository revision.
