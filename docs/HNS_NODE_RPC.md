# Handshake node wallet RPC adapter

`HnsNodeRpcBackend` is the concrete synchronous wallet-side adapter for the
authenticated `hns-node-rs` wallet RPC v1 contract frozen at node commit
`5ed38d15d50098191b4473d4dda66a93d4e3e6fc`. It implements `HnsBackend`; the
node supplies canonical chain evidence and broadcast admission while the wallet
alone derives keys, signs, approves, and persists workflows. The node never
signs.

## Trusted configuration and transport

`HnsNodeRpcConfig` accepts only an explicit loopback `SocketAddr` with a nonzero
port. It does not accept a URL, hostname, proxy, redirect target, or remote
address. The configured Authorization value must be 1..=4,096 bytes, contain
only visible ASCII (`0x20..=0x7e`), and have no leading or trailing space. Tabs,
controls, newlines, and non-ASCII bytes are rejected. The value is held in a
zeroizing container and every `Debug` implementation redacts it.

Connect, complete-write, and complete-read deadlines are independently bounded
and default to 5, 30, and 30 seconds. Each call opens one TCP connection and
sends exactly `POST /api/v1/wallet` with JSON, a decimal `Content-Length`, the
trusted Authorization value, and `Connection: close`.

The response parser accepts HTTP/1.1 fixed-length JSON only. It rejects
redirects, interim/upgrade responses, chunking, compression, duplicate header
names, malformed or conflicting lengths, oversized headers or bodies, wrong
content type, wrong API version or request ID, unknown/duplicate JSON fields,
result/error ambiguity, noncanonical stable error mappings, premature EOF, and
bytes after the declared body. Request serialization is capped at 1 MiB. The
node's 8 MiB serialized-result ceiling is enforced independently; the bounded
HTTP body allowance includes only fixed envelope and request-ID overhead.

The node listener defaults to a smaller 64 KiB request-body limit. Deployments
that restore large complete script sets must deliberately configure a larger
listener limit, never exceeding the node's 1 MiB hard maximum. A listener limit
failure is explicit and does not cause the adapter to split a logically atomic
script-set query.

## Snapshot and evidence rules

The first confirmed page learns the durable `u64` chain epoch. Every page must
match the complete requested tip, and every later block-hash, mempool,
transaction, spender, and name read is bound to that epoch and tip. Confirmed
cursors are opaque bytes tied to the exact sorted ScriptId set. Mempool pages
add a nonzero process-instance nonce and generation; both remain exact across
all continuations, gap-limit expansion, transaction/parent reads, and workflow
reconciliation. Any difference discards the partial snapshot.

The ordinary receive/change branches and the domain-separated `HnsName` branch
use separate bounded script queries. The name query is accepted only under the
exact chain binding and mempool binding learned by the coin query, so neither
query can reduce the other's lookahead or combine observations from different
node views.

ScriptId derivation hashes the canonical address bytes
`[version, hash_length_u8, hash...]` with BLAKE2b-256, sorts the resulting IDs,
and retains a checked reverse map to wallet derivations. Response hex is
lowercase and canonical. Addresses, canonical covenant bytes, confirmed UTXO
inclusion heights, raw transactions, txids,
outpoint echoes, cursor lengths, collection bounds, fee evidence, inclusion
counts, optional transaction positions, and optional exact block/admission
times are validated before projection into wallet types.

`quote_transaction_fee` binds the exact final signed transaction bytes to the
current chain epoch/tip, mempool instance/generation, and requested confirmation
target. The adapter verifies canonical raw bytes, txid, transaction weight,
policy virtual bytes, sigop cost, rate source/sample bounds, actual fee,
minimum fee, shortfall, and the node's `meets_minimum` relationship before
projecting the quote into wallet state. The wallet supplies the exact ordered
input coins reconstructed from persisted inclusion/address/covenant evidence;
the adapter and final workflow validator independently recompute weight,
sigops, sigop-adjusted policy virtual size, minimum fee, and actual fee with the
pinned `hns-script` implementation. Legacy rows without that evidence and any
outpoint/covenant/name-lock mismatch are unusable as inputs.

The send and exposed settlement signing paths are wired to sign first and quote
those exact bytes. Authorization peeks at the authenticated approval without
consuming it; after signing and quote validation, one SQLite transaction
consumes the unchanged approval, persists the authorized workflow with exact
raw bytes and quote, and activates the matching input reservations. Immediately
before submission the wallet re-quotes only the persisted bytes, commits the
refreshed quote and `RequiresRebroadcast` state, and then submits those same
bytes. A stale snapshot or temporarily unavailable quote input permits exactly
one complete reconciliation and one quote retry; there is no polling loop.

The reviewed immutable `hns-script` 0.2 source now supplies transaction sigops,
sigop-adjusted policy size, minimum-fee construction, and standard weight/
sigop bounds directly to the wallet. No local formula is copied. This source
has not passed consolidated wallet qualification, so
`HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` remains `false` and the wired quote
path still cannot authorize value.

Confirmed coinbase identity is preserved exactly, but coinbase outputs are
conservatively excluded from selection. No local maturity constant is invented;
canonical node-projected maturity evidence and qualification are required
before an HNS value release can make those outputs spendable.

Ordered spend queries are chunked at the frozen 256-outpoint wire maximum; each
batch preserves and validates every requested outpoint echo and binding.
Every unique spender block and every confirmed transaction/name-owner inclusion
is cross-checked through the epoch-bound active-chain block-hash method before
the runtime accepts it.
Name responses preserve the exact canonical current/proof NameState bytes and
strict Urkel proof bytes. The adapter decodes each raw state under the requested
name hash and requires every projected name, height, owner, value, resource,
transfer, renewal, claim, and flag field to equal it. The HNS runtime separately
checks strict proof inclusion, owner txid/index, exact output value, name
covenant and typed TRANSFER/FINALIZE shape. Current resources are retained only
when byte-identical to decoded `resource_data`; malformed typed DNS data remains
lossless canonical opaque data rather than invalidating consensus state.
For a TRANSFER owner, canonical NameState transfer height must equal that owner
transaction's active-chain inclusion height. A non-TRANSFER owner is rejected
while transfer height remains nonzero; FINALIZE is not incorrectly bound to its
own inclusion height.

## Release policy

This adapter removes the missing source boundary; it does not by itself enable
value movement. `HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` remains `false`, runtime
configuration rejects HNS send and settlement on every network. Imported names
now retain authoritative decoded metadata and account-bound ownership status,
while the context-free library import reports ownership as explicitly
unevaluated instead of claiming `NotWalletOwned`. That persisted status cannot
authorize value. `verify_name_ownership`
reacquires a non-serializable authority from the exact live snapshot and only
for a registered, unexpired, unrevoked, non-transferring owner output matching a
persisted `HnsName` derivation. Shakedex/HTLC descriptor or preimage transport
remains unavailable until protocol qualification, canonical fee-quote
integration, product integration, and the recorded gates land. Ordinary HNS send
and the exposed settlement lock, redeem, and refund paths are within this quote
boundary. Name transfer and FINALIZE transaction construction are not exposed
here and are not implied to be complete.

Focused and consolidated evidence for this source is recorded only in
[QUALIFICATION.md](QUALIFICATION.md); no test result changes a value gate.
