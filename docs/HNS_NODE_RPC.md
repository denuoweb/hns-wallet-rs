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

ScriptId derivation hashes the canonical address bytes
`[version, hash_length_u8, hash...]` with BLAKE2b-256, sorts the resulting IDs,
and retains a checked reverse map to wallet derivations. Response hex is
lowercase and canonical. Addresses, covenants, raw transactions, txids,
outpoint echoes, cursor lengths, collection bounds, fee evidence, inclusion
counts, optional transaction positions, and optional exact block/admission
times are validated before projection into wallet types.

`quote_transaction_fee` binds the exact final signed transaction bytes to the
current chain epoch/tip, mempool instance/generation, and requested confirmation
target. The adapter verifies canonical raw bytes, txid, transaction weight,
policy virtual bytes, sigop cost, rate source/sample bounds, actual fee,
minimum fee, shortfall, and the node's `meets_minimum` relationship before
projecting the quote into wallet state.

The send and exposed settlement signing paths are wired to sign first and quote
those exact bytes. Authorization peeks at the authenticated approval without
consuming it; after signing and quote validation, one SQLite transaction
consumes the unchanged approval, persists the authorized workflow with exact
raw bytes and quote, and activates the matching input reservations. Immediately
before submission the wallet re-quotes only the persisted bytes, commits the
refreshed quote and `RequiresRebroadcast` state, and then submits those same
bytes. A stale snapshot or temporarily unavailable quote input permits exactly
one complete reconciliation and one quote retry; there is no polling loop.

The released `hns-script` 0.1 API does not expose the canonical HSD
sigop-adjusted policy-size/fee algebra needed for an independent wallet check
of the node's minimum. The wallet must not copy that consensus/policy formula.
`HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED` therefore remains `false`, so the
wired quote path cannot authorize value until a released canonical helper is
integrated and qualified.

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
strict Urkel proof bytes. Projected name fields are checked for structural and
transaction consistency but are not reconstructed into canonical state or
used as ownership/resource authority.

## Release policy

This adapter removes the missing source boundary; it does not by itself enable
value movement. `HNS_VALUE_RUNTIME_RELEASE_QUALIFIED` remains `false`, runtime
configuration rejects HNS send and settlement on every network, imported names
remain watch-only, and Shakedex/HTLC descriptor or preimage transport remains
unavailable until published canonical `hns-rs` 0.2 types, dedicated name-role
scanning, canonical fee-quote algebra, product integration, and the recorded
qualification gates land. Ordinary HNS send and the exposed settlement lock,
redeem, and refund paths are within this quote boundary. Name transfer and
FINALIZE transaction construction are not exposed here and are not implied to
be complete.

No local build or test result was produced for this tranche. The next evidence
event is the single consolidated CI gate described in
[QUALIFICATION.md](QUALIFICATION.md).
