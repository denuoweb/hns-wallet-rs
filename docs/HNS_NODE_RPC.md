# Handshake node wallet RPC adapter

`HnsNodeRpcBackend` is the concrete synchronous wallet-side adapter for the
authenticated `hns-node-rs` wallet RPC v1 contract frozen at node commit
`74f7ae36ddfd4a396451d33a2bca1c71a04f8a75`. It implements `HnsBackend`; the
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

Fee-response target, source, sample count, and rate bounds are validated, but
the returned unit is atomic units per 1,000 HSD sigop-adjusted policy virtual
bytes. The dormant wallet transaction builder still sizes fees by transaction
weight and therefore must not use that value as release authority. Canonical
policy-size integration is an explicit HNS value-release blocker; the global
value gate prevents the mismatched calculation from becoming executable.

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
scanning, product integration, and the recorded qualification gates land.

No local build or test result was produced for this tranche. The next evidence
event is the single consolidated CI gate described in
[QUALIFICATION.md](QUALIFICATION.md).
