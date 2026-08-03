# Ethereum narrow settlement module

This is not a MetaMask-compatible provider. The current source supports
deterministic offline account derivation with separate ordinary/swap
derivation branches plus dormant typed native-ETH/HTLC primitives. It does not
currently expose synchronization, balance/history, send, signing, or settlement:
their immutable release-qualification gates are false. There are no tokens,
NFTs, arbitrary calldata/calls,
deployment through websites, chain switching, custom RPCs, WalletConnect,
staking, DeFi, or `window.ethereum`.

## Selected synchronization model

Helios is selected, pinned for integration review at upstream revision
`43a8c9f3cdda41a6f383c4db41d9a83f102638b1`. The intended model uses a recent
weak-subjectivity checkpoint, sync-committee/finality verification, verified
execution headers, and account/code/storage/transaction/receipt evidence bound
to execution roots.

Execution and consensus providers remain availability/privacy dependencies.
They may censor, omit, delay, correlate, equivocate below accepted proof/finality
thresholds, or make startup unavailable. Wrong-chain, stale, unfinalized,
proof-incomplete, unexpected-code, and reorged evidence fails closed.

The Rust crate currently defines structural chain/code/state/receipt/event
binding inputs, but does not embed a Helios runtime that produces
cryptographically unforgeable evidence tokens. Public serializable observations
and their verification booleans are not proof authority. An opaque Helios
evidence permit that current source cannot issue is required before structural
evidence can become a verified lock. Therefore Ethereum synchronization,
history, sending, and marketplace settlement are unavailable.

## Capability and permit boundary

Capability discovery exposes deterministic offline receive derivation only.
The exact synchronization, value-runtime, settlement-runtime, and mainnet
qualification constants are independently `false`; history shares the false
synchronization gate. Transaction constructors,
fee-bound role/address signing, and authoritative lock verification require
opaque permits with no available issuer. Typed builders, validators, and the
contract are dormant source boundaries, not an executable runtime. Redeem
preimages and signing intermediates are zeroized; the final signed bytes are a
non-cloneable redacted controlled-broadcast artifact with no public raw-byte
accessor.

## Contract

`contracts/src/NativeEthHtlc.sol` is one Solidity 0.8.35 contract with no
administrator, owner, proxy, upgrade, pause, token, fee withdrawal, fallback
application, or mutable configuration. It supports only:

```text
lock(swapId, hashlock, receiver, refundAddress, timelock) payable
redeem(swapId, preimage)
refund(swapId)
```

Each swap ID is single-use. The exact `msg.value` is frozen. Redeem requires
the receiver, SHA-256 preimage, and locked state. Refund requires the refund
address, elapsed timestamp, and locked state. Terminal state is recorded before
the value transfer, so reentrancy cannot repeat a payout; a failed transfer
reverts the transition. Events bind the terms and outcome.

The deterministic compiler package pins solc 0.8.35, optimizer runs 200,
Prague EVM, and no metadata CBOR. Its lockfile overrides the compiler wrapper's
temporary-file package to the audited patched line.

## Deployment policy

No deployment address is approved or checked in. A release manifest must bind
chain ID, contract address, deployment block, exact deployed runtime Keccak-256
hash, compiler artifact digest, and qualification report. The wallet verifies
chain ID, address, runtime code hash, transaction value/inclusion, finalized
block, current storage state, receipt status, and exact event before accepting
a lock.

Chain ID 1 is rejected unconditionally in this source; a caller-controlled
serialized policy flag is never release authority. Native-transfer and HTLC
construction require opaque value/settlement permits, and signing binds the
derived account role/address plus a previously enforced exact maximum fee. None
of those permits can currently be issued. Helios provenance has no public
release-flag acquisition path, and verified settlement also requires the
unavailable settlement permit. Mainnet can only be enabled by a
reviewed source change after deterministic bytecode, Helios proof coverage and
persistence, local-chain execution tests, rollback tests, and independent
contract review are complete.
