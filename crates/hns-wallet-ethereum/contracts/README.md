# Native ETH HTLC contract

This package compiles exactly one non-upgradeable native-ETH HTLC with
`solc` 0.8.35, optimizer runs 200, the Prague EVM target, and metadata removed
from the bytecode. The generated artifact is an input to deployment review; it
does not authorize a deployment or a contract address.

Run `npm ci && npm run build` after installing the pinned lockfile. `npm run
check` compares a fresh deterministic compilation with the checked-in artifact.
The ecosystem qualification gate fails closed when the compiler or artifact is
unavailable. No website-facing operation can deploy this contract.
