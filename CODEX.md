# Repository constraints

- Rust edition 2024, MSRV 1.89, workspace resolver 3.
- This is a self-custodial wallet. Never log or return seeds, private keys,
  passphrases, metadata keys, capability secrets, or HTLC preimages.
- Persist workflow state before broadcasting an irreversible transaction.
- Money uses checked integer base units and canonical rational arithmetic;
  floating point is forbidden.
- Handshake consensus and wire types come from published `hns-rs` crates.
  Do not copy them or add a committed sibling-path dependency.
- Bitcoin production synchronization uses Kyoto BIP157/158 only.
- Ethereum is native-ETH-only. Offline receive derivation is the sole available
  capability; synchronization/history gates remain false, value/settlement
  permits remain unissued, caller-supplied Helios booleans never authorize, and
  chain ID 1 is unavailable. No generic contract or calldata API may be exposed.
- All website requests are hostile input and must be origin, generation, size,
  expiry, permission, rate, and replay checked.
- Mainnet settlement remains disabled until the qualification matrix passes and
  a reviewed source change independently enables its immutable release gate.
- Do not push from this repository.
