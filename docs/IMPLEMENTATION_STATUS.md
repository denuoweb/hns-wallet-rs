# Implementation status

Snapshot: 2026-08-02. Overall status: experimental, not production ready.
Mainnet name trading and HNS/BTC/HNS/ETH settlement are disabled.

| Deliverable | Implemented evidence | Missing before complete |
| --- | --- | --- |
| Standalone workspace | 11 crates, resolver 3, Rust 1.89, independent lockfile; no sibling paths | release CI and published artifacts |
| Wallet types | IDs, decimal integer amounts, roles, capabilities, UI-safe status | API stabilization review |
| Store | schema v1, Argon2id, XChaCha20-Poly1305 secret records, lock/unlock, CAS workflows, permissions/replays | platform key wrapping, entity CRUD/recovery supervisor, DB benchmarks/audit |
| HNS | create/restore seed, separated keys, addresses, deterministic non-name coin selection, typed node backend, strict name proof import, persisted name operations | actual send/transfer/finalize builders, backend client, full sync/history/reorg |
| Provider | every specified method/event, exact secure origin, generations, permission/approval/replay/rate bounds, forbidden methods | browser/native runtime dispatch and complete approval UI |
| Shakedex | persisted seller/buyer/recovery state machines and canonical proof decoding | transaction construction, node/Denuo integration, restart/reorg/regtest suite |
| Denuo market | chain-neutral reservations/sessions; canonical V2 protocol implemented in `hns-rs` | released protocol dependency, reporter governance, live relay/board integration |
| Bitcoin | BDK BIP84 create/load/receive/send, actual Kyoto client builder, HTLC funding/spend/evidence units | supervisor, signed HTLC spend, broadcast/reorg/regtest/benchmarks |
| Ethereum | separated accounts, typed EIP-1559 native/HTLC signing, Helios policy, exact code/state/receipt/event checks, deterministic contract | embedded Helios proof source, persistence/history, local chain, approved address, audit |
| FFI | versioned bounded typed frames; Chromium phrase denial | generated JNI/Swift/Chromium bindings and compatibility E2E |
| Testkit | deterministic non-mainnet, hostile-input, reorg, and qualification fixtures | full multi-process network harnesses |
| Browser products | authority and adapter work lives in separate repositories | see ecosystem report after browser gates |

The 2026-08-02 local gate passed: 34 Rust tests, locked all-target check,
warning-denied Clippy/docs, deterministic Solidity artifact comparison, and a
zero-vulnerability npm audit. Exact repository revisions are recorded in the
ecosystem implementation report after every scoped repository commit exists.

## Deferred by design

Reverse-Dutch offers, arbitrary Bitcoin applications, generic Ethereum dapps,
tokens/NFTs/DeFi/staking, `window.ethereum`, WalletConnect, user-added chains or
contracts, browser contract deployment, hosted Bitcoin backends, crawler/
bootstrap expansion, and enabling any future chain pair without full
qualification are out of scope.
