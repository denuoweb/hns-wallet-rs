# Future work and excluded features

Snapshot: 2026-08-02. This file is a release-status ledger, not a promise that
an unavailable feature can be exercised through a hidden or placeholder path.
Anything without the complete persistence, restart, negative-test,
integration, and qualification evidence remains disabled or unavailable.

| Feature | Status | Release boundary |
| --- | --- | --- |
| Handshake ordinary wallet and known-name support | implemented source, value path unavailable | The authenticated loopback node RPC adapter, bounded restart-safe coin/name-role scans, restoration, history/reorg reconciliation, transaction construction/signing, and atomic account/workflow/input-reservation preparation are implemented. Send remains hard-disabled until released canonical fee algebra, product integration, consolidated adapter/regtest qualification, independent review, and a reviewed source-gate change are complete. The separately persisted `HnsName` scan discovers keys but deliberately does not prove ownership; name import remains watch-only until released canonical NameState/resource decoding binds ownership to committed bytes. |
| Fixed-price Shakedex | implemented source, unavailable | Persisted orchestration exists; live node/Denuo integration, complete signed transaction construction, and regtest/restart/reorg evidence are unavailable. |
| HNS/BTC native settlement | implemented source, unavailable | HNS and Bitcoin HTLC/evidence primitives, the HNS node evidence adapter, and a bounded Kyoto supervisor/pre-broadcast journal exist. The pinned Kyoto header/filter/peer persistence gap, Bitcoin signed-spend supervision, published HNS 0.2 settlement profile, end-to-end regtest/restart/reorg evidence, record archival, and resource qualification remain unavailable. |
| HNS/ETH native settlement | contained source, unavailable | Separated offline account derivation, typed dormant transaction/evidence primitives, and deterministic contract source exist. Synchronization, history, send, signing, authoritative evidence, and settlement are hard-disabled behind immutable false gates; embedded Helios proof production/persistence, approved deployment, local-chain qualification, and audit are unavailable. |
| Price-round market board | implemented source, unavailable | Canonical protocol types exist in an unreleased `hns-rs` boundary; reporter governance and live relay/browser integration are unavailable. |
| Litecoin module | deferred | A future module must implement `ChainModule`, `UtxoChainModule`, and `AtomicSettlement` and pass the full pair qualification suite. |
| Additional UTXO chains | deferred | No assumption is made that Bitcoin script, sighash, address, fee, dust, or locktime policy is reusable. |
| Additional account-based chains | deferred | Each chain requires a single selected verification model and a narrowly scoped settlement adapter. |
| Additional trading pairs | deferred | A pair is not advertised merely because two wallet modules exist; its complete success/refund/restart/reorg sequence must qualify first. |
| Content aliases | deferred | No alias resolver, provider adapter, or browser path exists. |
| Free generated or donated names | deferred | Free-name grants, three-word acquisition, name inventories, vaults, and sponsorship are excluded. |
| Renewal automation | deferred | Current renewal height may be metadata; alerts, scheduling, construction, automation, toggles, and public-renew scripts are excluded. |
| Domain-service functionality | deferred | Hosted accounts, provider adapters, billing, fiat payments, service accounts, and pooled operations are excluded. |
| Advanced identity | deferred | Only typed Handshake identity-signing boundaries are planned; generalized identity, key export, and name-key signing are unavailable. |
| Handshake auctions and registration | deferred | Ordinary-user OPEN, BID, REVEAL, REGISTER, automatic auction, resource editing, and update flows are excluded. |
| Generic Ethereum applications | unavailable | `window.ethereum`, WalletConnect, arbitrary calldata/contracts, deployment, tokens, NFTs, DeFi, staking, lending, custom RPC, and chain switching are deliberately forbidden. |
| Generic Bitcoin signing/applications | unavailable | PSBT export/signing, raw-transaction signing, alternate production backends, and unrelated Bitcoin script applications are deliberately forbidden. |
| Custodial or wrapped settlement | unavailable | Wrapped assets, custodial exchange accounts, pooled liquidity, AMMs, centralized order books, and server-held wallet keys are prohibited. |

No unavailable row is enabled for value movement. Moving a source boundary to
qualified requires corresponding evidence in `docs/QUALIFICATION.md`; moving it
to available additionally requires complete product integration and a reviewed
release policy.
