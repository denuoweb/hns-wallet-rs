# Future work and excluded features

Snapshot: 2026-08-02. This file is a release-status ledger, not a promise that
an unavailable feature can be exercised through a hidden or placeholder path.
Anything without the complete persistence, restart, negative-test,
integration, and qualification evidence remains disabled or unavailable.

| Feature | Status | Release boundary |
| --- | --- | --- |
| Handshake ordinary wallet and known-name support | experimental | Key, address, proof-import, coin-selection, and workflow foundations exist; complete sync and transaction builders are unavailable. |
| Fixed-price Shakedex | experimental, disabled | Persisted orchestration exists; live node/Denuo integration, full transaction construction, and regtest/restart/reorg evidence are unavailable. |
| HNS/BTC native settlement | experimental, disabled | Native HTLC primitives exist; signed end-to-end settlement, refunds, Kyoto supervisor integration, regtest, and resource qualification are unavailable. |
| HNS/ETH native settlement | experimental, disabled | Narrow signing, verification policy, and deterministic contract source exist; embedded Helios evidence, approved deployment, local-chain qualification, and audit are unavailable. |
| Price-round market board | experimental, disabled | Canonical protocol types exist in an unreleased `hns-rs` boundary; reporter governance and live relay/browser integration are unavailable. |
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

No row marked experimental is enabled for mainnet value. Moving a row to
implemented or tested requires corresponding code and evidence in
`docs/QUALIFICATION.md`; moving it to available additionally requires complete
product integration and a reviewed release policy.
