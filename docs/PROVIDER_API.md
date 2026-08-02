# Handshake Provider API

The website surface is `HandshakeProvider`, not `window.ethereum`:

```ts
interface HandshakeProvider {
  request(args: { method: string; params?: unknown }): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): void;
  removeListener(event: string, listener: (...args: unknown[]) => void): void;
}
```

Discovery uses `hns:requestProvider` and `hns:announceProvider`. A convenience
global may be announced, but consumers must not depend on one mutable global.

## Methods

General:

`wallet_getCapabilities`, `wallet_getEnabledModules`, `wallet_enableModule`,
`wallet_disableModule`, `wallet_requestPermissions`, `wallet_getPermissions`,
`wallet_revokePermissions`, `wallet_lock`, `wallet_getStatus`.

Handshake:

`hns_requestAccounts`, `hns_accounts`, `hns_getBalance`,
`hns_getTransactions`, `hns_getReceiveAddress`, `hns_send`, `hns_getNames`,
`hns_getName`, `hns_importKnownName`, `hns_transferName`, `hns_finalizeName`,
`hns_signTypedMessage`.

The method vocabulary is stable even when a capability is unavailable. In the
current release-gated runtime, imported names expose watch-only split proof/
current status. `hns_transferName` and `hns_finalizeName` must return unavailable
until canonical NameState parsing and the dedicated `HnsName` derivation scan
independently prove current ownership; unbound raw resource bytes are not
returned as proof-authenticated data.

External assets:

`asset_getAccount`, `asset_getBalance`, `asset_getTransactions`,
`asset_getReceiveTarget`, `asset_send`. Every call includes exactly one enabled
`bitcoin` or `ethereum` module. These methods never accept calldata or PSBTs.

Name market:

`nameMarket_listOffers`, `nameMarket_createFixedPriceOffer`,
`nameMarket_cancelOffer`, `nameMarket_acceptOffer`, `nameMarket_getSession`,
`nameMarket_finalizePurchase`, `nameMarket_recoverName`.

Cross-chain market:

`swap_getSupportedPairs`, `swap_getPriceRound`, `swap_listMarketIntents`,
`swap_publishMarketIntent`, `swap_cancelMarketIntent`, `swap_requestMatch`,
`swap_acceptFill`, `swap_getSession`, `swap_redeem`, `swap_refund`.

## Events

`connect`, `disconnect`, `permissionsChanged`, `modulesChanged`,
`accountsChanged`, `balancesChanged`, `transactionsChanged`, `namesChanged`,
`nameMarketChanged`, `priceRoundChanged`, `marketIntentChanged`,
`swapSessionChanged`, `walletLocked`.

Events are scoped to the same authenticated origin/context as requests. A
navigation, permission revocation, lock, authority generation change, or wallet
session change invalidates pending requests and event channels.

Browser-authority and wallet-session values are random identities, not ordered
counters. While both identities and the origin/namespace remain unchanged,
browser-authority, policy, permission, and navigation generations may only stay
equal or increase; a regression rejects the binding update. Any binding change
invalidates in-memory approvals, and a session change also resets session rate
state.

The first permission record for an origin may adopt the trusted current nonzero
generation. Every later grant must be exactly the authenticated stored
generation plus one. Revocation is also a compare-and-swap increment and leaves
an encrypted tombstone, preventing delete/regrant rollback. Approval and replay
lifetimes are capped and their expiry/identity metadata is authenticated before
pruning or use.

## Explicitly forbidden

The default website API rejects `eth_sendTransaction`, `eth_call`,
`eth_estimateGas`, `eth_sign`, `personal_sign`, `wallet_addEthereumChain`,
`wallet_switchEthereumChain`, `bitcoin_signPsbt`, `signRawTransaction`, seed or
private-key export, arbitrary filesystem/process/native-host operations, and
unknown methods. Marketplace actions are typed methods whose parameters are
reconstructed and verified by the wallet.

## Error posture

Unknown methods, forbidden methods, invalid params, oversized frames, insecure
origins, unauthorized capabilities, replays, request flooding, stale context,
stale approval, locked wallet, and unavailable module/backend are distinct
errors. Errors minimize account and policy disclosure.
