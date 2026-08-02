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

Events are private service frames scoped by an opaque host-issued authority
handle and exact service-owned revision. A navigation/policy/runtime change,
permission revocation, wallet-session rotation, authority replacement/revoke,
or service restart invalidates pending approvals and event channels.

The browser host retains the engine-issued authority. Only its private control
channel may register the logical origin, namespace, runtime session/generation,
policy/navigation generations, decision fingerprint, and expiry. Pages never
supply those values as authentication and never receive the opaque handle.
Wallet lock/session and permission generation are owned by the wallet service.

Permission records and encrypted tombstone generations survive service
restart. The service reads the current generation from `WalletStore`; it never
accepts one from a request. The first grant is generation one and every later
grant/revocation is exactly the stored generation plus one. Provider approvals,
handle-bound replay state, rate windows, request-ID windows, and event cursors
are deliberately process-ephemeral. Their maximum approval lifetime is 90
seconds, and old service sessions cannot resume them.

The 43 method names remain the closed vocabulary, but presence in that
vocabulary is not availability. Capability negotiation is a closed enum and an
unimplemented method returns `unsupportedCapability`. The checked-in subprocess
does not advertise provider dispatch, value movement, or browser integration.

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
